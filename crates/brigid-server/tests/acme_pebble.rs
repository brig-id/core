//! The certificate obtained with ACME, against Pebble, the test authority of
//! Let's Encrypt (core#75). CI starts Pebble and its DNS server
//! (`pebble-challtestsrv`, answering 127.0.0.1 for every name); without
//! them this test says so and passes.
//!
//! - `BRIGID_PEBBLE_DIRECTORY`: Pebble's directory, e.g. `https://localhost:14000/dir`
//! - `BRIGID_PEBBLE_CA`: the root of Pebble's own HTTPS (`test/certs/pebble.minica.pem`)
//! - `BRIGID_PEBBLE_TLS_PORT`: the port Pebble validates TLS-ALPN-01 on (5001)

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use brigid_crypto::MasterKey;
use brigid_server::acme::{self, Acme, AcmeSettings, Certificates};
use brigid_store::{AcmeSecret, EncryptedStore};

const DOMAIN: &str = "id.brigid.test";

#[tokio::test]
async fn a_certificate_is_obtained_served_and_renewed() {
    let (Ok(directory), Ok(ca)) = (
        std::env::var("BRIGID_PEBBLE_DIRECTORY"),
        std::env::var("BRIGID_PEBBLE_CA"),
    ) else {
        eprintln!("BRIGID_PEBBLE_DIRECTORY is not set: no ACME authority to test against");
        return;
    };
    let port: u16 = std::env::var("BRIGID_PEBBLE_TLS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5001);
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let master = MasterKey::from_hex(&"ab".repeat(32)).unwrap();
    let store = Arc::new(
        EncryptedStore::new("sqlite::memory:", master)
            .await
            .unwrap(),
    );
    let certificates = Arc::new(Certificates::default());

    // The listener the authority validates against, and later the one a
    // client reaches.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let handle = axum_server::Handle::new();
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(acme::server_config(
        certificates.clone(),
    )));
    let app = axum::Router::new().route("/", axum::routing::get(|| async { "brig·id" }));
    let server = tokio::spawn(
        axum_server::bind_rustls(addr, tls)
            .handle(handle.clone())
            .serve(app.into_make_service()),
    );
    handle.listening().await.expect("listener");

    let settings = AcmeSettings {
        domain: DOMAIN.to_owned(),
        directory: directory.clone(),
        contact: Some("operator@brigid.test".to_owned()),
        ca: Some(PathBuf::from(&ca)),
    };
    let manager = Acme::new(settings.clone(), store.clone(), certificates.clone());
    assert!(!certificates.ready());
    manager.obtain().await.expect("a certificate from Pebble");
    assert!(certificates.ready());

    // Served: a client that trusts Pebble's issuing root reaches the server
    // under its name.
    let roots = pebble_roots(&directory, &ca).await;
    let client = reqwest::Client::builder()
        .tls_certs_only(roots)
        .resolve(DOMAIN, addr)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let body = client
        .get(format!("https://{DOMAIN}:{port}/"))
        .send()
        .await
        .expect("an HTTPS request with the obtained certificate")
        .text()
        .await
        .unwrap();
    assert_eq!(body, "brig·id");

    // Kept in the database, encrypted: a restart loads it without an order.
    let stored = store.acme_secret(AcmeSecret::Certificate).await.unwrap();
    assert!(stored.is_some());
    let restarted = Acme::new(
        settings.clone(),
        store.clone(),
        Arc::new(Certificates::default()),
    );
    assert!(restarted.load_stored().await.is_some());

    // A renewal reuses the stored account and replaces the certificate.
    let account = store
        .acme_secret(AcmeSecret::Account)
        .await
        .unwrap()
        .unwrap();
    manager.obtain().await.expect("a renewal");
    assert_eq!(
        store
            .acme_secret(AcmeSecret::Account)
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        account.as_slice()
    );
    assert_ne!(
        store
            .acme_secret(AcmeSecret::Certificate)
            .await
            .unwrap()
            .unwrap()
            .as_slice(),
        stored.unwrap().as_slice()
    );

    handle.shutdown();
    let _ = server.await;
}

/// Pebble's issuing roots, from its management interface (port 15000 on the
/// directory's host).
async fn pebble_roots(directory: &str, ca: &str) -> Vec<reqwest::Certificate> {
    let pem = std::fs::read(ca).unwrap();
    let client = reqwest::Client::builder()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&pem).unwrap())
        .build()
        .unwrap();
    let mut url = reqwest::Url::parse(directory).unwrap();
    url.set_port(Some(15000)).unwrap();
    url.set_path("/roots/0");
    let root = client.get(url).send().await.unwrap().bytes().await.unwrap();
    reqwest::Certificate::from_pem_bundle(&root).unwrap()
}
