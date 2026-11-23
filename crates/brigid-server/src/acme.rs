//! The server's own certificate, obtained and renewed with ACME (RFC 8555).
//!
//! The domain is proved with TLS-ALPN-01 (RFC 8737) on the TLS listener
//! itself, so port 443 is the only one to open: during a challenge, a
//! handshake that offers only the `acme-tls/1` protocol receives a
//! self-signed certificate carrying the key authorization's digest; every
//! other handshake receives the current certificate.
//!
//! The account at the certificate authority and the certificate's private
//! key are kept encrypted in the database (`server_secrets`), like the
//! server's other secrets: a master key rotation re-encrypts them, and a
//! backup of the database carries them.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use brigid_store::{AcmeSecret, EncryptedStore};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// The protocol a TLS-ALPN-01 validation offers, alone (RFC 8737 §6.2).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// Let's Encrypt's production directory: the default authority.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// The certificates the TLS listener presents.
#[derive(Debug, Default)]
pub struct Certificates {
    current: RwLock<Option<Arc<CertifiedKey>>>,
    /// Challenge certificates by domain, while an order is being validated.
    challenges: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl Certificates {
    /// A listener that always presents `key` (certificate files).
    pub fn fixed(key: CertifiedKey) -> Self {
        Self {
            current: RwLock::new(Some(Arc::new(key))),
            challenges: RwLock::default(),
        }
    }

    fn install(&self, key: Arc<CertifiedKey>) {
        if let Ok(mut current) = self.current.write() {
            *current = Some(key);
        }
    }

    fn set_challenge(&self, domain: &str, key: Option<Arc<CertifiedKey>>) {
        if let Ok(mut challenges) = self.challenges.write() {
            match key {
                Some(key) => challenges.insert(domain.to_owned(), key),
                None => challenges.remove(domain),
            };
        }
    }

    /// Whether a certificate is installed.
    pub fn ready(&self) -> bool {
        self.current.read().is_ok_and(|c| c.is_some())
    }
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let challenge = hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN));
        if challenge {
            let name = hello.server_name()?;
            return self.challenges.read().ok()?.get(name).cloned();
        }
        self.current.read().ok()?.clone()
    }
}

/// The TLS configuration of the built-in listener: TLS 1.3 only (every
/// browser that can use a passkey speaks it), HTTP/2 and HTTP/1.1, and the
/// ACME protocol for validations.
pub fn server_config(certificates: Arc<Certificates>) -> ServerConfig {
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(certificates);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    config
}

/// A certificate chain and its key, read from PEM.
pub struct Loaded {
    pub key: CertifiedKey,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    /// The DNS names the leaf certificate is valid for.
    pub names: Vec<String>,
}

impl Loaded {
    /// When to renew: once two thirds of the lifetime have passed (30 days
    /// before the end of a 90-day certificate, 2 of a 6-day one).
    pub fn renew_at(&self) -> OffsetDateTime {
        self.not_after - (self.not_after - self.not_before) / 3
    }

    fn covers(&self, domain: &str) -> bool {
        self.names.iter().any(|n| n.eq_ignore_ascii_case(domain))
    }
}

/// Read a chain (leaf first) and its private key.
pub fn load(chain_pem: &[u8], key_pem: &[u8]) -> Result<Loaded, String> {
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("certificate chain: {e}"))?;
    let leaf = chain.first().ok_or("certificate chain: empty")?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| format!("certificate: {e}"))?;
    let time = |t: x509_parser::time::ASN1Time| {
        OffsetDateTime::from_unix_timestamp(t.timestamp()).map_err(|e| e.to_string())
    };
    let not_before = time(parsed.validity().not_before)?;
    let not_after = time(parsed.validity().not_after)?;
    let names = parsed
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => Some((*dns).to_owned()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("private key: {e}"))?;
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| format!("private key: {e}"))?;
    Ok(Loaded {
        key: CertifiedKey::new(chain, signer),
        not_before,
        not_after,
        names,
    })
}

/// What the operator configured.
#[derive(Debug, Clone)]
pub struct AcmeSettings {
    pub domain: String,
    /// The authority's directory URL.
    pub directory: String,
    /// An address the authority may write to about the certificate.
    pub contact: Option<String>,
    /// A PEM file of the authority's root, when it is not publicly trusted
    /// (a test authority such as Pebble, a private one).
    pub ca: Option<PathBuf>,
}

/// The stored account: its credentials and the directory they belong to.
#[derive(Serialize, Deserialize)]
struct StoredAccount {
    directory: String,
    credentials: AccountCredentials,
}

/// The stored certificate.
#[derive(Serialize, Deserialize)]
struct StoredCertificate {
    chain: String,
    key: String,
}

/// Obtains the certificate, installs it in [`Certificates`] and renews it.
pub struct Acme {
    settings: AcmeSettings,
    store: Arc<EncryptedStore>,
    certificates: Arc<Certificates>,
}

impl Acme {
    pub fn new(
        settings: AcmeSettings,
        store: Arc<EncryptedStore>,
        certificates: Arc<Certificates>,
    ) -> Self {
        Self {
            settings,
            store,
            certificates,
        }
    }

    /// Install the stored certificate if it is still valid for the domain.
    /// Returns when to renew it; `None` when a new one is needed now.
    pub async fn load_stored(&self) -> Option<OffsetDateTime> {
        let raw = match self.store.acme_secret(AcmeSecret::Certificate).await {
            Ok(raw) => raw?,
            Err(e) => {
                tracing::error!(error = %e, "cannot read the stored certificate");
                return None;
            }
        };
        let stored: StoredCertificate = serde_json::from_slice(&raw).ok()?;
        let loaded = match load(stored.chain.as_bytes(), stored.key.as_bytes()) {
            Ok(loaded) => loaded,
            Err(e) => {
                tracing::warn!(error = %e, "the stored certificate cannot be used");
                return None;
            }
        };
        if !loaded.covers(&self.settings.domain) || loaded.not_after <= OffsetDateTime::now_utc() {
            return None;
        }
        let renew_at = loaded.renew_at();
        self.certificates.install(Arc::new(loaded.key));
        tracing::info!(
            domain = %self.settings.domain,
            expires = %loaded.not_after,
            "certificate loaded from the database"
        );
        Some(renew_at)
    }

    /// Keep a valid certificate installed, for as long as the server runs.
    /// `listening` resolves once the TLS listener accepts connections: the
    /// authority's validation connects to it.
    pub async fn run(self, listening: impl std::future::Future<Output = ()>) {
        let mut renew_at = self.load_stored().await;
        listening.await;
        let mut failures: u32 = 0;
        loop {
            let now = OffsetDateTime::now_utc();
            match renew_at {
                Some(at) if at > now => {
                    // Wake at the renewal time, and at least twice a day to
                    // stay correct if the clock jumps.
                    let wait = (at - now).min(time::Duration::hours(12));
                    tokio::time::sleep(wait.unsigned_abs()).await;
                    if OffsetDateTime::now_utc() < at {
                        continue;
                    }
                }
                _ => {}
            }
            match self.obtain().await {
                Ok(at) => {
                    failures = 0;
                    renew_at = Some(at);
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    // 1 minute, doubling, at most 6 hours: an authority's
                    // rate limits count failed validations.
                    let wait = Duration::from_secs(60)
                        .saturating_mul(1 << failures.min(9).saturating_sub(1))
                        .min(Duration::from_secs(6 * 3600));
                    tracing::error!(
                        domain = %self.settings.domain,
                        error = %e,
                        retry_in_secs = wait.as_secs(),
                        "could not obtain a certificate"
                    );
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    /// One order: prove the domain, store and install the new certificate.
    /// Returns when to renew it.
    pub async fn obtain(&self) -> Result<OffsetDateTime, String> {
        let domain = &self.settings.domain;
        tracing::info!(%domain, directory = %self.settings.directory, "asking for a certificate");
        let account = self.account().await?;
        let identifiers = [Identifier::Dns(domain.clone())];
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| format!("new order: {e}"))?;

        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| format!("authorization: {e}"))?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => return Err(format!("authorization is {other:?}")),
            }
            let mut challenge = authz
                .challenge(ChallengeType::TlsAlpn01)
                .ok_or("the authority offers no tls-alpn-01 challenge")?;
            let name = challenge.identifier().to_string();
            let proof =
                challenge_certificate(&name, challenge.key_authorization().digest().as_ref())?;
            self.certificates
                .set_challenge(&name, Some(Arc::new(proof)));
            challenge
                .set_ready()
                .await
                .map_err(|e| format!("challenge: {e}"))?;
        }

        let retries = RetryPolicy::new()
            .initial_delay(Duration::from_secs(1))
            .timeout(Duration::from_secs(120));
        let status = order.poll_ready(&retries).await;
        self.certificates.set_challenge(domain, None);
        let status = status.map_err(|e| format!("validation: {e}"))?;
        if status != OrderStatus::Ready {
            return Err(format!(
                "the order is {status:?}, not ready: the authority could not reach this server on port 443 under {domain}"
            ));
        }
        let key_pem = order
            .finalize()
            .await
            .map_err(|e| format!("finalize: {e}"))?;
        let chain_pem = order
            .poll_certificate(&retries)
            .await
            .map_err(|e| format!("certificate: {e}"))?;

        let loaded = load(chain_pem.as_bytes(), key_pem.as_bytes())?;
        let stored = serde_json::to_vec(&StoredCertificate {
            chain: chain_pem,
            key: key_pem,
        })
        .map_err(|e| e.to_string())?;
        self.store
            .set_acme_secret(AcmeSecret::Certificate, &stored)
            .await
            .map_err(|e| format!("storing the certificate: {e}"))?;
        let renew_at = loaded.renew_at();
        tracing::info!(%domain, expires = %loaded.not_after, renew_at = %renew_at, "certificate obtained");
        self.certificates.install(Arc::new(loaded.key));
        Ok(renew_at)
    }

    /// The stored account for this directory, or a new one, stored.
    async fn account(&self) -> Result<Account, String> {
        let builder = || {
            match &self.settings.ca {
                Some(ca) => Account::builder_with_root(ca),
                None => Account::builder(),
            }
            .map_err(|e| format!("ACME client: {e}"))
        };

        if let Some(raw) = self
            .store
            .acme_secret(AcmeSecret::Account)
            .await
            .map_err(|e| format!("reading the account: {e}"))?
            && let Ok(stored) = serde_json::from_slice::<StoredAccount>(&raw)
            && stored.directory == self.settings.directory
        {
            return builder()?
                .from_credentials(stored.credentials)
                .await
                .map_err(|e| format!("account: {e}"));
        }

        let contact = self.settings.contact.as_ref().map(|c| {
            if c.contains(':') {
                c.clone()
            } else {
                format!("mailto:{c}")
            }
        });
        let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, credentials) = builder()?
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.settings.directory.clone(),
                None,
            )
            .await
            .map_err(|e| format!("new account: {e}"))?;
        let stored = serde_json::to_vec(&StoredAccount {
            directory: self.settings.directory.clone(),
            credentials,
        })
        .map_err(|e| e.to_string())?;
        self.store
            .set_acme_secret(AcmeSecret::Account, &stored)
            .await
            .map_err(|e| format!("storing the account: {e}"))?;
        tracing::info!(directory = %self.settings.directory, "account created at the certificate authority");
        Ok(account)
    }
}

/// The self-signed certificate a TLS-ALPN-01 validation expects: the domain
/// as its only name, and the `acmeIdentifier` extension holding the SHA-256
/// digest of the key authorization (RFC 8737 §3).
fn challenge_certificate(domain: &str, digest: &[u8]) -> Result<CertifiedKey, String> {
    let mut params = rcgen::CertificateParams::new(vec![domain.to_owned()])
        .map_err(|e| format!("challenge certificate: {e}"))?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
    let key = rcgen::KeyPair::generate().map_err(|e| format!("challenge key: {e}"))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("challenge certificate: {e}"))?;
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&der)
        .map_err(|e| format!("challenge key: {e}"))?;
    Ok(CertifiedKey::new(vec![cert.der().clone()], signer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed(domain: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![domain.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn a_chain_is_read_with_its_dates_and_names() {
        let (chain, key) = self_signed("id.example.org");
        let loaded = load(chain.as_bytes(), key.as_bytes()).unwrap();
        assert!(loaded.covers("id.example.org"));
        assert!(loaded.covers("ID.example.org"));
        assert!(!loaded.covers("other.example.org"));
        assert!(loaded.not_before < loaded.not_after);
        let third = (loaded.not_after - loaded.not_before) / 3;
        assert_eq!(loaded.renew_at(), loaded.not_after - third);
    }

    #[test]
    fn a_key_that_is_not_one_is_refused() {
        let (chain, _) = self_signed("id.example.org");
        assert!(load(chain.as_bytes(), b"not a key").is_err());
        assert!(load(b"", b"").is_err());
    }

    #[test]
    fn the_challenge_certificate_carries_the_digest() {
        let digest = [7u8; 32];
        let proof = challenge_certificate("id.example.org", &digest).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(proof.cert[0].as_ref()).unwrap();
        // id-pe-acmeIdentifier, 1.3.6.1.5.5.7.1.31, critical, an OCTET STRING
        // of the digest.
        let ext = parsed
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("acmeIdentifier extension");
        assert!(ext.critical);
        assert_eq!(&ext.value[2..], &digest);
    }
}
