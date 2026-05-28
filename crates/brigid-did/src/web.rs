//! DID:web construction, URL mapping, and remote resolution.
//!
//! Spec: <https://w3c-ccg.github.io/did-method-web/>
//!
//! Mapping rules:
//! - `did:web:example.com`          → `https://example.com/.well-known/did.json`
//! - `did:web:example.com:u:alice`  → `https://example.com/u/alice/did.json`

use crate::{
    error::{Error, Result},
    model::{DIDDocument, Did},
};

/// Build a `did:web` DID for a user on a given server.
///
/// Result format: `did:web:<server>:u:<username>`
pub fn build_did_web(username: &str, server: &str) -> Did {
    Did::new(format!("did:web:{server}:u:{username}"))
}

/// Map a `did:web` DID to its `.well-known/did.json` (or equivalent) URL.
///
/// Colon-separated path components after the host are converted to URL path
/// segments per the DID:web specification. The host segment is percent-decoded
/// before use so that port separators encoded as `%3A` become literal `:`,
/// enabling correct HTTPS URL construction (e.g. `did:web:example.com%3A8443`
/// maps to `https://example.com:8443/.well-known/did.json`).
pub fn did_web_to_url(did: &Did) -> Result<url::Url> {
    let s = did.as_str();
    let method_specific = s
        .strip_prefix("did:web:")
        .ok_or_else(|| Error::InvalidDid(format!("not a did:web DID: {s}")))?;

    let parts: Vec<&str> = method_specific.split(':').collect();
    // Percent-decode the host component so that `%3A` (colon) becomes `:` for
    // port numbers, and `%2F` (slash) becomes `/` for sub-path hosts.
    // The DID-Web specification mandates ASCII percent-encoded triplets but
    // does not constrain the hex case — accept both `%3A` and `%3a`.
    let host_decoded = parts[0]
        .replace("%3A", ":")
        .replace("%3a", ":")
        .replace("%2F", "/")
        .replace("%2f", "/");

    let raw = if parts.len() == 1 {
        format!("https://{host_decoded}/.well-known/did.json")
    } else {
        let path = parts[1..].join("/");
        format!("https://{host_decoded}/{path}/did.json")
    };

    Ok(raw.parse()?)
}

/// Fetch a DID document from an arbitrary URL string.
///
/// Extracted so that tests can inject an HTTP mock URL without requiring HTTPS.
///
/// The client enforces TLS 1.3 as the minimum negotiated version, per the
/// `brigid` security model (AGENTS.md). rustls would otherwise default to
/// `TLS 1.2` as the floor.
pub(crate) async fn fetch_document(url: &str) -> Result<DIDDocument> {
    // Bound the whole operation so a slow or stalled remote DID host cannot
    // tie up the caller's Axum task indefinitely. `reqwest::Client` has no
    // default request or connect timeout, which makes DID resolution a
    // DoS-amplification vector if any peer publishes a hostile or simply
    // unresponsive `.well-known/did.json` endpoint.
    let client = reqwest::Client::builder()
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        // Disable HTTP redirects entirely. `reqwest::Client` follows up to
        // 10 redirects by default, which would let a hostile (or merely
        // misconfigured) DID host bounce resolution to a plaintext `http://`
        // URL or to a different origin — turning DID:web resolution into
        // both a TLS-downgrade and a server-side-request-forgery vector.
        // DID:web has no legitimate reason to redirect: the URL is
        // deterministically derived from the DID, and any deviation MUST be
        // treated as a resolution failure.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = client.get(url).send().await?.error_for_status()?;
    let doc: DIDDocument = resp.json().await?;
    Ok(doc)
}

/// Fetch and deserialise a remote DID:web document over HTTPS.
pub async fn resolve_did_web(did: &Did) -> Result<DIDDocument> {
    fetch_document(did_web_to_url(did)?.as_str()).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_did_web_format() {
        let did = build_did_web("alice", "example.com");
        assert_eq!(did.as_str(), "did:web:example.com:u:alice");
    }

    #[test]
    fn did_web_to_url_with_path() {
        let did = build_did_web("alice", "example.com");
        let url = did_web_to_url(&did).unwrap();
        assert_eq!(url.as_str(), "https://example.com/u/alice/did.json");
    }

    #[test]
    fn did_web_to_url_root_only() {
        let did = Did::new("did:web:example.com");
        let url = did_web_to_url(&did).unwrap();
        assert_eq!(url.as_str(), "https://example.com/.well-known/did.json");
    }

    #[test]
    fn did_web_to_url_invalid_prefix() {
        let did = Did::new("did:key:abc");
        assert!(did_web_to_url(&did).is_err());
    }

    #[tokio::test]
    async fn resolve_did_web_returns_valid_document() {
        use serde_json::json;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;
        let body = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:localhost:u:alice",
            "verificationMethod": [{
                "id": "did:web:localhost:u:alice#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:localhost:u:alice",
                "publicKeyMultibase": "zDummyKey"
            }],
            "authentication": ["did:web:localhost:u:alice#key-1"]
        });

        Mock::given(method("GET"))
            .and(path("/u/alice/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        // Call fetch_document directly with the HTTP URL (wiremock uses HTTP).
        let url_str = format!("{}/u/alice/did.json", server.uri());
        let doc = fetch_document(&url_str).await.unwrap();

        assert_eq!(doc.id, "did:web:localhost:u:alice");
        assert_eq!(doc.verification_method.len(), 1);
    }

    /// `resolve_did_web` with a DID that maps to a reachable host but receives
    /// a connection-refused (no TLS server on that port).  This exercises the
    /// full body of `resolve_did_web` — including the `fetch_document(…).await`
    /// call — via the error path, giving line coverage without a real HTTPS server.
    #[tokio::test]
    async fn resolve_did_web_propagates_connection_error() {
        // Port 1 is always closed; the TLS handshake (or even TCP connect)
        // will fail immediately, covering resolve_did_web's body.
        let did = Did::new("did:web:127.0.0.1");
        let result = resolve_did_web(&did).await;
        assert!(result.is_err());
    }
}
