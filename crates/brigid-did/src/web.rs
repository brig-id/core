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

/// Returns `true` if `ip` must never be contacted by the did:web resolver —
/// loopback, RFC 1918 private ranges, link-local (which includes the
/// `169.254.169.254` cloud-provider metadata endpoint present on AWS/GCP/
/// Azure), IPv6 unique-local (`fc00::/7`), unspecified, multicast, and
/// broadcast. IPv4-mapped and IPv4-compatible IPv6 encodings are unwrapped
/// to their embedded IPv4 address first so they can't bypass the IPv4 checks
/// (e.g. `::ffff:169.254.169.254`).
///
/// did:web has no legitimate reason to ever resolve to any of these: every
/// DID's host is a public relying-party or federation-peer domain. Checked
/// against manually rather than via `std::net`'s `is_private`/etc. helpers
/// so the exact set of blocked ranges is explicit and auditable in one
/// place, and so it doesn't depend on which helpers happen to be stable on
/// this crate's MSRV.
fn is_disallowed_target(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // 169.254.0.0/16, incl. cloud metadata
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            // Check native IPv6 loopback/unspecified *before* attempting the
            // IPv4-compatible unwrap below: `Ipv6Addr::to_ipv4()`'s
            // deprecated `::a.b.c.d` mapping doesn't exclude `::1` or `::`
            // per RFC 4291, so `::1` would otherwise unwrap to `0.0.0.1` —
            // an address none of the IPv4 checks catch — silently bypassing
            // this function for IPv6 loopback.
            let is_unique_local = (v6.segments()[0] & 0xfe00) == 0xfc00; // fc00::/7
            let is_unicast_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80; // fe80::/10
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local
                || is_unicast_link_local
            {
                return true;
            }
            if let Some(mapped) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return is_disallowed_target(IpAddr::V4(mapped));
            }
            false
        }
    }
}

/// Fetch a DID document from an arbitrary URL string.
///
/// Extracted so that tests can inject an HTTP mock URL without requiring HTTPS.
///
/// The client enforces TLS 1.3 as the minimum negotiated version, per the
/// `brigid` security model (AGENTS.md). rustls would otherwise default to
/// `TLS 1.2` as the floor.
pub(crate) async fn fetch_document(url: &str) -> Result<DIDDocument> {
    fetch_document_inner(url, false).await
}

/// Test-only escape hatch for `fetch_document`'s SSRF guard.
///
/// `#[cfg(test)]` means this — and the `allow_private = true` path it
/// enables in `fetch_document_inner` — never exists in a release build; it
/// exists solely so `resolve_did_web_returns_valid_document` below can point
/// at a `wiremock::MockServer`, which always binds to loopback. Every real
/// caller goes through `fetch_document`, which always enforces the guard.
#[cfg(test)]
async fn fetch_document_allow_private(url: &str) -> Result<DIDDocument> {
    fetch_document_inner(url, true).await
}

async fn fetch_document_inner(url: &str, allow_private: bool) -> Result<DIDDocument> {
    let parsed: url::Url = url.parse()?;
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::Resolution(format!("URL has no host: {url}")))?
        .to_string();
    // `resolve_to_addrs` below always defers to the URL's own port, so this
    // is only used to build valid `SocketAddr`s for the DNS lookup itself.
    let port = parsed.port_or_known_default().unwrap_or(443);

    // Resolve DNS once, validate every returned address against
    // `is_disallowed_target`, then pin the connection to exactly those
    // validated addresses via `resolve_to_addrs`. Without pinning,
    // `reqwest`/hyper would re-resolve the hostname again at connect time —
    // a DNS-rebinding attacker can return a public IP for this check and a
    // private/internal one moments later for the real TCP connection,
    // making a check-then-connect without pinning bypassable.
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| Error::Resolution(format!("DNS lookup failed for {host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(Error::Resolution(format!(
            "DNS lookup for {host} returned no addresses"
        )));
    }
    if !allow_private {
        if let Some(bad) = addrs.iter().find(|a| is_disallowed_target(a.ip())) {
            return Err(Error::Resolution(format!(
                "refusing to resolve did:web host {host} to a private/internal address ({})",
                bad.ip()
            )));
        }
    }

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
        .resolve_to_addrs(&host, &addrs)
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

        // Call the test-only helper, which skips the SSRF guard so it can
        // point at wiremock's loopback-bound mock server (real callers
        // always go through `fetch_document`, which never skips it).
        let url_str = format!("{}/u/alice/did.json", server.uri());
        let doc = fetch_document_allow_private(&url_str).await.unwrap();

        assert_eq!(doc.id, "did:web:localhost:u:alice");
        assert_eq!(doc.verification_method.len(), 1);
    }

    /// `resolve_did_web` with a DID that maps to loopback is now rejected by
    /// the SSRF guard before any connection is attempted — this exercises
    /// the full body of `resolve_did_web`, including the guard, via the
    /// error path, giving line coverage without a real HTTPS server.
    #[tokio::test]
    async fn resolve_did_web_propagates_connection_error() {
        let did = Did::new("did:web:127.0.0.1");
        let result = resolve_did_web(&did).await;
        assert!(result.is_err());
    }

    #[test]
    fn is_disallowed_target_blocks_loopback() {
        assert!(is_disallowed_target("127.0.0.1".parse().unwrap()));
        assert!(is_disallowed_target("::1".parse().unwrap()));
    }

    #[test]
    fn is_disallowed_target_blocks_private_ranges() {
        assert!(is_disallowed_target("10.0.0.1".parse().unwrap()));
        assert!(is_disallowed_target("172.16.0.1".parse().unwrap()));
        assert!(is_disallowed_target("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn is_disallowed_target_blocks_link_local_and_cloud_metadata() {
        // 169.254.169.254 is the AWS/GCP/Azure instance-metadata endpoint —
        // the single most common real-world did:web SSRF payload.
        assert!(is_disallowed_target("169.254.169.254".parse().unwrap()));
        assert!(is_disallowed_target("169.254.0.1".parse().unwrap()));
        assert!(is_disallowed_target("fe80::1".parse().unwrap()));
    }

    #[test]
    fn is_disallowed_target_blocks_ipv6_unique_local() {
        assert!(is_disallowed_target("fc00::1".parse().unwrap()));
        assert!(is_disallowed_target("fd12:3456:789a::1".parse().unwrap()));
    }

    #[test]
    fn is_disallowed_target_blocks_unspecified_and_multicast() {
        assert!(is_disallowed_target("0.0.0.0".parse().unwrap()));
        assert!(is_disallowed_target("::".parse().unwrap()));
        assert!(is_disallowed_target("224.0.0.1".parse().unwrap()));
        assert!(is_disallowed_target("ff02::1".parse().unwrap()));
    }

    #[test]
    fn is_disallowed_target_blocks_ipv4_mapped_and_compatible_ipv6() {
        // These IPv6 forms embed an IPv4 address — a naive IPv6-only check
        // would let them straight through the IPv4 blocklist above.
        assert!(is_disallowed_target(
            "::ffff:169.254.169.254".parse().unwrap()
        ));
        assert!(is_disallowed_target("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_disallowed_target("::127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_disallowed_target_allows_public_addresses() {
        assert!(!is_disallowed_target("93.184.216.34".parse().unwrap()));
        assert!(!is_disallowed_target("1.1.1.1".parse().unwrap()));
        assert!(!is_disallowed_target(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn fetch_document_rejects_private_target_without_bypass() {
        // Same mock server as resolve_did_web_returns_valid_document, but
        // called through the real fetch_document — the SSRF guard must
        // reject it even though the mock would otherwise answer correctly.
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let url_str = format!("{}/u/alice/did.json", server.uri());
        let result = fetch_document(&url_str).await;
        assert!(result.is_err());
    }
}
