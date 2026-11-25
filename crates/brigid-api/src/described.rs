//! Clients that describe themselves (protocol.md §6, OAuth Client ID Metadata
//! Document): the `client_id` is an HTTPS URL, and the JSON document at that
//! URL says what the client is. No registration on the server.
//!
//! Reading the document is a request this server makes to an address anyone
//! chooses, so it is narrow: `https` only, a domain name (never an address
//! literal), no address of a special-use range on the address actually
//! connected to (the resolver hands the connector public addresses only), no
//! redirect, no proxy, at most [`MAX_DOCUMENT_BYTES`] and ten seconds. A valid
//! document is cached for what its `Cache-Control` says, bounded to five
//! minutes to a day; an error is never cached. The same rules hold for a
//! client's `jwks_uri`.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use brigid_identity::{Attribute, Need};
use brigid_store::{ApplicationType, Client, ClientAuth, ClientDocument};
use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;
use url::{Host, Url};

/// Longest document read, client metadata or JWKS (protocol.md §6).
pub const MAX_DOCUMENT_BYTES: usize = 5 * 1024;
/// Whole time allowed for one read.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounds of the time a valid document is kept without reading it again.
const MIN_FRESH: Duration = Duration::from_secs(300);
const MAX_FRESH: Duration = Duration::from_secs(24 * 3600);
/// Most documents (and key sets) held in memory at once.
const CACHE_CAPACITY: usize = 1_000;

// ---------------------------------------------------------------------------
// The client_id
// ---------------------------------------------------------------------------

/// The `client_id` of a client that describes itself, if `value` is one:
/// `https`, a domain name, a path other than `/`, no query, no fragment, no
/// user info, no `.` or `..` segment, and written exactly as the URL
/// serialises (so that one client has one identifier, compared as a string).
pub fn client_id_url(value: &str) -> Option<Url> {
    if !value.starts_with("https://") {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.as_str() != value
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.host(), Some(Host::Domain(_)))
        || url.path() == "/"
    {
        return None;
    }
    // `Url` removes dot segments; the string compare above already refused
    // a value that had some, this states it.
    if url.path_segments()?.any(|s| s == "." || s == "..") {
        return None;
    }
    Some(url)
}

/// A URL this server may fetch for a client (its `jwks_uri`): `https`, a
/// domain name, no user info, no fragment.
fn fetchable_url(value: &str) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && matches!(url.host(), Some(Host::Domain(_))))
    .then_some(url)
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// Why a document was not accepted. The message is logged and never sent to
/// the client's users as is.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct DocumentError(pub String);

fn invalid(message: impl Into<String>) -> DocumentError {
    DocumentError(message.into())
}

#[derive(Deserialize)]
struct RawDocument {
    client_id: String,
    client_name: Option<String>,
    client_uri: Option<String>,
    logo_uri: Option<String>,
    application_type: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
    jwks_uri: Option<String>,
    jwks: Option<serde_json::Value>,
    client_secret: Option<serde_json::Value>,
    brigid_attributes: Option<BTreeMap<String, String>>,
}

/// Read and check the document published at `client_id`, read at `now`
/// (Unix seconds). Returns the client as the server keeps it.
pub fn parse_document(client_id: &Url, body: &[u8], now: i64) -> Result<Client, DocumentError> {
    let raw: RawDocument =
        serde_json::from_slice(body).map_err(|e| invalid(format!("not a client document: {e}")))?;
    if raw.client_id != client_id.as_str() {
        return Err(invalid("its client_id is not the URL it was read from"));
    }
    if raw.client_secret.is_some() {
        return Err(invalid("a published document cannot hold a client_secret"));
    }
    let application_type = match raw.application_type.as_deref() {
        None | Some("web") => ApplicationType::Web,
        Some("native") => ApplicationType::Native,
        Some(other) => return Err(invalid(format!("unknown application_type {other:?}"))),
    };
    if let Some(grants) = &raw.grant_types
        && !grants.iter().any(|g| g == "authorization_code")
    {
        return Err(invalid("grant_types must include authorization_code"));
    }
    if let Some(types) = &raw.response_types
        && !types.iter().any(|t| t == "code")
    {
        return Err(invalid("response_types must include code"));
    }

    let auth = match (raw.token_endpoint_auth_method.as_deref(), application_type) {
        (Some("none"), _) => ClientAuth::None,
        (Some("private_key_jwt"), ApplicationType::Web) => ClientAuth::PrivateKeyJwt,
        (Some("private_key_jwt"), ApplicationType::Native) => {
            return Err(invalid(
                "a native application is a public client: token_endpoint_auth_method none",
            ));
        }
        (Some(other), _) => {
            return Err(invalid(format!(
                "token_endpoint_auth_method {other:?}: only none and private_key_jwt are offered"
            )));
        }
        (None, _) => {
            return Err(invalid(
                "token_endpoint_auth_method is required: none or private_key_jwt",
            ));
        }
    };
    let (jwks, jwks_uri) = match auth {
        ClientAuth::None => (None, None),
        ClientAuth::PrivateKeyJwt => match (raw.jwks, raw.jwks_uri) {
            (Some(jwks), None) => {
                let set: JwkSet = serde_json::from_value(jwks.clone())
                    .map_err(|e| invalid(format!("jwks is not a key set: {e}")))?;
                if !set.keys.iter().any(|k| usable_key(k, None)) {
                    return Err(invalid("jwks has no Ed25519 or P-256 signing key"));
                }
                (Some(jwks), None)
            }
            (None, Some(uri)) => {
                let url = fetchable_url(&uri)
                    .ok_or_else(|| invalid("jwks_uri must be an https URL on a domain name"))?;
                (None, Some(url.to_string()))
            }
            _ => {
                return Err(invalid(
                    "private_key_jwt needs its keys in jwks_uri or in jwks, not both",
                ));
            }
        },
    };

    if raw.redirect_uris.is_empty() {
        return Err(invalid("at least one redirect URI is required"));
    }
    for uri in &raw.redirect_uris {
        check_redirect_uri(client_id, application_type, uri)?;
    }

    let host = client_id.host_str().unwrap_or_default();
    let name = raw.client_name.as_deref().map(str::trim).unwrap_or(host);
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err(invalid(
            "client_name must have 1 to 100 characters, none of them a control character",
        ));
    }

    let mut attributes = BTreeMap::new();
    for (claim, need) in raw.brigid_attributes.unwrap_or_default() {
        let attribute = Attribute::parse(&claim)
            .ok_or_else(|| invalid(format!("brigid_attributes: unknown attribute {claim:?}")))?;
        let need = match need.as_str() {
            "required" => Need::Required,
            "optional" => Need::Optional,
            other => {
                return Err(invalid(format!(
                    "brigid_attributes: {claim} is {other:?}, not required or optional"
                )));
            }
        };
        attributes.insert(attribute, need);
    }

    let https = |uri: Option<String>| {
        uri.and_then(|u| Url::parse(&u).ok())
            .filter(|u| u.scheme() == "https")
            .map(String::from)
    };
    Ok(Client {
        client_id: client_id.to_string(),
        name: name.to_owned(),
        redirect_uris: raw.redirect_uris,
        confidential: auth == ClientAuth::PrivateKeyJwt,
        attributes,
        created_at: now,
        document: Some(ClientDocument {
            application_type,
            auth,
            jwks,
            jwks_uri,
            client_uri: https(raw.client_uri),
            logo_uri: https(raw.logo_uri),
            fetched_at: now,
        }),
    })
}

/// A redirect URI a document may list. A web client's are `https` on the
/// origin of its `client_id`. A native application's (RFC 8252) are the
/// loopback address over `http` (`127.0.0.1` or `[::1]`, any port), its
/// private-use scheme (the `client_id`'s host reversed, then `:/`), or
/// `https` on the origin of its `client_id`.
fn check_redirect_uri(
    client_id: &Url,
    application_type: ApplicationType,
    uri: &str,
) -> Result<(), DocumentError> {
    let bad = |why: &str| invalid(format!("redirect URI {uri:?}: {why}"));
    let url = Url::parse(uri).map_err(|_| bad("not an absolute URL"))?;
    if url.fragment().is_some() {
        return Err(bad("it has a fragment"));
    }
    if url.scheme() == "https" {
        return if url.origin() == client_id.origin() {
            Ok(())
        } else {
            Err(bad("not on the origin of the client_id"))
        };
    }
    if application_type == ApplicationType::Web {
        return Err(bad("a web client's redirect URIs are https"));
    }
    if url.scheme() == "http" {
        return if is_loopback(&url) {
            Ok(())
        } else {
            Err(bad(
                "http is for the loopback address only (127.0.0.1 or [::1], not localhost)",
            ))
        };
    }
    if url.scheme() == private_use_scheme(client_id)
        && uri.starts_with(&format!("{}:/", url.scheme()))
        && !uri.starts_with(&format!("{}://", url.scheme()))
    {
        return Ok(());
    }
    Err(bad(&format!(
        "a native application's private-use scheme is {}:/",
        private_use_scheme(client_id)
    )))
}

fn is_loopback(url: &Url) -> bool {
    matches!(
        url.host(),
        Some(Host::Ipv4(ip)) if ip == Ipv4Addr::LOCALHOST
    ) || matches!(url.host(), Some(Host::Ipv6(ip)) if ip == Ipv6Addr::LOCALHOST)
}

/// `https://shop.example/…` → `example.shop`.
fn private_use_scheme(client_id: &Url) -> String {
    client_id
        .host_str()
        .unwrap_or_default()
        .split('.')
        .rev()
        .collect::<Vec<_>>()
        .join(".")
}

/// Whether `client` may send people back to `uri`: listed in its document
/// (or registration), compared exactly; for the loopback redirect URIs of a
/// native application, the port is not compared (RFC 8252 §7.3).
pub fn accepts_redirect(client: &Client, uri: &str) -> bool {
    if client.redirect_uris.iter().any(|listed| listed == uri) {
        return true;
    }
    let native = client
        .document
        .as_ref()
        .is_some_and(|d| d.application_type == ApplicationType::Native);
    if !native {
        return false;
    }
    let Ok(mut asked) = Url::parse(uri) else {
        return false;
    };
    if asked.scheme() != "http" || !is_loopback(&asked) || asked.set_port(None).is_err() {
        return false;
    }
    client.redirect_uris.iter().any(|listed| {
        Url::parse(listed).is_ok_and(|mut listed| {
            listed.scheme() == "http" && listed.set_port(None).is_ok() && listed == asked
        })
    })
}

/// Whether `jwk` can verify a client's signature, for `alg` (any of the two
/// accepted when `None`): Ed25519 for EdDSA, P-256 for ES256, meant for
/// signatures if it says what it is for.
pub fn usable_key(jwk: &jsonwebtoken::jwk::Jwk, alg: Option<jsonwebtoken::Algorithm>) -> bool {
    use jsonwebtoken::{
        Algorithm,
        jwk::{AlgorithmParameters, EllipticCurve, PublicKeyUse},
    };
    let for_signing = matches!(
        jwk.common.public_key_use,
        None | Some(PublicKeyUse::Signature)
    );
    let fits = match &jwk.algorithm {
        AlgorithmParameters::OctetKeyPair(p) => {
            p.curve == EllipticCurve::Ed25519 && alg.is_none_or(|a| a == Algorithm::EdDSA)
        }
        AlgorithmParameters::EllipticCurve(p) => {
            p.curve == EllipticCurve::P256 && alg.is_none_or(|a| a == Algorithm::ES256)
        }
        _ => false,
    };
    for_signing && fits
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/// A document as read: its body and how long it may be kept.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub body: Vec<u8>,
    /// `Cache-Control: max-age` (or `no-store`/`no-cache`: zero).
    pub max_age: Option<Duration>,
}

pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<Fetched, String>> + Send + 'a>>;

/// What reads a client's documents. The server uses [`HttpFetcher`]; tests
/// give documents of their own.
pub trait Fetch: Send + Sync {
    fn fetch<'a>(&'a self, url: &'a Url) -> FetchFuture<'a>;
}

/// Reads documents over HTTPS with the rules of this module.
pub struct HttpFetcher {
    client: reqwest::Client,
}

impl HttpFetcher {
    /// # Errors
    /// When the TLS backend cannot be set up.
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(FETCH_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .dns_resolver(Arc::new(PublicOnly))
            .user_agent(concat!("brig-id/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { client })
    }
}

impl Fetch for HttpFetcher {
    fn fetch<'a>(&'a self, url: &'a Url) -> FetchFuture<'a> {
        Box::pin(async move {
            // An address literal never goes through the resolver: refused
            // here, whatever the caller checked.
            if !matches!(url.host(), Some(Host::Domain(_))) || url.scheme() != "https" {
                return Err("only https URLs on a domain name are read".into());
            }
            let mut response = self
                .client
                .get(url.clone())
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|e| format!("cannot read {url}: {e}"))?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(format!("{url} answered {}", response.status()));
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_DOCUMENT_BYTES as u64)
            {
                return Err(format!("{url} is larger than {MAX_DOCUMENT_BYTES} bytes"));
            }
            let max_age = response
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                .and_then(cache_max_age);
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| format!("cannot read {url}: {e}"))?
            {
                body.extend_from_slice(&chunk);
                if body.len() > MAX_DOCUMENT_BYTES {
                    return Err(format!("{url} is larger than {MAX_DOCUMENT_BYTES} bytes"));
                }
            }
            Ok(Fetched { body, max_age })
        })
    }
}

/// The freshness a `Cache-Control` header gives, if it gives one.
fn cache_max_age(value: &str) -> Option<Duration> {
    let mut max_age = None;
    for directive in value.split(',').map(str::trim) {
        let lower = directive.to_ascii_lowercase();
        if lower == "no-store" || lower == "no-cache" {
            return Some(Duration::ZERO);
        }
        if let Some(seconds) = lower.strip_prefix("max-age=") {
            max_age = seconds
                .trim_matches('"')
                .parse()
                .ok()
                .map(Duration::from_secs);
        }
    }
    max_age
}

/// Resolves a name to its public addresses only: the connector never sees
/// an address of a special-use range, so what is checked is what is
/// connected to (DNS rebinding included).
struct PublicOnly;

impl reqwest::dns::Resolve for PublicOnly {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|a| is_public(a.ip()))
                .collect();
            if addresses.is_empty() {
                return Err(format!("{host} has no public address").into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Whether `ip` is a public unicast address: none of the special-use ranges
/// of RFC 6890 and its successors (loopback, private, shared, link-local and
/// the cloud metadata address, documentation, benchmarking, multicast,
/// reserved), IPv4 inside IPv6 judged as IPv4.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let s = v6.segments();
            let special = v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] & 0xffc0) == 0xfec0 // site-local fec0::/10
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x2001 && s[1] < 0x0200) // IETF protocol assignments, Teredo
                || s[0] == 0x2002 // 6to4
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // discard
                || s[0] == 0; // ::/16, IPv4-compatible and the like
            !special
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..128).contains(&b)) // shared, 100.64/10
        || (a == 169 && b == 254) // link-local, cloud metadata
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // documentation
        || (a == 192 && b == 88 && c == 99) // 6to4 relay
        || (a == 192 && b == 168)
        || (a == 198 && (18..20).contains(&b)) // benchmarking
        || (a == 198 && b == 51 && c == 100) // documentation
        || (a == 203 && b == 0 && c == 113) // documentation
        || a >= 224) // multicast, reserved, broadcast
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

struct Cached<T> {
    value: T,
    stored: Instant,
    fresh_for: Duration,
}

/// Valid documents and key sets read lately. A cache: each node of a server
/// has its own, and the last valid document of a client is in the store.
pub struct Described {
    pub fetcher: Arc<dyn Fetch>,
    documents: Mutex<HashMap<String, Cached<Client>>>,
    key_sets: Mutex<HashMap<String, Cached<JwkSet>>>,
}

impl Described {
    pub fn new(fetcher: Arc<dyn Fetch>) -> Self {
        Self {
            fetcher,
            documents: Mutex::new(HashMap::new()),
            key_sets: Mutex::new(HashMap::new()),
        }
    }

    /// The client at `client_id`: from the cache while fresh, read again
    /// otherwise. `Err` when it cannot be read or is not valid: nothing of
    /// that is cached.
    pub async fn client(&self, client_id: &Url, now: i64) -> Result<Client, String> {
        if let Some(client) = fresh(&self.documents, client_id.as_str(), Duration::ZERO) {
            return Ok(client);
        }
        let fetched = self.fetcher.fetch(client_id).await?;
        let client = parse_document(client_id, &fetched.body, now).map_err(|e| e.0)?;
        keep(
            &self.documents,
            client_id.as_str(),
            client.clone(),
            fetched.max_age,
        );
        Ok(client)
    }

    /// The keys of a client that publishes them at `jwks_uri`. `reload`
    /// reads them again unless the cached set is less than a minute old: a
    /// signature by a key the set does not have may come from a key the
    /// client just added.
    pub async fn key_set(&self, jwks_uri: &str, reload: bool) -> Result<JwkSet, String> {
        let min_age = if reload {
            Duration::from_secs(60)
        } else {
            Duration::ZERO
        };
        if let Some(set) = fresh(&self.key_sets, jwks_uri, min_age) {
            return Ok(set);
        }
        let url = fetchable_url(jwks_uri).ok_or("jwks_uri is not an https URL on a domain name")?;
        let fetched = self.fetcher.fetch(&url).await?;
        let set: JwkSet = serde_json::from_slice(&fetched.body)
            .map_err(|e| format!("{jwks_uri} is not a key set: {e}"))?;
        keep(&self.key_sets, jwks_uri, set.clone(), fetched.max_age);
        Ok(set)
    }
}

/// The cached value of `key` while fresh. With `min_age`, only a value at
/// least that old counts as stale: a younger one is returned even after an
/// explicit reload.
fn fresh<T: Clone>(
    cache: &Mutex<HashMap<String, Cached<T>>>,
    key: &str,
    min_age: Duration,
) -> Option<T> {
    let cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    let entry = cache.get(key)?;
    let age = entry.stored.elapsed();
    let fresh = if min_age.is_zero() {
        age < entry.fresh_for
    } else {
        age < min_age
    };
    fresh.then(|| entry.value.clone())
}

fn keep<T>(
    cache: &Mutex<HashMap<String, Cached<T>>>,
    key: &str,
    value: T,
    max_age: Option<Duration>,
) {
    let fresh_for = max_age.unwrap_or(MIN_FRESH).clamp(MIN_FRESH, MAX_FRESH);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= CACHE_CAPACITY && !cache.contains_key(key) {
        cache.retain(|_, e| e.stored.elapsed() < e.fresh_for);
        if cache.len() >= CACHE_CAPACITY
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, e)| e.stored)
                .map(|(k, _)| k.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        key.to_owned(),
        Cached {
            value,
            stored: Instant::now(),
            fresh_for,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Url {
        client_id_url("https://shop.example/oauth-client-metadata.json").unwrap()
    }

    fn doc(extra: serde_json::Value) -> Vec<u8> {
        let mut base = serde_json::json!({
            "client_id": "https://shop.example/oauth-client-metadata.json",
            "client_name": "Example Shop",
            "redirect_uris": ["https://shop.example/callback"],
            "token_endpoint_auth_method": "none",
        });
        for (k, v) in extra.as_object().unwrap() {
            base[k] = v.clone();
        }
        serde_json::to_vec(&base).unwrap()
    }

    #[test]
    fn a_client_id_is_an_https_url_with_a_path() {
        for good in [
            "https://shop.example/oauth-client-metadata.json",
            "https://shop.example/a/b.json",
            "https://shop.example:8443/client",
        ] {
            assert!(client_id_url(good).is_some(), "{good}");
        }
        for bad in [
            "http://shop.example/client.json",
            "https://shop.example/",
            "https://shop.example",
            "https://shop.example/client.json?x=1",
            "https://shop.example/client.json#x",
            "https://user@shop.example/client.json",
            "https://shop.example/a/../client.json",
            "https://shop.example/./client.json",
            "https://SHOP.example/client.json",
            "https://shop.example:443/client.json",
            "https://127.0.0.1/client.json",
            "https://[::1]/client.json",
            "3f1c2a7e-5b8d-4c1f-9e2a-0d6b7c8e9f10",
        ] {
            assert!(client_id_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_valid_document_gives_a_client() {
        let body = doc(serde_json::json!({
            "brigid_attributes": { "email": "required", "given_name": "optional" },
            "logo_uri": "https://shop.example/logo.png",
            "client_uri": "http://shop.example",
        }));
        let client = parse_document(&id(), &body, 7).unwrap();
        assert_eq!(client.client_id, id().as_str());
        assert_eq!(client.name, "Example Shop");
        assert!(!client.confidential);
        assert_eq!(client.attributes[&Attribute::Email], Need::Required);
        assert_eq!(client.attributes[&Attribute::GivenName], Need::Optional);
        let document = client.document.unwrap();
        assert_eq!(document.auth, ClientAuth::None);
        assert_eq!(
            document.logo_uri.as_deref(),
            Some("https://shop.example/logo.png")
        );
        assert_eq!(document.client_uri, None, "an http home page is dropped");
        assert_eq!(document.fetched_at, 7);
    }

    #[test]
    fn a_document_is_refused_for_what_the_spec_forbids() {
        let cases = [
            serde_json::json!({ "client_id": "https://other.example/c.json" }),
            serde_json::json!({ "client_secret": "s" }),
            serde_json::json!({ "token_endpoint_auth_method": "client_secret_basic" }),
            serde_json::json!({ "token_endpoint_auth_method": null }),
            serde_json::json!({ "redirect_uris": [] }),
            serde_json::json!({ "redirect_uris": ["https://evil.example/callback"] }),
            serde_json::json!({ "redirect_uris": ["http://shop.example/callback"] }),
            serde_json::json!({ "redirect_uris": ["http://127.0.0.1/callback"] }),
            serde_json::json!({ "redirect_uris": ["https://shop.example/cb#x"] }),
            serde_json::json!({ "grant_types": ["implicit"] }),
            serde_json::json!({ "response_types": ["token"] }),
            serde_json::json!({ "application_type": "tv" }),
            serde_json::json!({ "brigid_attributes": { "shoe_size": "optional" } }),
            serde_json::json!({ "brigid_attributes": { "email": "maybe" } }),
            serde_json::json!({ "client_name": " " }),
            serde_json::json!({ "token_endpoint_auth_method": "private_key_jwt" }),
            serde_json::json!({
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": "https://shop.example/jwks.json",
                "jwks": { "keys": [] },
            }),
            serde_json::json!({
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": "http://shop.example/jwks.json",
            }),
            serde_json::json!({
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": { "keys": [{ "kty": "oct", "k": "c2VjcmV0" }] },
            }),
            serde_json::json!({
                "application_type": "native",
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks_uri": "https://shop.example/jwks.json",
            }),
        ];
        for extra in cases {
            assert!(
                parse_document(&id(), &doc(extra.clone()), 0).is_err(),
                "accepted: {extra}"
            );
        }
        assert!(parse_document(&id(), b"not json", 0).is_err());
    }

    #[test]
    fn a_web_client_with_keys_is_confidential() {
        let body = doc(serde_json::json!({
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://shop.example/jwks.json",
        }));
        let client = parse_document(&id(), &body, 0).unwrap();
        assert!(client.confidential);
        let document = client.document.unwrap();
        assert_eq!(document.auth, ClientAuth::PrivateKeyJwt);
        assert_eq!(
            document.jwks_uri.as_deref(),
            Some("https://shop.example/jwks.json")
        );
    }

    #[test]
    fn a_native_application_returns_by_loopback_its_scheme_or_its_origin() {
        let body = doc(serde_json::json!({
            "application_type": "native",
            "redirect_uris": [
                "http://127.0.0.1/callback",
                "http://[::1]/callback",
                "example.shop:/callback",
                "https://shop.example/app-callback",
            ],
        }));
        let client = parse_document(&id(), &body, 0).unwrap();
        assert!(accepts_redirect(&client, "http://127.0.0.1:51234/callback"));
        assert!(accepts_redirect(&client, "http://127.0.0.1/callback"));
        assert!(accepts_redirect(&client, "http://[::1]:8000/callback"));
        assert!(accepts_redirect(&client, "example.shop:/callback"));
        assert!(!accepts_redirect(&client, "http://127.0.0.1:51234/other"));
        assert!(!accepts_redirect(
            &client,
            "http://localhost:51234/callback"
        ));
        assert!(!accepts_redirect(&client, "example.shop:/other"));

        for bad in [
            "http://localhost/callback",
            "shop.example:/callback",
            "example.shop://callback",
            "com.other:/callback",
        ] {
            let body = doc(serde_json::json!({
                "application_type": "native",
                "redirect_uris": [bad],
            }));
            assert!(parse_document(&id(), &body, 0).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn a_web_client_redirect_is_compared_exactly() {
        let client = parse_document(&id(), &doc(serde_json::json!({})), 0).unwrap();
        assert!(accepts_redirect(&client, "https://shop.example/callback"));
        assert!(!accepts_redirect(&client, "https://shop.example/callback/"));
        assert!(!accepts_redirect(
            &client,
            "https://shop.example/callback?x=1"
        ));
    }

    #[test]
    fn special_use_addresses_are_not_public() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.67.31.127",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "::1",
            "::",
            "fd00:ec2::254",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "2001:db8::1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "82.70.231.222",
            "2606:4700:4700::1111",
            "2a01:4f8::1",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn cache_control_gives_the_freshness() {
        assert_eq!(
            cache_max_age("public, max-age=600"),
            Some(Duration::from_secs(600))
        );
        assert_eq!(cache_max_age("no-store"), Some(Duration::ZERO));
        assert_eq!(cache_max_age("public"), None);
    }

    #[tokio::test]
    async fn the_fetcher_reaches_no_special_use_address() {
        let fetcher = HttpFetcher::new().expect("the TLS backend starts");
        for url in [
            "https://localhost/client.json",
            "https://127.0.0.1/client.json",
            "https://[::1]/client.json",
            "http://shop.example/client.json",
        ] {
            let url = Url::parse(url).unwrap();
            assert!(fetcher.fetch(&url).await.is_err(), "{url}");
        }
    }

    /// Reads a real document over the network: `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "needs the network"]
    async fn the_fetcher_reads_a_public_document() {
        let fetcher = HttpFetcher::new().unwrap();
        let url = Url::parse("https://helm.brig.id/.well-known/openid-configuration").unwrap();
        let fetched = fetcher.fetch(&url).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&fetched.body).unwrap();
        assert_eq!(json["issuer"], "https://helm.brig.id");
    }
}
