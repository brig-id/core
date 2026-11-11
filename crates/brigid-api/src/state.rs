//! Shared application state passed to all Axum handlers via [`axum::extract::State`].

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use brigid_oidc::{JtiStore, OidcSigningKey};
use brigid_store::EncryptedStore;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration,
};

/// In-flight registration session keyed by a temporary session UUID.
pub struct PendingRegistration {
    pub user_id: Uuid,
    pub username: String,
    pub server: String,
    pub state: PasskeyRegistration,
    /// Timestamp when this session was created; used for TTL eviction.
    pub created_at: Instant,
}

/// The WebAuthn state of a pending login: for a named user, or username-less
/// (discoverable credential, the user is learnt from the response).
pub enum PendingLogin {
    Named {
        user_id: Uuid,
        state: PasskeyAuthentication,
    },
    Discoverable(DiscoverableAuthentication),
}

/// In-flight authentication session keyed by a temporary session UUID.
pub struct PendingAuthentication {
    /// Relying-party identifier sent at `/auth/login/begin`. Bound into the
    /// pending session so the `aud` claim and VSID derived at
    /// `/auth/login/finish` cannot be changed between the two halves of the
    /// flow (an attacker controlling the second request must otherwise be
    /// able to swap the audience for a token they did not initiate).
    pub client_id: String,
    pub login: PendingLogin,
    /// Timestamp when this session was created; used for TTL eviction.
    pub created_at: Instant,
}

/// Challenge sessions expire after 5 minutes of inactivity.
pub(crate) const PENDING_SESSION_TTL: Duration = Duration::from_secs(300);

/// Hard upper bound on the number of in-flight WebAuthn challenges held in
/// memory for each of the registration and authentication maps.
///
/// `evict_expired_pending()` provides a soft bound (TTL only), but a sustained
/// burst of `begin_*` requests faster than the TTL can still grow the maps
/// without limit. This cap turns that growth into a backpressure signal
/// (HTTP 429) instead of letting attackers exhaust process memory.
///
/// Sized to keep total worst-case memory for both maps below ~10 MB on a
/// 64-bit target, comfortably above the per-IP rate limit (20 req/min) for
/// a small operator deployment but small enough to detect floods.
pub(crate) const PENDING_SESSION_MAX_CAPACITY: usize = 10_000;

/// Central application state shared (via `Arc`) across all request handlers.
pub struct AppState {
    pub store: Arc<EncryptedStore>,
    pub webauthn: Arc<brigid_webauthn::WebauthnService>,
    /// The key that signs new tokens.
    pub oidc_key: Arc<OidcSigningKey>,
    /// Keys retired by a rotation but still within their grace period: tokens
    /// they signed still verify and they stay in the JWKS (core#22).
    pub retired_oidc_keys: Vec<Arc<OidcSigningKey>>,
    pub jti_store: Arc<Mutex<JtiStore>>,
    pub base_url: Url,
    /// The keying material of every VSID: `EncryptedStore::vsid_secret`.
    pub vsid_salt: [u8; 32],
    pub pending_registrations: Arc<Mutex<HashMap<Uuid, PendingRegistration>>>,
    pub pending_authentications: Arc<Mutex<HashMap<Uuid, PendingAuthentication>>>,
    /// Whether to trust `x-forwarded-for` for rate-limit key extraction.
    ///
    /// MUST be `true` only when the API is reachable exclusively through a
    /// trusted reverse proxy (e.g. Caddy in the reference deployment) that
    /// overwrites the header. If the API is reachable directly, an attacker
    /// can forge the header to bypass rate limits — keep this `false`.
    pub trust_forwarded_for: bool,
}

impl AppState {
    pub fn new(
        store: EncryptedStore,
        webauthn: brigid_webauthn::WebauthnService,
        oidc_key: OidcSigningKey,
        base_url: Url,
        vsid_salt: [u8; 32],
    ) -> Self {
        Self {
            store: Arc::new(store),
            webauthn: Arc::new(webauthn),
            oidc_key: Arc::new(oidc_key),
            retired_oidc_keys: Vec::new(),
            jti_store: Arc::new(Mutex::new(JtiStore::new())),
            base_url,
            vsid_salt,
            pending_registrations: Arc::new(Mutex::new(HashMap::new())),
            pending_authentications: Arc::new(Mutex::new(HashMap::new())),
            // Default to false — safe for direct exposure and tests. The
            // production deployment binary (`server-leaf`) must opt-in when
            // Caddy (or another trusted proxy) terminates the public TLS edge.
            trust_forwarded_for: false,
        }
    }

    /// Keys retired by a rotation that must keep verifying their tokens.
    #[must_use]
    pub fn with_retired_oidc_keys(mut self, keys: Vec<OidcSigningKey>) -> Self {
        self.retired_oidc_keys = keys.into_iter().map(Arc::new).collect();
        self
    }

    /// This server's host name: the domain of its accounts and the `server`
    /// claim of the tokens it issues. Never taken from stored or
    /// client-supplied data.
    pub fn host(&self) -> Result<&str, crate::error::ApiError> {
        self.base_url
            .host_str()
            .ok_or_else(|| crate::error::ApiError::Internal("base_url has no host".into()))
    }

    /// The current key followed by the retired ones still in grace.
    pub fn oidc_verification_keys(&self) -> Vec<&OidcSigningKey> {
        std::iter::once(self.oidc_key.as_ref())
            .chain(self.retired_oidc_keys.iter().map(AsRef::as_ref))
            .collect()
    }

    /// Evict pending sessions older than [`PENDING_SESSION_TTL`].
    ///
    /// Call this before inserting a new pending session to bound memory growth.
    pub fn evict_expired_pending(&self) {
        let cutoff = Instant::now() - PENDING_SESSION_TTL;
        self.pending_registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, v| v.created_at > cutoff);
        self.pending_authentications
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, v| v.created_at > cutoff);
    }
}
