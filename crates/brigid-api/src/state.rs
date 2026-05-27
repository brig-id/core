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
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

/// In-flight registration session keyed by a temporary session UUID.
pub struct PendingRegistration {
    pub user_id: Uuid,
    pub username: String,
    pub server: String,
    pub state: PasskeyRegistration,
    /// Timestamp when this session was created; used for TTL eviction.
    pub created_at: Instant,
}

/// In-flight authentication session keyed by a temporary session UUID.
pub struct PendingAuthentication {
    pub user_id: Uuid,
    pub state: PasskeyAuthentication,
    /// Timestamp when this session was created; used for TTL eviction.
    pub created_at: Instant,
}

/// Challenge sessions expire after 5 minutes of inactivity.
const PENDING_SESSION_TTL: Duration = Duration::from_secs(300);

/// Central application state shared (via `Arc`) across all request handlers.
pub struct AppState {
    pub store: Arc<EncryptedStore>,
    pub webauthn: Arc<brigid_webauthn::WebauthnService>,
    pub oidc_key: Arc<OidcSigningKey>,
    pub jti_store: Arc<Mutex<JtiStore>>,
    pub base_url: Url,
    /// Pre-computed VSID salt — caller must use `brigid_identity::derive_vsid_salt(&master)`.
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
