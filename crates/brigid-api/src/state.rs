//! Shared application state passed to all Axum handlers via [`axum::extract::State`].

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use brigid_oidc::OidcSigningKey;
use brigid_store::EncryptedStore;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration,
};

/// What a registration ceremony was started for. Each `finish` endpoint
/// accepts only its own kind, so a session begun to add a passkey (or to
/// recover an account) cannot be completed as something else.
pub enum RegistrationPurpose {
    /// A new account (`/auth/register/*`); `finish` signs it in.
    Signup,
    /// One more passkey for a signed-in account (`/auth/passkeys/add/*`).
    AddPasskey,
    /// A passkey enrolled with a recovery code (`/auth/recovery/*`). The
    /// code's recovery id is consumed at `finish`, which signs in.
    Recovery {
        recovery_id: [u8; brigid_identity::recovery::RECOVERY_ID_LEN],
    },
}

/// In-flight registration session keyed by a temporary session UUID.
pub struct PendingRegistration {
    pub purpose: RegistrationPurpose,
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
    pub login: PendingLogin,
    /// Timestamp when this session was created; used for TTL eviction.
    pub created_at: Instant,
}

/// What the `prompt` parameter of an authorization request asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    /// Nothing in particular.
    Default,
    /// A new passkey ceremony, whatever the session.
    Login,
    /// Show the choice of identity even if one is remembered
    /// (`consent`, `select_account`).
    Select,
    /// No interface at all: answer from what is already known, or fail.
    None,
}

/// An authorization request (ADR-005 §2) that passed validation and waits
/// for the person: sign in if needed, then choose an identity.
#[derive(Debug, Clone)]
pub struct PendingAuthorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    /// PKCE `S256` challenge (ADR-008: every client sends one).
    pub code_challenge: String,
    pub prompt: Prompt,
    /// `max_age`: the passkey ceremony must be at most this many seconds old.
    pub max_age: Option<i64>,
    pub created_at: Instant,
    /// Unix time of the request: with `prompt=login`, the passkey ceremony
    /// must be more recent.
    pub created_unix: i64,
}

/// An authorization code waiting to be exchanged at the token endpoint.
pub struct IssuedCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub account_id: Uuid,
    pub identity_id: Uuid,
    /// Unix time of the passkey ceremony behind the session.
    pub auth_time: i64,
    pub created_at: Instant,
}

/// A person has ten minutes to sign in and choose an identity.
pub(crate) const PENDING_AUTHORIZATION_TTL: Duration = Duration::from_secs(600);

/// A relying party has one minute to exchange a code.
pub(crate) const AUTHORIZATION_CODE_TTL: Duration = Duration::from_secs(60);

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
    pub base_url: Url,
    /// An account session ends after this long without use (ADR-005).
    pub session_idle: Duration,
    /// An account session ends this long after the passkey ceremony that
    /// opened it, used or not (ADR-005).
    pub session_lifetime: Duration,
    /// The keying material of every VSID: `EncryptedStore::vsid_secret`.
    pub vsid_salt: [u8; 32],
    pub pending_registrations: Arc<Mutex<HashMap<Uuid, PendingRegistration>>>,
    pub pending_authentications: Arc<Mutex<HashMap<Uuid, PendingAuthentication>>>,
    /// Authorization requests waiting for the person, by request id.
    pub pending_authorizations: Arc<Mutex<HashMap<String, PendingAuthorization>>>,
    /// Authorization codes waiting to be exchanged, by code.
    pub authorization_codes: Arc<Mutex<HashMap<String, IssuedCode>>>,
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
            base_url,
            session_idle: Duration::from_secs(3600),
            session_lifetime: Duration::from_secs(12 * 3600),
            vsid_salt,
            pending_registrations: Arc::new(Mutex::new(HashMap::new())),
            pending_authentications: Arc::new(Mutex::new(HashMap::new())),
            pending_authorizations: Arc::new(Mutex::new(HashMap::new())),
            authorization_codes: Arc::new(Mutex::new(HashMap::new())),
            // Default to false — safe for direct exposure and tests. The
            // production deployment binary (`server-leaf`) must opt-in when
            // Caddy (or another trusted proxy) terminates the public TLS edge.
            trust_forwarded_for: false,
        }
    }

    /// Session timeouts: `idle` without use, `lifetime` in any case.
    #[must_use]
    pub fn with_session_timeouts(mut self, idle: Duration, lifetime: Duration) -> Self {
        self.session_idle = idle;
        self.session_lifetime = lifetime;
        self
    }

    /// Whether this server is reached over HTTPS: the session cookie is then
    /// `Secure` with the `__Host-` prefix. Plain HTTP is for local development.
    pub fn https(&self) -> bool {
        self.base_url.scheme() == "https"
    }

    /// The origin of this server (`scheme://host[:port]`), as browsers send it
    /// in the `Origin` header.
    pub fn origin(&self) -> String {
        self.base_url.origin().ascii_serialization()
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

    /// This server's issuer identifier: its base URL without a trailing slash.
    pub fn issuer(&self) -> &str {
        self.base_url.as_str().trim_end_matches('/')
    }

    /// Keep an authorization request for the person to answer; returns its
    /// id. `None` when too many are waiting already.
    pub fn hold_authorization(&self, request: PendingAuthorization) -> Option<String> {
        let id = random_token()?;
        let mut pending = self
            .pending_authorizations
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pending.retain(|_, v| v.created_at.elapsed() < PENDING_AUTHORIZATION_TTL);
        if pending.len() >= PENDING_SESSION_MAX_CAPACITY {
            return None;
        }
        pending.insert(id.clone(), request);
        Some(id)
    }

    /// The authorization request `id`, if it is still waiting.
    pub fn pending_authorization(&self, id: &str) -> Option<PendingAuthorization> {
        self.pending_authorizations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .filter(|v| v.created_at.elapsed() < PENDING_AUTHORIZATION_TTL)
            .cloned()
    }

    /// Take the authorization request `id` out: it is answered once.
    pub fn take_authorization(&self, id: &str) -> Option<PendingAuthorization> {
        self.pending_authorizations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id)
            .filter(|v| v.created_at.elapsed() < PENDING_AUTHORIZATION_TTL)
    }

    /// Issue an authorization code. `None` when too many are waiting already.
    pub fn issue_code(&self, code: IssuedCode) -> Option<String> {
        let value = random_token()?;
        let mut codes = self
            .authorization_codes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        codes.retain(|_, v| v.created_at.elapsed() < AUTHORIZATION_CODE_TTL);
        if codes.len() >= PENDING_SESSION_MAX_CAPACITY {
            return None;
        }
        codes.insert(value.clone(), code);
        Some(value)
    }

    /// Take a code out, whatever happens next: a code is presented once.
    pub fn redeem_code(&self, code: &str) -> Option<IssuedCode> {
        self.authorization_codes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(code)
            .filter(|v| v.created_at.elapsed() < AUTHORIZATION_CODE_TTL)
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

/// 256 random bits in hexadecimal: a request id, a code, an access token.
/// `None` when the operating system has no entropy to give.
pub(crate) fn random_token() -> Option<String> {
    helpers4::random::random_bytes(32)
        .ok()
        .map(|bytes| helpers4::hex::encode(&bytes))
}
