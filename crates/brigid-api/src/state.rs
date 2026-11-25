//! Shared application state passed to all Axum handlers via [`axum::extract::State`].

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use brigid_identity::{Attribute, Attributes, Need};
use brigid_oidc::OidcSigningKey;
use brigid_store::{Client, ClientList, ClientPolicy, EncryptedStore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration,
};

use crate::{
    error::ApiError,
    shared::{Kind, Memory, Shared},
};

/// What a registration ceremony was started for. Each `finish` endpoint
/// accepts only its own kind, so a session begun to add a passkey (or to
/// recover an account) cannot be completed as something else.
#[derive(Serialize, Deserialize)]
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

impl RegistrationPurpose {
    /// The kind a ceremony begun for this is kept under.
    pub fn kind(&self) -> Kind {
        match self {
            Self::Signup => Kind::Signup,
            Self::AddPasskey => Kind::AddPasskey,
            Self::Recovery { .. } => Kind::Recovery,
        }
    }
}

/// In-flight registration session keyed by a temporary session UUID. It
/// is kept for [`Kind::ttl`], by what keeps the server's shared state.
#[derive(Serialize, Deserialize)]
pub struct PendingRegistration {
    pub purpose: RegistrationPurpose,
    /// The setup link or the invitation that allows this sign-up, when the
    /// server asks for one. Spent when the account is created.
    pub link: Option<String>,
    pub user_id: Uuid,
    pub username: String,
    pub server: String,
    pub state: PasskeyRegistration,
}

/// The WebAuthn state of a pending login: for a named user, or username-less
/// (discoverable credential, the user is learnt from the response).
#[derive(Serialize, Deserialize)]
pub enum PendingLogin {
    Named {
        user_id: Uuid,
        state: PasskeyAuthentication,
    },
    Discoverable(DiscoverableAuthentication),
}

/// What an authentication ceremony was started for. Each `finish` endpoint
/// accepts only its own kind: a ceremony begun to sign in cannot delete an
/// account, and the other way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticationPurpose {
    /// Opening a session (`/auth/login/*`).
    SignIn,
    /// Deleting the signed-in account (`/account/delete/*`).
    DeleteAccount,
    /// Confirming, in an open session, that the person is there: asked
    /// before an administrative change (`/auth/confirm/*`).
    Confirm,
}

impl AuthenticationPurpose {
    /// The kind a ceremony begun for this is kept under.
    pub fn kind(self) -> Kind {
        match self {
            Self::SignIn => Kind::SignIn,
            Self::DeleteAccount => Kind::DeleteAccount,
            Self::Confirm => Kind::Confirm,
        }
    }
}

/// In-flight authentication session keyed by a temporary session UUID. It
/// is kept for [`Kind::ttl`], by what keeps the server's shared state.
#[derive(Serialize, Deserialize)]
pub struct PendingAuthentication {
    pub purpose: AuthenticationPurpose,
    pub login: PendingLogin,
}

/// What the `prompt` parameter of an authorization request asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// An authorization request (spec `protocol.md` §6) that passed validation and waits
/// for the person: sign in if needed, then choose an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuthorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    /// PKCE `S256` challenge (spec `protocol.md` §6: every client sends one).
    pub code_challenge: String,
    pub prompt: Prompt,
    /// The attributes the request asks for, and whether the application
    /// needs each one: what its scopes cover of the client's registration.
    pub asked: BTreeMap<Attribute, Need>,
    /// `max_age`: the passkey ceremony must be at most this many seconds old.
    pub max_age: Option<i64>,
    /// Unix time of the request: with `prompt=login`, the passkey ceremony
    /// must be more recent.
    pub created_unix: i64,
}

/// An authorization code waiting to be exchanged at the token endpoint.
#[derive(Serialize, Deserialize)]
pub struct IssuedCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub account_id: Uuid,
    pub identity_id: Uuid,
    /// The attributes the token will carry: asked by the request, and
    /// accepted by the person with these exact values.
    pub attributes: Attributes,
    /// Unix time of the passkey ceremony behind the session.
    pub auth_time: i64,
}

/// The log of administrative actions is kept twelve months unless the
/// operator says otherwise.
pub(crate) const ADMIN_LOG_RETENTION: Duration = Duration::from_secs(365 * 24 * 3600);

/// An administrative change needs a passkey ceremony at most this old.
pub(crate) const CONFIRMATION_TTL: Duration = Duration::from_secs(300);

/// A setup link, and a link that grants the administrator role, last an hour.
pub const OPERATOR_LINK_TTL: Duration = Duration::from_secs(3600);

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
    /// An account session ends after this long without use (spec `protocol.md` §5).
    pub session_idle: Duration,
    /// An account session ends this long after the passkey ceremony that
    /// opened it, used or not (spec `protocol.md` §5).
    pub session_lifetime: Duration,
    /// The keying material of every VSID: `EncryptedStore::vsid_secret`.
    pub vsid_salt: [u8; 32],
    /// What every node of this server must see the same, and that lives
    /// minutes: passkey ceremonies in progress, authorization requests
    /// waiting for the person, authorization codes, the assertions of
    /// clients already presented. In this process's memory unless the
    /// edition says otherwise ([`AppState::with_shared`]).
    pub shared: Arc<dyn Shared>,
    /// How long an entry of the log of administrative actions is kept. The
    /// log holds identifiers of accounts: it is not kept for ever.
    pub admin_log_retention: Duration,
    /// How old the latest passkey ceremony of a session may be for an
    /// administrative change to be accepted from it.
    pub confirmation_ttl: Duration,
    /// The program this server is, and its version: what its administrators
    /// read to know what runs. `None` when the program did not say.
    pub edition: Option<Edition>,
    /// Whether to trust `x-forwarded-for` for rate-limit key extraction.
    ///
    /// MUST be `true` only when the API is reachable exclusively through a
    /// trusted reverse proxy (e.g. Caddy in the reference deployment) that
    /// overwrites the header. If the API is reachable directly, an attacker
    /// can forge the header to bypass rate limits — keep this `false`.
    pub trust_forwarded_for: bool,
    /// What reads the documents of clients that describe themselves, and
    /// what was read of them lately (protocol.md §6).
    pub described: Arc<crate::described::Described>,
}

/// The program a server is, as it names itself: an edition and its version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edition {
    pub name: String,
    pub version: String,
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
            shared: Arc::new(Memory::new()),
            admin_log_retention: ADMIN_LOG_RETENTION,
            confirmation_ttl: CONFIRMATION_TTL,
            edition: None,
            // Default to false — safe for direct exposure and tests. An
            // edition behind a trusted proxy (Caddy, nginx) that replaces
            // `X-Forwarded-For` opts in (`security.trust_forwarded_for`).
            trust_forwarded_for: false,
            described: Arc::new(crate::described::Described::new(default_fetcher())),
        }
    }

    /// What keeps the state shared between the nodes of this server, for
    /// an edition made of several: one node's memory is not enough there.
    #[must_use]
    pub fn with_shared(mut self, shared: Arc<dyn Shared>) -> Self {
        self.shared = shared;
        self
    }

    /// What reads client documents: tests give their own.
    #[must_use]
    pub fn with_fetcher(mut self, fetcher: Arc<dyn crate::described::Fetch>) -> Self {
        self.described = Arc::new(crate::described::Described::new(fetcher));
        self
    }

    /// The client `client_id`: registered on the machine, or describing
    /// itself at that URL and accepted by the operator's policy. `None` when
    /// it is neither, or its document cannot be read and was never read.
    ///
    /// A document read is kept in the store: the identities chosen for the
    /// client and what people shared with it point to it, and it serves
    /// while a new read fails.
    pub async fn client(&self, client_id: &str) -> Result<Option<Client>, crate::error::ApiError> {
        let internal = |e: brigid_store::Error| crate::error::ApiError::Internal(Box::new(e));
        let Some(url) = crate::described::client_id_url(client_id) else {
            // A registered client; a described one is never read by this
            // way, so that the policy and the lists always apply.
            return Ok(self
                .store
                .fetch_client(client_id)
                .await
                .map_err(internal)?
                .filter(|client| !client.described()));
        };
        let list = self.store.client_list(client_id).await.map_err(internal)?;
        let accepted = match self.store.client_policy().await.map_err(internal)? {
            ClientPolicy::Registered => false,
            ClientPolicy::Open => list != Some(ClientList::Refused),
            ClientPolicy::Listed => list == Some(ClientList::Accepted),
        };
        if !accepted {
            return Ok(None);
        }
        let now = helpers4::time::unix_now().map_or(0, |secs| secs as i64);
        match self.described.client(&url, now).await {
            Ok(mut client) => {
                // The operator's cap: what the document asks beyond it is
                // dropped, as if the document did not ask it.
                let cap = self.store.described_attributes().await.map_err(internal)?;
                client
                    .attributes
                    .retain(|attribute, _| cap.contains(attribute));
                // The first sign-in's date stays the creation date.
                if let Some(known) = self.store.fetch_client(client_id).await.map_err(internal)? {
                    client.created_at = known.created_at;
                }
                self.store
                    .save_described_client(&client)
                    .await
                    .map_err(internal)?;
                Ok(Some(client))
            }
            Err(reason) => {
                tracing::info!(client_id, %reason, "client document not usable");
                // The last valid document, while a new read fails, under
                // today's cap.
                let cap = self.store.described_attributes().await.map_err(internal)?;
                Ok(self
                    .store
                    .fetch_client(client_id)
                    .await
                    .map_err(internal)?
                    .filter(Client::described)
                    .map(|mut client| {
                        client
                            .attributes
                            .retain(|attribute, _| cap.contains(attribute));
                        client
                    }))
            }
        }
    }

    /// Session timeouts: `idle` without use, `lifetime` in any case.
    #[must_use]
    pub fn with_session_timeouts(mut self, idle: Duration, lifetime: Duration) -> Self {
        self.session_idle = idle;
        self.session_lifetime = lifetime;
        self
    }

    /// How recent a passkey ceremony an administrative change asks for.
    #[must_use]
    pub fn with_confirmation_ttl(mut self, ttl: Duration) -> Self {
        self.confirmation_ttl = ttl;
        self
    }

    /// The program built on this crate, and its version (`seedling`,
    /// `0.6.1`): public, in `GET /auth/server`.
    #[must_use]
    pub fn with_edition(mut self, name: &str, version: &str) -> Self {
        self.edition = Some(Edition {
            name: name.to_owned(),
            version: version.to_owned(),
        });
        self
    }

    /// How long the log of administrative actions is kept.
    #[must_use]
    pub fn with_admin_log_retention(mut self, retention: Duration) -> Self {
        self.admin_log_retention = retention;
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

    /// Keeps `value` under `kind` and `id`, for the kind's time. `false`
    /// when too many of its family are kept already.
    pub(crate) async fn hold<T: Serialize>(
        &self,
        kind: Kind,
        id: &str,
        value: &T,
    ) -> Result<bool, ApiError> {
        let bytes = serde_json::to_vec(value).map_err(|e| ApiError::Internal(Box::new(e)))?;
        self.shared
            .put(kind, id, bytes)
            .await
            .map_err(ApiError::Internal)
    }

    /// What is kept under `kind` and `id`, left in place.
    pub(crate) async fn held<T: DeserializeOwned>(
        &self,
        kind: Kind,
        id: &str,
    ) -> Result<Option<T>, ApiError> {
        let bytes = self
            .shared
            .get(kind, id)
            .await
            .map_err(ApiError::Internal)?;
        Ok(bytes.and_then(|bytes| read(kind, &bytes)))
    }

    /// Takes what is kept under `kind` and `id` out: it is given once.
    pub(crate) async fn take<T: DeserializeOwned>(
        &self,
        kind: Kind,
        id: &str,
    ) -> Result<Option<T>, ApiError> {
        let bytes = self
            .shared
            .take(kind, id)
            .await
            .map_err(ApiError::Internal)?;
        Ok(bytes.and_then(|bytes| read(kind, &bytes)))
    }

    /// Keep an authorization request for the person to answer; returns its
    /// id. `None` when too many are waiting already.
    pub async fn hold_authorization(
        &self,
        request: &PendingAuthorization,
    ) -> Result<Option<String>, ApiError> {
        let Some(id) = random_token() else {
            return Ok(None);
        };
        Ok(self
            .hold(Kind::Authorization, &id, request)
            .await?
            .then_some(id))
    }

    /// The authorization request `id`, if it is still waiting.
    pub async fn pending_authorization(
        &self,
        id: &str,
    ) -> Result<Option<PendingAuthorization>, ApiError> {
        self.held(Kind::Authorization, id).await
    }

    /// Take the authorization request `id` out: it is answered once.
    pub async fn take_authorization(
        &self,
        id: &str,
    ) -> Result<Option<PendingAuthorization>, ApiError> {
        self.take(Kind::Authorization, id).await
    }

    /// Issue an authorization code. `None` when too many are waiting already.
    pub async fn issue_code(&self, code: &IssuedCode) -> Result<Option<String>, ApiError> {
        let Some(value) = random_token() else {
            return Ok(None);
        };
        Ok(self.hold(Kind::Code, &value, code).await?.then_some(value))
    }

    /// Take a code out, whatever happens next: a code is presented once.
    pub async fn redeem_code(&self, code: &str) -> Result<Option<IssuedCode>, ApiError> {
        self.take(Kind::Code, code).await
    }
}

/// A kept value as what it was kept as. A value that cannot be read (kept
/// by a node of another version, which a new kind prevents) is as absent.
fn read<T: DeserializeOwned>(kind: Kind, bytes: &[u8]) -> Option<T> {
    serde_json::from_slice(bytes)
        .map_err(
            |e| tracing::warn!(kind = kind.name(), error = %e, "a kept value could not be read"),
        )
        .ok()
}

/// Reads documents over HTTPS; if the TLS backend cannot start, a fetcher
/// that reads nothing, so that registered clients keep working.
fn default_fetcher() -> Arc<dyn crate::described::Fetch> {
    match crate::described::HttpFetcher::new() {
        Ok(fetcher) => Arc::new(fetcher),
        Err(e) => {
            tracing::error!(error = %e, "cannot read client documents");
            Arc::new(Unreachable)
        }
    }
}

struct Unreachable;

impl crate::described::Fetch for Unreachable {
    fn fetch<'a>(&'a self, _: &'a Url) -> crate::described::FetchFuture<'a> {
        Box::pin(async { Err("this server cannot read client documents".into()) })
    }
}

/// 256 random bits in hexadecimal: a request id, a code, an access token.
/// `None` when the operating system has no entropy to give.
pub(crate) fn random_token() -> Option<String> {
    helpers4::random::random_bytes(32)
        .ok()
        .map(|bytes| helpers4::hex::encode(&bytes))
}
