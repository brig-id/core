//! Data models for brigid-store.

use time::OffsetDateTime;
use uuid::Uuid;

/// A brig·id user record.
#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub server: String,
    pub created_at: OffsetDateTime,
}

/// A WebAuthn credential bound to a user.
///
/// The `data` field holds arbitrary serialised credential bytes that are
/// encrypted end-to-end before storage.
#[derive(Debug, Clone)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub data: Vec<u8>,
}

/// An identity of an account (`users`). Its `name` and `logo` are labels for
/// the person, inside brig·id: no relying party receives them, only the VSID
/// derived from `id`. `logo` is an `icon:<style>:<name>` reference.
#[derive(Debug, Clone)]
pub struct Identity {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub logo: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// A stored OIDC signing key: its `kid` and decrypted 32-byte seed.
/// `retired_at` is `None` for the current key.
pub struct StoredOidcKey {
    pub kid: String,
    pub seed: zeroize::Zeroizing<[u8; 32]>,
    pub created_at: OffsetDateTime,
    pub retired_at: Option<OffsetDateTime>,
}

/// Where an account stands with its recovery code (ADR-004).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryStatus {
    /// When the current code was generated; `None` when there is no usable code.
    pub code_created_at: Option<OffsetDateTime>,
    /// When a code was last used to recover the account.
    pub last_used_at: Option<OffsetDateTime>,
}

/// A registered relying party (ADR-005 §2): a site that may ask this server to
/// sign people in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub client_id: String,
    /// Shown to the person on the page that links an identity to the site.
    pub name: String,
    /// Where the person may be sent back, compared exactly.
    pub redirect_uris: Vec<String>,
    /// Whether the client authenticates with a secret at the token endpoint.
    /// A public client has none.
    pub confidential: bool,
    /// Unix seconds.
    pub created_at: i64,
}
