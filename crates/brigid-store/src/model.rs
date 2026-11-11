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

/// An identity: what a relying party sees. It belongs to one account (`users`).
///
/// never changes the VSID derived from it. `logo` is an `icon:<style>:<name>`
/// reference.
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
