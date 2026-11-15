//! Data models for brigid-store.

use std::collections::BTreeMap;

use brigid_identity::{Attribute, Attributes, Need};
use serde::{Deserialize, Serialize};
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

/// An identity of an account (`users`). Its `name`, `logo` and `description`
/// are labels for the person, inside brig·id: no relying party receives
/// them. `logo` is an `icon:<style>:<name>` reference. A relying party
/// receives the VSID derived from `id`, and the `attributes` the person
/// accepted to share with it ([`Grant`]).
#[derive(Debug, Clone)]
pub struct Identity {
    pub id: Uuid,
    pub account_id: Uuid,
    pub name: String,
    pub logo: String,
    pub description: Option<String>,
    /// What the identity can share. An absent attribute has no value.
    pub attributes: Attributes,
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
    /// The attributes it may ask for, and whether it needs each one. A
    /// request for anything else is refused.
    pub attributes: BTreeMap<Attribute, Need>,
    /// Unix seconds.
    pub created_at: i64,
}

/// What a person decided about one attribute for one relying party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// The value they accepted to share; `None` when they refused. A person
    /// accepts a value, not a field name: once the identity's value differs
    /// from this one, nothing is accepted any more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// When they decided (Unix seconds).
    pub at: i64,
}

/// What an identity gave a relying party: it exists from the first sign-in
/// there, with no decision when nothing was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub identity_id: Uuid,
    pub client_id: String,
    pub decisions: BTreeMap<Attribute, Decision>,
    /// The first sign-in (Unix seconds).
    pub created_at: i64,
    /// The latest sign-in (Unix seconds).
    pub last_used_at: i64,
}

impl Grant {
    /// The value of `attribute` the person accepted to share, if they did.
    pub fn shared(&self, attribute: Attribute) -> Option<&str> {
        self.decisions.get(&attribute)?.value.as_deref()
    }

    /// Whether the person refused to share `attribute`.
    pub fn refused(&self, attribute: Attribute) -> bool {
        self.decisions
            .get(&attribute)
            .is_some_and(|decision| decision.value.is_none())
    }
}
