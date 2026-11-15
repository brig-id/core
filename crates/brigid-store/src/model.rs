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

/// What a link handed out by the server is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    /// Creates the first account, as administrator.
    Setup,
    /// Grants the role to the signed-in account that opens it.
    Admin,
    /// Creates an ordinary account.
    Invitation,
}

impl LinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Admin => "admin",
            Self::Invitation => "invitation",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "setup" => Some(Self::Setup),
            "admin" => Some(Self::Admin),
            "invitation" => Some(Self::Invitation),
            _ => None,
        }
    }
}

/// A link as its maker sees it afterwards: never the link itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub id: Uuid,
    pub kind: LinkKind,
    /// How many more times it can be used.
    pub uses_left: i64,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
}

/// Who may create an account on this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupPolicy {
    /// Anyone.
    Open,
    /// Whoever holds an invitation. The default: a server is not open to
    /// strangers until its administrator says so.
    Invitation,
    /// Nobody.
    Closed,
}

impl SignupPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Invitation => "invitation",
            Self::Closed => "closed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "invitation" => Some(Self::Invitation),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

/// What an administrator sees of an account: enough to run the server,
/// nothing of what the person does with it. No identity, no label, no
/// attribute, no application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    pub id: Uuid,
    /// The generated username: what the person's passkey manager shows.
    pub username: String,
    pub created_at: OffsetDateTime,
    pub admin: bool,
    /// Unix seconds since when it is suspended.
    pub suspended_at: Option<i64>,
    /// Unix seconds of the last passkey ceremony that opened a session.
    pub last_sign_in_at: Option<i64>,
    pub passkeys: i64,
    /// Whether it has a usable recovery code.
    pub recovery_code: bool,
}

/// Where an account stands for the server: its role, and whether it may
/// sign in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountStanding {
    pub admin: bool,
    pub suspended: bool,
}

/// One administrative action, as it is logged.
///
/// Accounts are named by their identifier, never by a name: the name is
/// looked up when the log is read, and an entry about an account that was
/// deleted since names nobody. Nothing an account's identities are or do is
/// ever written here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminAction {
    /// What was done, e.g. `account.suspend`.
    pub action: String,
    /// The account that did it; `None` for the machine's command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Uuid>,
    /// The account it was done to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<Uuid>,
    /// The application it was done to, by its registered name, or a value
    /// that was set (a sign-up policy). Never personal data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// An entry of the log of administrative actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminLogEntry {
    /// Unix seconds.
    pub at: i64,
    pub action: AdminAction,
}
