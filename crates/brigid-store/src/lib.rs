//! brigid-store: zero-trust SQLite storage for brig·id.
//!
//! All sensitive fields are encrypted with AES-256-GCM before INSERT.
//! A raw SQLite dump must never reveal readable secrets.

pub mod admin;
pub mod error;
pub mod model;
pub mod store;

pub use error::{Error, Result};
pub use model::{
    AccountStanding, AccountSummary, AcmeSecret, AdminAction, AdminLogEntry, ApplicationType,
    Client, ClientAuth, ClientDocument, ClientList, ClientPolicy, Credential, Decision, Grant,
    Identity, Link, LinkKind, RecoveryStatus, SignupPolicy, StoredOidcKey, User,
};
pub use store::{EncryptedStore, SessionInfo, fetch_user, fetch_user_by_username, store_user};

/// SQLx migrator — embeds all `migrations/` SQL files at compile time.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
