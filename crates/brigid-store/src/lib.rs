//! brigid-store: zero-trust SQLite storage for brig·id.
//!
//! All sensitive fields are encrypted with AES-256-GCM before INSERT.
//! A raw SQLite dump must never reveal readable secrets.

pub mod error;
pub mod model;
pub mod store;

pub use error::{Error, Result};
pub use model::{Credential, User};
pub use store::EncryptedStore;

/// SQLx migrator — embeds all `migrations/` SQL files at compile time.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
