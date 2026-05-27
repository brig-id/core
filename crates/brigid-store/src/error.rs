//! Error types for brigid-store.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("crypto error: {0}")]
    Crypto(#[from] brigid_crypto::Error),

    #[error("invalid encrypted blob")]
    InvalidBlob,

    #[error("UTF-8 decode error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("UUID parse error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("timestamp error: {0}")]
    Time(String),

    /// A row with a unique key (e.g. `username_index`) already exists.
    /// This is the authoritative duplicate signal — pre-checks are advisory only.
    #[error("duplicate row (unique constraint violated)")]
    Duplicate,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
