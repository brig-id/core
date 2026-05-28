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

    /// An update or fetch targeted a row that does not exist (any more).
    /// Surfaced by [`update_credential`](crate::update_credential) when
    /// `UPDATE` matches zero rows — e.g. the credential was concurrently
    /// deleted while a counter persistence was in flight.
    #[error("row not found")]
    NotFound,

    /// A `Credential` was handed to an atomic-registration entry point with
    /// a `user_id` that does not match the `User` being created. Returned
    /// by [`EncryptedStore::register_user_with_credential`](crate::EncryptedStore::register_user_with_credential)
    /// before any database write to prevent attaching a wrongly-encrypted
    /// credential to the new user (or attaching the new user's credential to
    /// another existing user).
    #[error("credential user_id does not match the user being registered")]
    CredentialUserMismatch,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
