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

    /// An identity's name, logo or description failed validation.
    #[error("invalid identity: {0}")]
    InvalidIdentity(#[from] brigid_identity::Error),

    /// A passkey label is too long or contains control characters.
    #[error("invalid passkey label")]
    InvalidLabel,

    /// A relying party's name or one of its redirect URIs failed validation.
    #[error("invalid client: {0}")]
    InvalidClient(&'static str),

    #[error("timestamp error: {0}")]
    Time(String),

    /// The operating system's random source failed.
    #[error("no entropy available: {0}")]
    Entropy(#[from] helpers4::random::EntropyError),

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

    /// A link (setup, administrator, invitation) is unknown, expired, used
    /// up, or not of the kind the operation takes.
    #[error("this link is not valid (any more)")]
    LinkSpent,

    /// The change would leave the server without an administrator who can
    /// sign in.
    #[error("the last administrator cannot be removed")]
    LastAdministrator,

    /// What an account or an address may create is used up: nothing was
    /// written. Carries the limit and its value.
    #[error("the limit {0} ({1}) is reached")]
    LimitReached(crate::Limit, u32),

    /// A limit was set below 1 or above its maximum.
    #[error("{0} is 1 to {max}", max = crate::Limit::max(*.0))]
    InvalidLimit(crate::Limit),

    /// A file given as a backup is not a database of a brig·id server.
    #[error("not a database of a brig·id server: {0}")]
    NotABackup(String),

    /// A backup made by a newer version of the server than this one: its
    /// schema has steps this one does not know.
    #[error("made by a newer version of the server (schema {found}; this one knows up to {known})")]
    NewerSchema { found: i64, known: i64 },

    /// A backup whose schema steps differ from this version's: made by
    /// another build.
    #[error("its schema step {0} differs from this version's: made by another build")]
    SchemaMismatch(i64),

    /// The master key opens nothing of a backup: it was made under another key.
    #[error("the master key does not open it: it was made under another master key")]
    WrongMasterKey,

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
