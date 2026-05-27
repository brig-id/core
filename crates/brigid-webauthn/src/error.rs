use thiserror::Error;
use webauthn_rs::prelude::WebauthnError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("WebAuthn error: {0}")]
    Webauthn(String),
    #[error("store error: {0}")]
    Store(#[from] brigid_store::Error),
    #[error("no credentials registered for this user")]
    NoCredentials,
    /// `update_passkey` was called for a credential ID that does not exist in
    /// the store. This indicates a desynchronisation between the authenticated
    /// passkey and the persisted state — the signature counter cannot be
    /// advanced safely, so we refuse rather than silently dropping the update.
    #[error("authenticated credential not found in store; counter not updated")]
    CredentialNotMatched,
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<WebauthnError> for Error {
    fn from(e: WebauthnError) -> Self {
        Error::Webauthn(format!("{e:?}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
