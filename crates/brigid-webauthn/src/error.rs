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
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<WebauthnError> for Error {
    fn from(e: WebauthnError) -> Self {
        Error::Webauthn(format!("{e:?}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
