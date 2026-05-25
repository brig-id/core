//! Error types for brigid-did.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("invalid public key: {0}")]
    InvalidKey(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
