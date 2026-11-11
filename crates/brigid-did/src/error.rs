//! Error types for brigid-did.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid public key: {0}")]
    InvalidKey(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
