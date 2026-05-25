use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, Error>;
