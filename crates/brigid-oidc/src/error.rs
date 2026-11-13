use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("invalid token TTL (overflow or out of i64 range)")]
    InvalidTtl,
}

pub type Result<T> = std::result::Result<T, Error>;
