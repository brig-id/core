use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("JWT error: {0}")]
    Jwt(String),
    #[error("token expired")]
    Expired,
    #[error("invalid audience")]
    InvalidAudience,
    #[error("JTI replay detected")]
    JtiReplay,
    #[error("invalid token TTL (overflow or out of i64 range)")]
    InvalidTtl,
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => Error::Expired,
            ErrorKind::InvalidAudience => Error::InvalidAudience,
            _ => Error::Jwt(format!("{e}")),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
