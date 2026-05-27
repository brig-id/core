pub mod error;
pub mod service;

pub use error::{Error, Result};
pub use service::{
    AuthResult, WebauthnService, load_passkeys, passkey_to_credential, store_passkey,
    update_passkey,
};
