//! brigid-did: the server's own DID document.
//!
//! Only the server has a DID (`did:web:<server>`, `/.well-known/did.json`), which
//! publishes the key that signs its tokens. Accounts and identities are
//! identified by UUIDs (ADR-007 in the spec).

pub mod error;
pub mod handler;
pub mod model;

pub use error::{Error, Result};
pub use handler::did_root_document_handler;
pub use model::{DIDDocument, VerificationMethod};
