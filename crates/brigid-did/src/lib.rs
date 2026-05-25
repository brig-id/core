//! brigid-did: DID:web and DID:peer resolution for brig·id.
//!
//! - `build_did_web` / `did_web_to_url` / `resolve_did_web` — DID:web
//! - `generate_did_peer` / `resolve_did_peer` — DID:peer (numalgo 2, Ed25519)
//! - `did_document_handler` — construct a DID Core document for `.well-known/did.json`

pub mod error;
pub mod handler;
pub mod model;
pub mod peer;
pub mod web;

pub use error::{Error, Result};
pub use handler::did_document_handler;
pub use model::{DIDDocument, Did, VerificationMethod};
pub use peer::{generate_did_peer, resolve_did_peer};
pub use web::{build_did_web, did_web_to_url, resolve_did_web};
