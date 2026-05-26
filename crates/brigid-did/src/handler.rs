//! Handler that builds a DID Core document for a DID:web user.
//!
//! The returned [`DIDDocument`] can be serialised to JSON and served at the
//! path derived from `did_web_to_url()` (e.g. `/u/alice/did.json`).

use crate::{
    error::{Error, Result},
    model::{DIDDocument, VerificationMethod},
    web::build_did_web,
};

const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];

/// Build a DID Core document for `username` on `server`, using the provided
/// Ed25519 public key bytes (32 bytes).
///
/// The `publicKeyMultibase` field uses base58btc encoding with the
/// `ed25519-pub` multicodec prefix, as required by `Ed25519VerificationKey2020`.
pub fn did_document_handler(
    username: &str,
    server: &str,
    public_key_bytes: &[u8],
) -> Result<DIDDocument> {
    if public_key_bytes.len() != 32 {
        return Err(Error::InvalidKey(format!(
            "expected 32 bytes, got {}",
            public_key_bytes.len()
        )));
    }

    let did = build_did_web(username, server);
    let method_id = format!("{did}#key-1");

    let mut payload = Vec::with_capacity(2 + 32);
    payload.extend_from_slice(&MULTICODEC_ED25519);
    payload.extend_from_slice(public_key_bytes);
    let public_key_multibase = format!("z{}", bs58::encode(&payload).into_string());

    Ok(DIDDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
        ],
        id: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: method_id.clone(),
            key_type: "Ed25519VerificationKey2020".to_string(),
            controller: did.to_string(),
            public_key_multibase,
        }],
        authentication: vec![method_id],
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn handler_returns_valid_document() {
        let doc = did_document_handler("alice", "example.com", &sample_key()).unwrap();
        assert_eq!(doc.id, "did:web:example.com:u:alice");
        assert_eq!(
            doc.context,
            [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ]
        );
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(
            doc.verification_method[0].key_type,
            "Ed25519VerificationKey2020"
        );
        assert_eq!(doc.verification_method[0].controller, doc.id);
        assert_eq!(doc.authentication[0], doc.verification_method[0].id);
    }

    #[test]
    fn public_key_multibase_starts_with_z() {
        let doc = did_document_handler("bob", "brig.id", &sample_key()).unwrap();
        assert!(
            doc.verification_method[0]
                .public_key_multibase
                .starts_with('z'),
            "publicKeyMultibase must use base58btc multibase prefix"
        );
    }

    #[test]
    fn document_serialises_to_valid_json() {
        let doc = did_document_handler("alice", "example.com", &sample_key()).unwrap();
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"@context\""));
        assert!(json.contains("\"verificationMethod\""));
        assert!(json.contains("\"authentication\""));
        assert!(json.contains("did:web:example.com:u:alice"));
    }

    #[test]
    fn wrong_key_length_is_rejected() {
        assert!(did_document_handler("alice", "example.com", &[0u8; 31]).is_err());
        assert!(did_document_handler("alice", "example.com", &[0u8; 33]).is_err());
    }
}
