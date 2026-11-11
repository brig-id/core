//! The server's DID document (`did:web:<server>`, served at
//! `/.well-known/did.json`).
//!
//! It publishes the key that signs the server's tokens, alongside the JWKS.
//! Accounts and identities have no DID (ADR-007): only the server does.

use crate::{
    error::{Error, Result},
    model::{DIDDocument, VerificationMethod},
};

const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];

/// Build the DID Core document of the server `server` (`did:web:<server>`),
/// whose verification method is the Ed25519 public key `public_key_bytes`
/// (32 bytes), encoded as `publicKeyMultibase` (base58btc, `ed25519-pub`
/// multicodec prefix) as `Ed25519VerificationKey2020` requires.
pub fn did_root_document_handler(server: &str, public_key_bytes: &[u8]) -> Result<DIDDocument> {
    if public_key_bytes.len() != 32 {
        return Err(Error::InvalidKey(format!(
            "expected 32 bytes, got {}",
            public_key_bytes.len()
        )));
    }

    let did = format!("did:web:{server}");
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
        id: did.clone(),
        verification_method: vec![VerificationMethod {
            id: method_id.clone(),
            key_type: "Ed25519VerificationKey2020".to_string(),
            controller: did,
            public_key_multibase,
        }],
        authentication: vec![method_id],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn server_document_is_well_formed() {
        let doc = did_root_document_handler("example.com", &sample_key()).unwrap();
        assert_eq!(doc.id, "did:web:example.com");
        assert_eq!(
            doc.context,
            [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ]
        );
        assert_eq!(doc.verification_method.len(), 1);
        let vm = &doc.verification_method[0];
        assert_eq!(vm.key_type, "Ed25519VerificationKey2020");
        assert_eq!(vm.controller, doc.id);
        assert_eq!(doc.authentication, std::slice::from_ref(&vm.id));
    }

    #[test]
    fn the_key_is_multibase_with_the_ed25519_prefix() {
        let doc = did_root_document_handler("brig.id", &sample_key()).unwrap();
        let mb = &doc.verification_method[0].public_key_multibase;
        let decoded = bs58::decode(mb.strip_prefix('z').unwrap()).into_vec().unwrap();
        assert_eq!(&decoded[..2], &MULTICODEC_ED25519);
        assert_eq!(&decoded[2..], &sample_key());
    }

    #[test]
    fn document_serialises_to_did_core_json() {
        let doc = did_root_document_handler("example.com", &sample_key()).unwrap();
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"@context\""));
        assert!(json.contains("\"verificationMethod\""));
    }

    #[test]
    fn rejects_a_key_of_the_wrong_length() {
        assert!(did_root_document_handler("example.com", &[0u8; 31]).is_err());
    }
}
