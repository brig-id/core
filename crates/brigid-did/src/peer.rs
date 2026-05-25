//! DID:peer generation and resolution (numalgo 2, single Ed25519 key).
//!
//! Format: `did:peer:2.z<base58btc(0xed 0x01 || key_bytes)>`
//!
//! - `0xed 0x01` is the varint-encoded multicodec prefix for `ed25519-pub`.
//! - Base58btc uses the Bitcoin/IPFS alphabet (as in multibase prefix `z`).

use crate::error::{Error, Result};
use crate::model::Did;

const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];

/// Generate a `did:peer:2` DID from a 32-byte Ed25519 public key.
pub fn generate_did_peer(public_key: &[u8]) -> Result<Did> {
    if public_key.len() != 32 {
        return Err(Error::InvalidKey(format!(
            "expected 32 bytes, got {}",
            public_key.len()
        )));
    }
    let mut payload = Vec::with_capacity(2 + 32);
    payload.extend_from_slice(&MULTICODEC_ED25519);
    payload.extend_from_slice(public_key);
    let encoded = bs58::encode(&payload).into_string();
    Ok(Did::new(format!("did:peer:2.z{encoded}")))
}

/// Resolve a `did:peer:2` DID back to its 32-byte Ed25519 public key.
pub fn resolve_did_peer(did: &Did) -> Result<[u8; 32]> {
    let s = did.as_str();
    let suffix = s
        .strip_prefix("did:peer:2.z")
        .ok_or_else(|| Error::InvalidDid(format!("not a did:peer:2.z DID: {s}")))?;

    let decoded = bs58::decode(suffix)
        .into_vec()
        .map_err(|e| Error::InvalidKey(e.to_string()))?;

    if decoded.len() < 2
        || decoded[0] != MULTICODEC_ED25519[0]
        || decoded[1] != MULTICODEC_ED25519[1]
    {
        return Err(Error::InvalidKey(
            "invalid ed25519-pub multicodec prefix".to_string(),
        ));
    }

    let key_bytes = &decoded[2..];
    if key_bytes.len() != 32 {
        return Err(Error::InvalidKey(format!(
            "expected 32 key bytes, got {}",
            key_bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);
    Ok(key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        k
    }

    #[test]
    fn generate_resolve_round_trip() {
        let key = sample_key();
        let did = generate_did_peer(&key).unwrap();
        let recovered = resolve_did_peer(&did).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn did_starts_with_prefix() {
        let did = generate_did_peer(&sample_key()).unwrap();
        assert!(did.as_str().starts_with("did:peer:2.z"));
    }

    #[test]
    fn wrong_key_length_is_rejected() {
        assert!(generate_did_peer(&[0u8; 31]).is_err());
        assert!(generate_did_peer(&[0u8; 33]).is_err());
        assert!(generate_did_peer(&[]).is_err());
    }

    #[test]
    fn invalid_did_prefix_is_rejected() {
        let did = Did::new("did:web:example.com");
        assert!(resolve_did_peer(&did).is_err());
    }

    #[test]
    fn invalid_multicodec_prefix_is_rejected() {
        // Encode 34 bytes with wrong prefix (not [0xed, 0x01]) so decoding
        // succeeds but the multicodec check fails.
        let mut payload = vec![0x12u8, 0x34]; // wrong prefix
        payload.extend_from_slice(&[0u8; 32]);
        let encoded = bs58::encode(&payload).into_string();
        let did = Did::new(format!("did:peer:2.z{encoded}"));
        let err = resolve_did_peer(&did).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid ed25519-pub multicodec prefix"),
            "unexpected error: {err}"
        );
    }

    /// Correct multicodec prefix but only 31 key bytes — covers the
    /// `key_bytes.len() != 32` branch (lines 50-53).
    #[test]
    fn wrong_decoded_key_length_is_rejected() {
        let mut payload = vec![0xed, 0x01];
        payload.extend_from_slice(&[0u8; 31]); // 31 bytes, not 32
        let encoded = bs58::encode(&payload).into_string();
        let did = Did::new(format!("did:peer:2.z{encoded}"));
        let err = resolve_did_peer(&did).unwrap_err();
        assert!(
            err.to_string().contains("expected 32 key bytes"),
            "unexpected error: {err}"
        );
    }

    /// '0', 'O', 'I', 'l' are not valid base58btc characters — exercises the
    /// `map_err(|e| Error::InvalidKey(e.to_string()))` closure (line 37).
    #[test]
    fn invalid_base58_suffix_is_rejected() {
        let did = Did::new("did:peer:2.z0OIl");
        let err = resolve_did_peer(&did).unwrap_err();
        // The error should mention the invalid character, not a DID prefix problem.
        assert!(
            !err.to_string().contains("not a did:peer:2.z"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn different_keys_produce_different_dids() {
        let k1 = [0u8; 32];
        let k2 = [1u8; 32];
        let d1 = generate_did_peer(&k1).unwrap();
        let d2 = generate_did_peer(&k2).unwrap();
        assert_ne!(d1, d2);
    }
}
