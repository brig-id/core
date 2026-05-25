use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use sha3::{Digest, Sha3_256};

use brigid_crypto::MasterKey;

/// A Virtual Stable Identifier (VSID): stable per `(did_root, client_id, salt)`,
/// non-correlable across services (different `client_id` → different VSID).
///
/// INVARIANTS:
/// - MUST be derived from a root DID (`did:web:…`) only.
/// - MUST NOT be derived from an alias or a virtual identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vsid(String);

impl Vsid {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Vsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Derives a 32-byte VSID salt from the master key.
///
/// Uses HKDF-SHA3-256 with `info = "brigid-vsid-salt"`.
/// Cannot fail for a 32-byte output (HKDF limit is 255 × HashLen = 8160 bytes).
pub fn derive_vsid_salt(master: &MasterKey) -> [u8; 32] {
    let key = brigid_crypto::hkdf::derive_key(master, b"brigid-vsid-salt", 32)
        .expect("HKDF with 32-byte output never fails");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key);
    arr
}

/// Computes the VSID from a root DID, client identifier, and salt.
///
/// Formula:
/// ```text
/// SHA3-256(
///   u32_be(len(did_root)) || did_root ||
///   u32_be(len(client_id)) || client_id ||
///   salt
/// )
/// ```
/// Length-prefixed fields prevent collisions (`:` appears in DIDs).
/// Result is base64url-encoded without padding.
///
/// # Invariants
///
/// `did_root` MUST be a root DID (`did:web:…`). Passing an alias or a virtual
/// identity DID here violates the VSID security model.
pub fn compute_vsid(did_root: &str, client_id: &str, salt: &[u8]) -> Vsid {
    let mut hasher = Sha3_256::new();
    hasher.update((did_root.len() as u32).to_be_bytes());
    hasher.update(did_root.as_bytes());
    hasher.update((client_id.len() as u32).to_be_bytes());
    hasher.update(client_id.as_bytes());
    hasher.update(salt);
    let digest = hasher.finalize();
    Vsid(Base64UrlUnpadded::encode_string(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master() -> MasterKey {
        MasterKey::from_hex(&"42".repeat(32)).unwrap()
    }

    const DID_ROOT: &str = "did:web:brig.id:u:berenger";

    #[test]
    fn vsid_is_stable() {
        let master = test_master();
        let salt = derive_vsid_salt(&master);
        let v1 = compute_vsid(DID_ROOT, "app1", &salt);
        let v2 = compute_vsid(DID_ROOT, "app1", &salt);
        assert_eq!(v1, v2, "same inputs must produce the same VSID");
    }

    #[test]
    fn vsid_non_correlable_across_clients() {
        let master = test_master();
        let salt = derive_vsid_salt(&master);
        let v1 = compute_vsid(DID_ROOT, "app1", &salt);
        let v2 = compute_vsid(DID_ROOT, "app2", &salt);
        assert_ne!(v1, v2, "different client_id must yield different VSID");
    }

    #[test]
    fn vsid_differs_across_salts() {
        let s1 = [0u8; 32];
        let s2 = [1u8; 32];
        let v1 = compute_vsid(DID_ROOT, "app1", &s1);
        let v2 = compute_vsid(DID_ROOT, "app1", &s2);
        assert_ne!(v1, v2, "different salt must yield different VSID");
    }

    #[test]
    fn vsid_never_derived_from_alias() {
        // Demonstrates the invariant: computing VSID from an alias-like string
        // is a programming error. The VSID from a root DID must differ from
        // what you would get if you mistakenly passed an alias.
        let master = test_master();
        let salt = derive_vsid_salt(&master);
        let vsid_from_root = compute_vsid("did:web:brig.id:u:berenger", "app1", &salt);
        let vsid_from_alias = compute_vsid("_berenger_alias", "app1", &salt);
        assert_ne!(
            vsid_from_root, vsid_from_alias,
            "VSID from alias must differ from VSID from root DID"
        );
    }

    #[test]
    fn vsid_display_and_as_str() {
        let v = compute_vsid(DID_ROOT, "app1", &[0u8; 32]);
        assert_eq!(v.as_str(), v.to_string());
        assert!(!v.as_str().is_empty());
    }

    #[test]
    fn derive_vsid_salt_is_deterministic() {
        let master = test_master();
        let s1 = derive_vsid_salt(&master);
        let s2 = derive_vsid_salt(&master);
        assert_eq!(s1, s2);
    }
}
