use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use sha3::Sha3_256;

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
/// HKDF-SHA3-256(
///   IKM  = salt,
///   salt = b"" (none, already a derived key),
///   info = "brigid-vsid-v1" ||
///          u32_be(len(did_root)) || did_root ||
///          u32_be(len(client_id)) || client_id
/// )[..32]
/// ```
/// Length-prefixed fields prevent collisions (`:` appears in DIDs).
/// Result is base64url-encoded without padding.
///
/// # Invariants
///
/// `did_root` MUST be a root DID (`did:web:…`). Passing an alias or a virtual
/// identity DID here violates the VSID security model.
pub fn compute_vsid(did_root: &str, client_id: &str, salt: &[u8]) -> crate::Result<Vsid> {
    // The prefix check alone would accept malformed values like `did:web:`
    // (empty body) or values containing path separators (`/`) that are not
    // valid did:web syntax. Validate the body strictly so we never derive a
    // VSID from clearly malformed input.
    //
    // Note: brig\u00b7id uses multi-component did:web identifiers of the form
    // `did:web:<host>:u:<username>` for root public identities, so embedded
    // `:` characters are permitted. Leading/trailing `:` and `/` are not.
    let body = did_root.strip_prefix("did:web:").ok_or_else(|| {
        crate::Error::InvalidIdentifier("did_root must be a did:web: DID".to_string())
    })?;
    if body.is_empty()
        || body.contains('/')
        || body.starts_with(':')
        || body.ends_with(':')
        || body.contains("::")
    {
        return Err(crate::Error::InvalidIdentifier(
            "did_root has malformed did:web syntax".to_string(),
        ));
    }
    let dr_len = (did_root.len() as u32).to_be_bytes();
    let ci_len = (client_id.len() as u32).to_be_bytes();

    let mut info = Vec::with_capacity(14 + 4 + did_root.len() + 4 + client_id.len());
    info.extend_from_slice(b"brigid-vsid-v1");
    info.extend_from_slice(&dr_len);
    info.extend_from_slice(did_root.as_bytes());
    info.extend_from_slice(&ci_len);
    info.extend_from_slice(client_id.as_bytes());

    // `salt` is already a 32-byte HKDF-derived value — use it as IKM with no
    // additional salt (HKDF without a salt uses a zero-filled hash-length pad).
    let hk = Hkdf::<Sha3_256>::new(None, salt);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes always fits within HKDF output limit");
    Ok(Vsid(Base64UrlUnpadded::encode_string(&okm)))
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
        let v1 = compute_vsid(DID_ROOT, "app1", &salt).unwrap();
        let v2 = compute_vsid(DID_ROOT, "app1", &salt).unwrap();
        assert_eq!(v1, v2, "same inputs must produce the same VSID");
    }

    #[test]
    fn vsid_non_correlable_across_clients() {
        let master = test_master();
        let salt = derive_vsid_salt(&master);
        let v1 = compute_vsid(DID_ROOT, "app1", &salt).unwrap();
        let v2 = compute_vsid(DID_ROOT, "app2", &salt).unwrap();
        assert_ne!(v1, v2, "different client_id must yield different VSID");
    }

    #[test]
    fn vsid_differs_across_salts() {
        let s1 = [0u8; 32];
        let s2 = [1u8; 32];
        let v1 = compute_vsid(DID_ROOT, "app1", &s1).unwrap();
        let v2 = compute_vsid(DID_ROOT, "app1", &s2).unwrap();
        assert_ne!(v1, v2, "different salt must yield different VSID");
    }

    #[test]
    fn vsid_never_derived_from_alias() {
        // Invariant: compute_vsid rejects non-root-DID inputs at the call site,
        // preventing alias or virtual identity DIDs from leaking into VSIDs.
        let master = test_master();
        let salt = derive_vsid_salt(&master);
        assert!(
            compute_vsid("did:web:brig.id:u:berenger", "app1", &salt).is_ok(),
            "root did:web: DID must be accepted"
        );
        assert!(
            compute_vsid("_berenger_alias", "app1", &salt).is_err(),
            "non-DID alias must be rejected"
        );
    }

    #[test]
    fn vsid_display_and_as_str() {
        let v = compute_vsid(DID_ROOT, "app1", &[0u8; 32]).unwrap();
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
