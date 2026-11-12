use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use sha3::Sha3_256;

use brigid_crypto::MasterKey;
use uuid::Uuid;

/// A Virtual Stable Identifier (VSID): the `sub` a relying party sees for an
/// identity ([ADR-007] in the spec). Stable per `(identity, client_id)`, and
/// different for every `client_id`, so two relying parties can't link their
/// users. Computed from the identity's UUID: renaming the account, moving the
/// server to another domain or rotating the master key changes no VSID.
///
/// [ADR-007]: https://github.com/brig-id/spec/blob/main/decisions/007-identifiers.md
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

/// Derives a 32-byte VSID salt from the master key
/// (HKDF-SHA3-256, `info = "brigid-vsid-salt"`).
///
/// This is how the VSID secret was obtained before it was stored. It is only
/// passed to `EncryptedStore::vsid_secret`, which keeps it for a database
/// whose accounts already have VSIDs computed with it; a new database gets a
/// random secret instead.
pub fn derive_vsid_salt(master: &MasterKey) -> [u8; 32] {
    let key = brigid_crypto::hkdf::derive_key(master, b"brigid-vsid-salt", 32)
        .expect("HKDF with 32-byte output never fails");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key);
    arr
}

/// `HKDF-SHA3-256(ikm = secret, info = label || id (16 bytes) ||
/// u32_be(len(client_id)) || client_id)[..32]`, unpadded base64url. The id has
/// a fixed length and `client_id` is length-prefixed, so the input is
/// unambiguous; `label` versions the construction.
fn derive_subject(label: &[u8], id: Uuid, client_id: &str, secret: &[u8]) -> Vsid {
    let mut info = Vec::with_capacity(label.len() + 16 + 4 + client_id.len());
    info.extend_from_slice(label);
    info.extend_from_slice(id.as_bytes());
    info.extend_from_slice(&(client_id.len() as u32).to_be_bytes());
    info.extend_from_slice(client_id.as_bytes());
    // `secret` is 32 random (or HKDF-derived) bytes: used as IKM with no salt.
    let hk = Hkdf::<Sha3_256>::new(None, secret);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes always fits within HKDF output limit");
    Vsid(Base64UrlUnpadded::encode_string(&okm))
}

/// The VSID of identity `identity_id` at relying party `client_id`
/// (`info` label `brigid-vsid-v2`). `secret` is the deployment's VSID secret
/// (ADR-006).
pub fn identity_vsid(identity_id: Uuid, client_id: &str, secret: &[u8]) -> Vsid {
    derive_subject(b"brigid-vsid-v2", identity_id, client_id, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7u8; 32];

    fn id(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    #[test]
    fn deterministic() {
        assert_eq!(
            identity_vsid(id(1), "app1", &SECRET),
            identity_vsid(id(1), "app1", &SECRET)
        );
    }

    #[test]
    fn different_client_different_vsid() {
        assert_ne!(
            identity_vsid(id(1), "app1", &SECRET),
            identity_vsid(id(1), "app2", &SECRET)
        );
    }

    #[test]
    fn different_identity_different_vsid() {
        assert_ne!(
            identity_vsid(id(1), "app1", &SECRET),
            identity_vsid(id(2), "app1", &SECRET)
        );
    }

    #[test]
    fn depends_on_the_secret() {
        assert_ne!(
            identity_vsid(id(1), "app1", &SECRET),
            identity_vsid(id(1), "app1", &[8u8; 32])
        );
    }

    #[test]
    fn client_id_is_length_prefixed() {
        // Without the prefix, ("a", id) and ("", id ‖ "a") could meet; with a
        // fixed-length id they can't, and the prefix covers the rest.
        assert_ne!(
            identity_vsid(id(1), "ab", &SECRET),
            identity_vsid(id(1), "a", &SECRET)
        );
    }

    /// Pins the formula: an accidental change would move every VSID.
    #[test]
    fn known_answer() {
        let v = identity_vsid(id(1), "https://rp.example", &SECRET);
        assert_eq!(v.as_str().len(), 43);
        assert_eq!(v.as_str(), KNOWN_VSID, "VSID v2 formula changed");
    }

    // Recomputed independently (Python hmac + sha3_256, HKDF per RFC 5869).
    const KNOWN_VSID: &str = "II-Ekb91b_YeEn5OsWse5EwHrg7DMPI6daf30K1JQoE";

    #[test]
    fn derive_vsid_salt_is_stable() {
        let m = MasterKey::from_hex(&"42".repeat(32)).unwrap();
        assert_eq!(derive_vsid_salt(&m), derive_vsid_salt(&m));
    }
}
