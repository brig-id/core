use sha3::{Digest, Sha3_256};

/// A private alias: an opaque handle that contains at least one `_` and no `@`.
///
/// This type is defined in phase 3 but not yet surfaced in the public API (v0.0.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateAlias(pub(crate) String);

impl PrivateAlias {
    /// Returns `true` iff `s` is a valid private alias: non-empty, contains `_`, no `@`.
    pub fn is_valid(s: &str) -> bool {
        !s.is_empty() && s.contains('_') && !s.contains('@')
    }

    /// Constructs a `PrivateAlias` if `s` satisfies `is_valid`, otherwise `None`.
    pub fn new(s: &str) -> Option<Self> {
        if Self::is_valid(s) {
            Some(Self(s.to_string()))
        } else {
            None
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts the alias to a `did:peer:2.z<base58btc(0xed01 || 32B)>`
    /// identifier compatible with [`brigid_did::resolve_did_peer`].
    ///
    /// The alias is stripped of underscores then hashed with SHA3-256; the
    /// resulting 32 bytes occupy the position normally reserved for an
    /// Ed25519 public key in a `did:peer:2` numalgo-2 identifier, so the
    /// multicodec prefix (`0xed 0x01`) and base58btc encoding match the
    /// spec syntactically. The 32 bytes carry **no** asymmetric semantics:
    /// resolving the DID recovers the SHA3-256 commitment to the alias,
    /// not a signing key. Phase 4 will replace this placeholder with a
    /// proper Ed25519 verification-key binding.
    ///
    /// INVARIANT: VSID computation MUST NOT use this method — the result
    /// is NOT a root DID and MUST NOT be passed to `compute_vsid`.
    pub fn to_did_peer(&self) -> String {
        let stripped: String = self.0.chars().filter(|c| *c != '_').collect();
        let hash = Sha3_256::digest(stripped.as_bytes());
        // Multicodec prefix for `ed25519-pub` (varint 0xed 0x01), per the
        // `did:peer:2.z` format. Kept in sync with
        // `brigid_did::peer::MULTICODEC_ED25519`.
        let mut payload = Vec::with_capacity(2 + 32);
        payload.extend_from_slice(&[0xed, 0x01]);
        payload.extend_from_slice(hash.as_slice());
        let encoded = bs58::encode(&payload).into_string();
        format!("did:peer:2.z{encoded}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_alias() {
        assert!(PrivateAlias::is_valid("x8Fj_29K"));
    }

    #[test]
    fn no_underscore_is_invalid() {
        assert!(!PrivateAlias::is_valid("noUnderscore"));
    }

    #[test]
    fn empty_is_invalid() {
        assert!(!PrivateAlias::is_valid(""));
    }

    #[test]
    fn at_sign_makes_invalid() {
        assert!(!PrivateAlias::is_valid("alias@domain_test"));
    }

    #[test]
    fn new_returns_some_for_valid() {
        let a = PrivateAlias::new("valid_alias").unwrap();
        assert_eq!(a.as_str(), "valid_alias");
    }

    #[test]
    fn new_returns_none_for_invalid() {
        assert!(PrivateAlias::new("nounderscore").is_none());
    }

    #[test]
    fn to_did_peer_has_expected_prefix() {
        let a = PrivateAlias::new("x8Fj_29K").unwrap();
        let did = a.to_did_peer();
        assert!(did.starts_with("did:peer:2.z"), "got: {did}");
    }

    #[test]
    fn to_did_peer_strips_underscores_deterministically() {
        let a1 = PrivateAlias::new("he_llo").unwrap();
        let a2 = PrivateAlias::new("h_ello").unwrap();
        // Both strip to "hello", so same DID
        assert_eq!(a1.to_did_peer(), a2.to_did_peer());
    }
}
