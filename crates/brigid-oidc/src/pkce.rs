//! Proof Key for Code Exchange (RFC 7636), `S256` only.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

/// Whether `challenge` has the shape of an `S256` code challenge: the
/// unpadded base64url of a SHA-256 digest, 43 characters.
pub fn is_valid_challenge(challenge: &str) -> bool {
    challenge.len() == 43 && challenge.bytes().all(is_base64url)
}

/// Whether `verifier` presented at the token endpoint is the one whose
/// `S256` challenge came with the authorization request. A verifier that
/// does not have the form RFC 7636 §4.1 requires (43 to 128 unreserved
/// characters) is refused before hashing.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    if !(43..=128).contains(&verifier.len()) || !verifier.bytes().all(is_unreserved) {
        return false;
    }
    let computed = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
    // Both sides are public once the code is redeemed; the comparison is
    // still done in constant time so that nothing depends on that reasoning.
    computed.len() == challenge.len()
        && computed
            .bytes()
            .zip(challenge.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn is_base64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 appendix B.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn the_rfc_7636_example_verifies() {
        assert!(is_valid_challenge(CHALLENGE));
        assert!(verify_s256(VERIFIER, CHALLENGE));
    }

    #[test]
    fn another_verifier_or_a_malformed_one_is_refused() {
        let other = "a".repeat(43);
        assert!(!verify_s256(&other, CHALLENGE));
        assert!(!verify_s256("short", CHALLENGE));
        assert!(!verify_s256(&"a".repeat(129), CHALLENGE));
        assert!(!verify_s256(&format!("{}!", &VERIFIER[..42]), CHALLENGE));
        // The challenge itself is not a verifier for itself.
        assert!(!verify_s256(CHALLENGE, CHALLENGE));
    }

    #[test]
    fn a_challenge_has_43_base64url_characters() {
        assert!(!is_valid_challenge(""));
        assert!(!is_valid_challenge(&CHALLENGE[..42]));
        assert!(!is_valid_challenge(&format!("{}=", &CHALLENGE[..42])));
        assert!(!is_valid_challenge(&format!("{CHALLENGE}A")));
    }
}
