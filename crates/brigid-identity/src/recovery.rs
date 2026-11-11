//! Account recovery codes ([ADR-004] in the spec).
//!
//! A code is 25 bytes, shown as 40 base32 characters in groups of four
//! (`ABCD-EFGH-…`):
//!
//! | bytes | content |
//! | ----- | ------- |
//! | 8     | **recovery id**: random, names the account through a keyed index |
//! | 16    | **secret**: random, 128 bits; only a verifier of it is stored |
//! | 1     | check byte, so a typo is reported before any request is made |
//!
//! The code carries neither the username nor the account id: renaming the
//! account keeps the code valid, and the code reveals nothing about it.
//!
//! [ADR-004]: https://github.com/brig-id/spec/blob/main/decisions/004-account-recovery.md

use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// Length of the recovery id.
pub const RECOVERY_ID_LEN: usize = 8;
/// Length of the secret.
pub const SECRET_LEN: usize = 16;
const CODE_LEN: usize = RECOVERY_ID_LEN + SECRET_LEN + 1;

/// Why a typed code was refused before any lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    /// Not 40 base32 characters once dashes and spaces are removed.
    #[error("a recovery code is 40 characters (letters A–Z and digits 2–7)")]
    Format,
    /// The check byte does not match: most likely a typo.
    #[error("this recovery code has a typo")]
    Checksum,
}

/// A recovery code, decoded. The secret is wiped when it is dropped.
pub struct RecoveryCode {
    pub recovery_id: [u8; RECOVERY_ID_LEN],
    pub secret: Zeroizing<[u8; SECRET_LEN]>,
}

impl RecoveryCode {
    /// A new code from the operating system's random source.
    pub fn generate() -> Result<Self, helpers4::random::EntropyError> {
        let id = helpers4::random::random_bytes(RECOVERY_ID_LEN)?;
        let secret = Zeroizing::new(helpers4::random::random_bytes(SECRET_LEN)?);
        let mut code = Self {
            recovery_id: [0; RECOVERY_ID_LEN],
            secret: Zeroizing::new([0; SECRET_LEN]),
        };
        code.recovery_id.copy_from_slice(&id);
        code.secret.copy_from_slice(&secret);
        Ok(code)
    }

    fn check_byte(recovery_id: &[u8], secret: &[u8]) -> u8 {
        let mut h = Sha3_256::new();
        h.update(b"brigid-recovery-check-v1");
        h.update(recovery_id);
        h.update(secret);
        h.finalize()[0]
    }

    /// The code as the user sees it: 40 base32 characters, groups of four.
    pub fn display(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new([0u8; CODE_LEN]);
        raw[..RECOVERY_ID_LEN].copy_from_slice(&self.recovery_id);
        raw[RECOVERY_ID_LEN..CODE_LEN - 1].copy_from_slice(&*self.secret);
        raw[CODE_LEN - 1] = Self::check_byte(&self.recovery_id, &*self.secret);
        // 25 bytes are exactly 40 base32 characters: no padding.
        let b32 = Zeroizing::new(helpers4::hex::base32_encode(&*raw));
        let mut out = Zeroizing::new(String::with_capacity(49));
        for (i, c) in b32.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    /// Reads a typed code. Case, dashes and spaces don't matter, and the
    /// digits people type for look-alike letters (`0`→`O`, `1`→`I`, `8`→`B`)
    /// are read as those letters.
    pub fn parse(typed: &str) -> Result<Self, CodeError> {
        let normalized: Zeroizing<String> = Zeroizing::new(
            typed
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| match c.to_ascii_uppercase() {
                    '0' => 'O',
                    '1' => 'I',
                    '8' => 'B',
                    other => other,
                })
                .collect(),
        );
        if normalized.len() != 40 {
            return Err(CodeError::Format);
        }
        let raw = Zeroizing::new(
            helpers4::hex::base32_decode(&normalized).map_err(|_| CodeError::Format)?,
        );
        if raw.len() != CODE_LEN {
            return Err(CodeError::Format);
        }
        let (id, rest) = raw.split_at(RECOVERY_ID_LEN);
        let (secret, check) = rest.split_at(SECRET_LEN);
        if Self::check_byte(id, secret) != check[0] {
            return Err(CodeError::Checksum);
        }
        let mut code = Self {
            recovery_id: [0; RECOVERY_ID_LEN],
            secret: Zeroizing::new([0; SECRET_LEN]),
        };
        code.recovery_id.copy_from_slice(id);
        code.secret.copy_from_slice(secret);
        Ok(code)
    }

    /// What the server stores instead of the secret. Unkeyed on purpose: the
    /// secret has 128 random bits, so no key or slow hash is needed against
    /// guessing, and the verifier survives a master key rotation unchanged.
    pub fn verifier(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha3_256>::new(None, &*self.secret);
        let mut out = [0u8; 32];
        hk.expand(b"brigid-recovery-verifier-v1", &mut out)
            .expect("32 bytes is a valid HKDF-SHA3-256 output length");
        out
    }

    /// Does this code's secret match a stored verifier? Constant time.
    pub fn matches(&self, verifier: &[u8]) -> bool {
        helpers4::bytes::constant_time_eq(&self.verifier(), verifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_its_display_form() {
        let code = RecoveryCode::generate().unwrap();
        let shown = code.display();
        assert_eq!(shown.len(), 49, "40 characters and 9 dashes: {}", *shown);
        assert!(shown.split('-').all(|g| g.len() == 4));
        let back = RecoveryCode::parse(&shown).unwrap();
        assert_eq!(back.recovery_id, code.recovery_id);
        assert_eq!(*back.secret, *code.secret);
    }

    #[test]
    fn reads_what_people_type() {
        let code = RecoveryCode::generate().unwrap();
        let shown = code.display();
        let sloppy = shown.to_lowercase().replace('-', " ");
        assert_eq!(
            RecoveryCode::parse(&sloppy).unwrap().recovery_id,
            code.recovery_id
        );
        let digits = shown.replace('O', "0").replace('I', "1").replace('B', "8");
        assert_eq!(
            RecoveryCode::parse(&digits).unwrap().recovery_id,
            code.recovery_id
        );
    }

    #[test]
    fn reports_typos_and_bad_formats() {
        let shown = RecoveryCode::generate().unwrap().display();
        // Change one character to another valid base32 letter.
        let mut typo: Vec<char> = shown.chars().collect();
        typo[5] = if typo[5] == 'A' { 'C' } else { 'A' };
        let typo: String = typo.into_iter().collect();
        assert!(matches!(
            RecoveryCode::parse(&typo),
            Err(CodeError::Checksum) | Err(CodeError::Format)
        ));
        assert_eq!(RecoveryCode::parse("ABCD").err(), Some(CodeError::Format));
        assert_eq!(
            RecoveryCode::parse(&"9".repeat(40)).err(),
            Some(CodeError::Format)
        );
    }

    #[test]
    fn the_verifier_matches_only_its_secret() {
        let a = RecoveryCode::generate().unwrap();
        let b = RecoveryCode::generate().unwrap();
        assert!(a.matches(&a.verifier()));
        assert!(!a.matches(&b.verifier()));
        assert!(!a.matches(&[]));
        assert_ne!(a.recovery_id, b.recovery_id);
    }
}
