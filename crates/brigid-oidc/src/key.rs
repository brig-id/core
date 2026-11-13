use ed25519_dalek::SigningKey;
use pkcs8::EncodePrivateKey;
use rand_core::UnwrapErr;
use uuid::Uuid;

/// An Ed25519 signing key used to issue and verify OIDC ID Tokens.
pub struct OidcSigningKey {
    kid: String,
    signing_key: SigningKey,
}

impl OidcSigningKey {
    /// Generate a fresh Ed25519 keypair with a random `kid`.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut UnwrapErr(getrandom::SysRng));
        Self {
            kid: Uuid::new_v4().to_string(),
            signing_key,
        }
    }

    /// Reconstruct a key from raw 32-byte seed bytes.
    ///
    /// The signing seed is treated as opaque caller-supplied material: this
    /// method performs **no** KDF, HKDF, or master-key derivation. Callers are
    /// responsible for decrypting the seed (typically stored encrypted under
    /// `MASTER_KEY` via `brigid-store`) before invoking this constructor.
    pub fn from_raw_bytes(kid: String, bytes: &[u8; 32]) -> Self {
        Self {
            kid,
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// Reconstruct a key from its 32-byte seed, with its RFC 7638 JWK
    /// thumbprint as `kid`: stable for the key, distinct between keys, so
    /// several keys can be published side by side during a rotation.
    pub fn from_seed(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let kid = jwk_thumbprint(&signing_key.verifying_key());
        Self { kid, signing_key }
    }

    /// The key ID, used in JWT `kid` header and JWKS.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The Ed25519 verifying key (for JWKS construction).
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Exports the raw 32-byte seed for encrypted storage by the caller.
    pub fn to_raw_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub(crate) fn encoding_key(&self) -> jsonwebtoken::EncodingKey {
        let der = self
            .signing_key
            .to_pkcs8_der()
            .expect("Ed25519 PKCS8 DER encoding never fails");
        jsonwebtoken::EncodingKey::from_ed_der(der.as_bytes())
    }

    #[cfg(test)]
    pub(crate) fn decoding_key(&self) -> jsonwebtoken::DecodingKey {
        // ring (used internally by jsonwebtoken) expects raw 32-byte public key bytes.
        jsonwebtoken::DecodingKey::from_ed_der(self.signing_key.verifying_key().as_bytes())
    }
}

/// RFC 7638 thumbprint of an Ed25519 public key: SHA-256 over the canonical
/// JWK `{"crv":"Ed25519","kty":"OKP","x":"<base64url>"}`, base64url-encoded.
pub fn jwk_thumbprint(vk: &ed25519_dalek::VerifyingKey) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};
    let canonical = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        Base64UrlUnpadded::encode_string(vk.as_bytes())
    );
    Base64UrlUnpadded::encode_string(&Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 appendix A.3: the thumbprint of its example Ed25519 key.
    #[test]
    fn thumbprint_matches_rfc_8037() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let x =
            Base64UrlUnpadded::decode_vec("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&x.try_into().unwrap()).unwrap();
        assert_eq!(
            jwk_thumbprint(&vk),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn from_seed_uses_the_thumbprint_as_kid() {
        let a = OidcSigningKey::from_seed(&[1u8; 32]);
        let b = OidcSigningKey::from_seed(&[2u8; 32]);
        assert_eq!(a.kid(), jwk_thumbprint(&a.verifying_key()));
        assert_eq!(a.kid(), OidcSigningKey::from_seed(&[1u8; 32]).kid());
        assert_ne!(a.kid(), b.kid());
    }
}
