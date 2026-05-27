use ed25519_dalek::SigningKey;
use pkcs8::EncodePrivateKey;
use rand_core::OsRng;
use uuid::Uuid;

/// An Ed25519 signing key used to issue and verify OIDC ID Tokens.
pub struct OidcSigningKey {
    kid: String,
    signing_key: SigningKey,
}

impl OidcSigningKey {
    /// Generate a fresh Ed25519 keypair with a random `kid`.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
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

    pub(crate) fn decoding_key(&self) -> jsonwebtoken::DecodingKey {
        // ring (used internally by jsonwebtoken) expects raw 32-byte public key bytes.
        jsonwebtoken::DecodingKey::from_ed_der(self.signing_key.verifying_key().as_bytes())
    }
}
