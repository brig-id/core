use brigid_identity::Vsid;
use jsonwebtoken::{Algorithm, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::jti::JtiStore;
use crate::key::OidcSigningKey;

/// Parameters for issuing an OIDC ID Token.
pub struct IssuanceParams<'a> {
    /// Virtual Stable Identifier — always used as the `sub` claim.
    pub vsid: &'a Vsid,
    /// Issuer URL (e.g. `"https://example.com"`).
    pub issuer: &'a str,
    /// Client identifier — used as the `aud` claim.
    pub client_id: &'a str,
    /// Brig·id server domain (e.g. `"example.com"`).
    pub server: &'a str,
    /// Token lifetime in seconds (added to `now_unix`).
    pub ttl_secs: u64,
}

/// OIDC ID Token claims.
//
// NOTE on omitted claims: the token deliberately does NOT include the user's
// root DID (or any other stable, cross-RP user identifier). The `sub` claim
// is a VSID derived from `(did_root, client_id, salt)`, which makes it
// pairwise per relying party. Adding a stable DID claim to RP-facing tokens
// would let two colluding RPs correlate the same user across `aud` values
// and undermine that pairwise-subject privacy property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — always the VSID (stable per `(did_root, client_id, salt)`).
    pub sub: String,
    /// Issuer — `https://<server>`.
    pub iss: String,
    /// Audience — the client identifier.
    pub aud: String,
    /// Expiry (unix timestamp).
    pub exp: i64,
    /// Issued-at (unix timestamp).
    pub iat: i64,
    /// JWT ID — uuid v4 used for replay prevention.
    pub jti: String,
    /// Brig·id server domain. Identifies the issuing server, not the user;
    /// kept distinct from `iss` (which carries the scheme + host) so RPs can
    /// match the bare hostname without re-parsing the URL.
    pub server: String,
    /// Alias type (Phase 0.0.1 — always `"public"`).
    pub alias_type: String,
}

/// Issue an OIDC ID Token signed with `key`.
///
/// - `now_unix`: current unix timestamp (seconds). Pass `time::OffsetDateTime::now_utc().unix_timestamp()`.
pub fn issue_token(
    params: &IssuanceParams<'_>,
    key: &OidcSigningKey,
    now_unix: i64,
) -> Result<String> {
    // Compute `exp = now_unix + ttl_secs` with explicit overflow handling.
    // A direct `as i64` cast of a large `u64` ttl would silently wrap to a
    // negative value and produce an already-expired token; a naive `+` could
    // also overflow at the i64 boundary. Both failure modes are surfaced as
    // `Error::InvalidTtl` so the caller can reject the request instead of
    // minting a bogus token.
    let ttl_i64 = i64::try_from(params.ttl_secs).map_err(|_| Error::InvalidTtl)?;
    let exp = now_unix.checked_add(ttl_i64).ok_or(Error::InvalidTtl)?;
    let claims = Claims {
        sub: params.vsid.to_string(),
        iss: params.issuer.to_string(),
        aud: params.client_id.to_string(),
        exp,
        iat: now_unix,
        jti: Uuid::new_v4().to_string(),
        server: params.server.to_string(),
        alias_type: "public".to_string(),
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(key.kid().to_string());
    let token = jsonwebtoken::encode(&header, &claims, &key.encoding_key())?;
    Ok(token)
}

/// Validate an OIDC ID Token and return its claims.
///
/// Checks signature, expiry, issuer, audience, and JTI replay.
pub fn validate_token(
    jwt: &str,
    expected_issuer: &str,
    expected_aud: &str,
    key: &OidcSigningKey,
    jti_store: &mut JtiStore,
) -> Result<Claims> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[expected_aud]);
    validation.set_issuer(&[expected_issuer]);
    // Disable jsonwebtoken's default 60s clock leeway: it would otherwise let
    // a token validate cryptographically after its `exp`, while `JtiStore`
    // evicts the replay-protection entry at exactly `exp`. The two semantics
    // must agree to prevent a replay window after expiry.
    validation.leeway = 0;
    let token_data = jsonwebtoken::decode::<Claims>(jwt, &key.decoding_key(), &validation)?;
    let claims = token_data.claims;
    jti_store.check_and_insert(&claims.jti, claims.exp)?;
    Ok(claims)
}

/// Decode and validate an OIDC token for repeated bearer auth use.
///
/// Checks signature, expiry, issuer, audience, and JTI blacklist.
/// Does **not** insert the JTI — allows the same token to be used multiple times
/// within its lifetime. Use this for bearer auth middleware.
/// Use [`validate_token`] when you want to consume the token (one-time use).
///
/// `expected_aud` is `Option<&str>`: pass `Some(aud)` when the consumer knows
/// which RP the token must target; pass `None` when the issuer itself accepts
/// any audience it has signed (e.g. an issuer-hosted `/auth/logout` that
/// revokes a token regardless of the original RP). Skipping the audience
/// check is safe in that single-issuer case because the signature already
/// proves the issuer minted the token.
pub fn decode_token(
    jwt: &str,
    expected_issuer: &str,
    expected_aud: Option<&str>,
    key: &OidcSigningKey,
    jti_store: &JtiStore,
) -> Result<Claims> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    match expected_aud {
        Some(aud) => validation.set_audience(&[aud]),
        None => validation.validate_aud = false,
    }
    validation.set_issuer(&[expected_issuer]);
    // Disable jsonwebtoken's default 60s clock leeway — see `validate_token`.
    validation.leeway = 0;
    let token_data = jsonwebtoken::decode::<Claims>(jwt, &key.decoding_key(), &validation)?;
    let claims = token_data.claims;
    if jti_store.is_blacklisted(&claims.jti) {
        return Err(Error::JtiReplay);
    }
    Ok(claims)
}

/// [`decode_token`] against a set of keys: the current one and those retired
/// within the grace period of a rotation. The key is chosen by the token's
/// `kid` header; a token without `kid`, or with an unknown one, is rejected.
pub fn decode_token_with_keys(
    jwt: &str,
    expected_issuer: &str,
    expected_aud: Option<&str>,
    keys: &[&OidcSigningKey],
    jti_store: &JtiStore,
) -> Result<Claims> {
    let header = jsonwebtoken::decode_header(jwt)?;
    let kid = header.kid.ok_or(Error::UnknownKey)?;
    let key = keys
        .iter()
        .find(|k| k.kid() == kid)
        .ok_or(Error::UnknownKey)?;
    decode_token(jwt, expected_issuer, expected_aud, key, jti_store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use brigid_crypto::MasterKey;
    use brigid_identity::{derive_vsid_salt, identity_vsid};

    fn master() -> MasterKey {
        MasterKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn test_vsid() -> Vsid {
        let salt = derive_vsid_salt(&master());
        identity_vsid(uuid::Uuid::from_bytes([1; 16]), "test-client", &salt)
    }

    fn test_key() -> OidcSigningKey {
        OidcSigningKey::generate()
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn test_params<'a>(vsid: &'a Vsid, client_id: &'a str) -> IssuanceParams<'a> {
        IssuanceParams {
            vsid,
            issuer: "https://example.com",
            client_id,
            server: "example.com",
            ttl_secs: 3600,
        }
    }

    #[test]
    fn issue_and_validate_roundtrip() {
        let key = test_key();
        let vsid = test_vsid();
        let mut store = JtiStore::new();

        let token = issue_token(&test_params(&vsid, "my-client"), &key, now()).unwrap();

        let claims =
            validate_token(&token, "https://example.com", "my-client", &key, &mut store).unwrap();

        assert_eq!(claims.sub, vsid.to_string());
        assert_eq!(claims.aud, "my-client");
        assert_eq!(claims.iss, "https://example.com");
        assert_eq!(claims.alias_type, "public");
    }

    #[test]
    fn sub_is_vsid_not_username_or_did() {
        let key = test_key();
        let vsid = test_vsid();
        let vsid_str = vsid.to_string();
        let mut store = JtiStore::new();

        let token = issue_token(&test_params(&vsid, "my-client"), &key, now()).unwrap();

        let claims =
            validate_token(&token, "https://example.com", "my-client", &key, &mut store).unwrap();

        // sub must be the VSID — not the username, alias, or raw DID
        assert_eq!(claims.sub, vsid_str);
        assert_ne!(claims.sub, "did:web:example.com");
        assert_ne!(claims.sub, "example.com");
    }

    #[test]
    fn validate_expired_token() {
        let key = test_key();
        let vsid = test_vsid();
        let mut store = JtiStore::new();

        // Issue with now = Unix epoch → exp = 1 (immediately expired)
        let params = IssuanceParams {
            vsid: &vsid,
            issuer: "https://example.com",
            client_id: "my-client",
            server: "example.com",
            ttl_secs: 1,
        };
        let token = issue_token(&params, &key, 0).unwrap();

        let err = validate_token(&token, "https://example.com", "my-client", &key, &mut store)
            .unwrap_err();
        assert!(matches!(err, Error::Expired));
    }

    #[test]
    fn validate_wrong_audience() {
        let key = test_key();
        let vsid = test_vsid();
        let mut store = JtiStore::new();

        let token = issue_token(&test_params(&vsid, "correct-client"), &key, now()).unwrap();

        let err = validate_token(
            &token,
            "https://example.com",
            "wrong-client",
            &key,
            &mut store,
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidAudience));
    }

    #[test]
    fn validate_jti_replay() {
        let key = test_key();
        let vsid = test_vsid();
        let mut store = JtiStore::new();

        let token = issue_token(&test_params(&vsid, "my-client"), &key, now()).unwrap();

        // First validation succeeds
        validate_token(&token, "https://example.com", "my-client", &key, &mut store).unwrap();

        // Second validation with the same token must fail (replay)
        let err = validate_token(&token, "https://example.com", "my-client", &key, &mut store)
            .unwrap_err();
        assert!(matches!(err, Error::JtiReplay));
    }

    #[test]
    fn validate_invalid_signature() {
        let key = test_key();
        let vsid = test_vsid();
        let mut store = JtiStore::new();

        let mut token = issue_token(&test_params(&vsid, "my-client"), &key, now()).unwrap();

        // Tamper with the last character of the signature part
        let last = token.pop().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        token.push(replacement);

        let err = validate_token(&token, "https://example.com", "my-client", &key, &mut store)
            .unwrap_err();
        // Hits the `_ => Error::Jwt` arm in From<jsonwebtoken::errors::Error>
        assert!(matches!(err, Error::Jwt(_)));
    }

    #[test]
    fn key_roundtrip_from_raw_bytes() {
        let key = OidcSigningKey::generate();
        let kid = key.kid().to_string();
        let bytes = key.to_raw_bytes();

        let key2 = OidcSigningKey::from_raw_bytes(kid.clone(), &bytes);
        assert_eq!(key2.kid(), kid);

        let vsid = test_vsid();
        let mut store = JtiStore::new();
        let token = issue_token(&test_params(&vsid, "client"), &key2, now()).unwrap();
        validate_token(&token, "https://example.com", "client", &key2, &mut store).unwrap();
    }

    // ── Algorithm confusion (core#21) ───────────────────────────────────────

    fn b64(bytes: &[u8]) -> String {
        use base64ct::Encoding;
        base64ct::Base64UrlUnpadded::encode_string(bytes)
    }

    /// Claims that would pass every other check, so only the algorithm or the
    /// signature can cause the rejection.
    fn valid_claims_json() -> String {
        serde_json::json!({
            "sub": test_vsid().to_string(),
            "iss": "https://example.com",
            "aud": "my-client",
            "exp": now() + 3600,
            "iat": now(),
            "jti": uuid::Uuid::new_v4().to_string(),
            "server": "example.com",
            "alias_type": "public",
        })
        .to_string()
    }

    fn assert_rejected_everywhere(token: &str, key: &OidcSigningKey) {
        let mut store = JtiStore::new();
        assert!(
            validate_token(token, "https://example.com", "my-client", key, &mut store).is_err(),
            "validate_token accepted a forged token"
        );
        assert!(
            decode_token(token, "https://example.com", None, key, &store).is_err(),
            "decode_token accepted a forged token"
        );
    }

    #[test]
    fn alg_none_is_rejected() {
        let key = test_key();
        let header = format!(r#"{{"alg":"none","typ":"JWT","kid":"{}"}}"#, key.kid());
        let unsigned = format!(
            "{}.{}",
            b64(header.as_bytes()),
            b64(valid_claims_json().as_bytes())
        );
        // Both shapes seen in the wild: trailing dot with empty signature, and none.
        assert_rejected_everywhere(&format!("{unsigned}."), &key);
        assert_rejected_everywhere(&unsigned, &key);
    }

    /// The classic confusion: HMAC-sign with the server's *public* key as the
    /// secret and hope the verifier picks the algorithm from the header.
    #[test]
    fn hs256_signed_with_the_public_key_is_rejected() {
        let key = test_key();
        let public = key.verifying_key().to_bytes();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(key.kid().to_string());
        let claims: serde_json::Value = serde_json::from_str(&valid_claims_json()).unwrap();
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(&public),
        )
        .unwrap();
        assert_rejected_everywhere(&token, &key);
    }

    /// A well-formed EdDSA token from another key, even claiming our `kid`.
    #[test]
    fn token_from_another_ed25519_key_is_rejected() {
        let real = test_key();
        let attacker = OidcSigningKey::from_raw_bytes(real.kid().to_string(), &[7u8; 32]);
        let token = issue_token(&test_params(&test_vsid(), "my-client"), &attacker, now()).unwrap();
        assert_rejected_everywhere(&token, &real);
        // Sanity: the same token is accepted by the key that signed it.
        let mut store = JtiStore::new();
        assert!(
            validate_token(
                &token,
                "https://example.com",
                "my-client",
                &attacker,
                &mut store
            )
            .is_ok()
        );
    }
}

#[cfg(test)]
mod multi_key_tests {
    use super::*;
    use brigid_crypto::MasterKey;
    use brigid_identity::{derive_vsid_salt, identity_vsid};

    fn token_from(key: &OidcSigningKey) -> String {
        let salt = derive_vsid_salt(&MasterKey::from_hex(&"ab".repeat(32)).unwrap());
        let vsid = identity_vsid(uuid::Uuid::from_bytes([1; 16]), "c", &salt);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        issue_token(
            &IssuanceParams {
                vsid: &vsid,
                issuer: "https://example.com",
                client_id: "c",
                server: "example.com",
                ttl_secs: 3600,
            },
            key,
            now,
        )
        .unwrap()
    }

    /// During a rotation, tokens signed by the retired key still verify; a
    /// key outside the set does not, even if it reuses a known `kid`.
    #[test]
    fn picks_the_key_by_kid() {
        let old = OidcSigningKey::from_seed(&[1u8; 32]);
        let new = OidcSigningKey::from_seed(&[2u8; 32]);
        let store = JtiStore::new();
        let keys = [&new, &old];
        for k in [&old, &new] {
            decode_token_with_keys(&token_from(k), "https://example.com", None, &keys, &store)
                .unwrap();
        }
        let stranger = OidcSigningKey::from_seed(&[3u8; 32]);
        assert!(matches!(
            decode_token_with_keys(
                &token_from(&stranger),
                "https://example.com",
                None,
                &keys,
                &store
            ),
            Err(Error::UnknownKey)
        ));
        let impostor = OidcSigningKey::from_raw_bytes(old.kid().to_string(), &[4u8; 32]);
        assert!(
            decode_token_with_keys(
                &token_from(&impostor),
                "https://example.com",
                None,
                &keys,
                &store
            )
            .is_err()
        );
    }
}
