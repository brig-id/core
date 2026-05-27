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
    /// Root DID of the authenticated user.
    pub user_did: &'a str,
    /// Brig·id server domain (e.g. `"example.com"`).
    pub server: &'a str,
    /// Token lifetime in seconds (added to `now_unix`).
    pub ttl_secs: u64,
}

/// OIDC ID Token claims.
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
    /// Root DID of the authenticated user.
    pub did: String,
    /// Brig·id server domain.
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
    let claims = Claims {
        sub: params.vsid.to_string(),
        iss: params.issuer.to_string(),
        aud: params.client_id.to_string(),
        exp: now_unix + params.ttl_secs as i64,
        iat: now_unix,
        jti: Uuid::new_v4().to_string(),
        did: params.user_did.to_string(),
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
pub fn decode_token(
    jwt: &str,
    expected_issuer: &str,
    expected_aud: &str,
    key: &OidcSigningKey,
    jti_store: &JtiStore,
) -> Result<Claims> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[expected_aud]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use brigid_crypto::MasterKey;
    use brigid_identity::{compute_vsid, derive_vsid_salt};

    fn master() -> MasterKey {
        MasterKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn test_vsid() -> Vsid {
        let salt = derive_vsid_salt(&master());
        compute_vsid("did:web:example.com", "test-client", &salt).unwrap()
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
            user_did: "did:web:example.com",
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
        assert_eq!(claims.did, "did:web:example.com");
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
            user_did: "did:web:example.com",
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
}
