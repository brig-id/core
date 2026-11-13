use brigid_identity::Vsid;
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::key::OidcSigningKey;

/// What goes into an ID token (ADR-005 §2, ADR-008).
pub struct IssuanceParams<'a> {
    /// The VSID of the identity for this client: the `sub` claim.
    pub vsid: &'a Vsid,
    /// Issuer URL (e.g. `"https://example.com"`).
    pub issuer: &'a str,
    /// The relying party the token is for: the `aud` claim.
    pub client_id: &'a str,
    /// The `nonce` of the authorization request, returned unchanged.
    pub nonce: Option<&'a str>,
    /// Unix time of the passkey ceremony behind the session.
    pub auth_time: i64,
    /// Token lifetime in seconds (added to `now_unix`).
    pub ttl_secs: u64,
}

/// The claims of an ID token.
///
/// Nothing here describes the person or the identity: `sub` is a VSID, an
/// identifier that exists for one identity at one relying party. A claim
/// that is the same at two relying parties would let them link their users.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: the VSID.
    pub sub: String,
    /// Issuer: this server's URL.
    pub iss: String,
    /// Audience: the client identifier.
    pub aud: String,
    /// Expiry (Unix seconds).
    pub exp: i64,
    /// Issued at (Unix seconds).
    pub iat: i64,
    /// When the person last proved who they are with a passkey (Unix seconds).
    pub auth_time: i64,
    /// The authorization request's `nonce`, when it had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Unique per token.
    pub jti: String,
}

/// Issue an ID token signed with `key` (EdDSA). `now_unix` is the current
/// Unix time in seconds.
pub fn issue_token(
    params: &IssuanceParams<'_>,
    key: &OidcSigningKey,
    now_unix: i64,
) -> Result<String> {
    // A `u64` lifetime cast with `as` could wrap to a negative value and mint
    // a token that is already expired; the addition could overflow too.
    let ttl = i64::try_from(params.ttl_secs).map_err(|_| Error::InvalidTtl)?;
    let exp = now_unix.checked_add(ttl).ok_or(Error::InvalidTtl)?;
    let claims = Claims {
        sub: params.vsid.to_string(),
        iss: params.issuer.to_string(),
        aud: params.client_id.to_string(),
        exp,
        iat: now_unix,
        auth_time: params.auth_time,
        nonce: params.nonce.map(str::to_owned),
        jti: Uuid::new_v4().to_string(),
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(key.kid().to_string());
    Ok(jsonwebtoken::encode(&header, &claims, &key.encoding_key())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brigid_identity::identity_vsid;
    use jsonwebtoken::Validation;

    fn test_vsid() -> Vsid {
        identity_vsid(uuid::Uuid::from_bytes([1; 16]), "test-client", &[7u8; 32])
    }

    fn params<'a>(vsid: &'a Vsid, nonce: Option<&'a str>) -> IssuanceParams<'a> {
        IssuanceParams {
            vsid,
            issuer: "https://example.com",
            client_id: "test-client",
            nonce,
            auth_time: 1_700_000_000,
            ttl_secs: 300,
        }
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// What a relying party does with the token: signature, issuer, audience.
    fn verify(jwt: &str, key: &OidcSigningKey) -> jsonwebtoken::errors::Result<Claims> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["test-client"]);
        validation.set_issuer(&["https://example.com"]);
        validation.leeway = 0;
        jsonwebtoken::decode::<Claims>(jwt, &key.decoding_key(), &validation).map(|d| d.claims)
    }

    #[test]
    fn the_token_carries_the_vsid_and_the_request_binding() {
        let key = OidcSigningKey::generate();
        let vsid = test_vsid();
        let t = now();
        let jwt = issue_token(&params(&vsid, Some("n-0S6_WzA2Mj")), &key, t).unwrap();
        let claims = verify(&jwt, &key).unwrap();
        assert_eq!(claims.sub, vsid.as_str());
        assert_eq!(claims.iss, "https://example.com");
        assert_eq!(claims.aud, "test-client");
        assert_eq!(claims.iat, t);
        assert_eq!(claims.exp, t + 300);
        assert_eq!(claims.auth_time, 1_700_000_000);
        assert_eq!(claims.nonce.as_deref(), Some("n-0S6_WzA2Mj"));

        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(header.kid.as_deref(), Some(key.kid()));
    }

    /// The payload holds the eight claims and nothing else: no name, no
    /// account, nothing shared between relying parties.
    #[test]
    fn the_payload_has_no_other_claim() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let key = OidcSigningKey::generate();
        let vsid = test_vsid();
        let jwt = issue_token(&params(&vsid, Some("n")), &key, now()).unwrap();
        let payload = Base64UrlUnpadded::decode_vec(jwt.split('.').nth(1).unwrap()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let mut names: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "aud",
                "auth_time",
                "exp",
                "iat",
                "iss",
                "jti",
                "nonce",
                "sub"
            ]
        );

        let jwt = issue_token(&params(&vsid, None), &key, now()).unwrap();
        let payload = Base64UrlUnpadded::decode_vec(jwt.split('.').nth(1).unwrap()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(json.get("nonce").is_none(), "no nonce asked, none returned");
    }

    #[test]
    fn each_token_has_its_own_jti() {
        let key = OidcSigningKey::generate();
        let vsid = test_vsid();
        let a = verify(
            &issue_token(&params(&vsid, None), &key, now()).unwrap(),
            &key,
        )
        .unwrap();
        let b = verify(
            &issue_token(&params(&vsid, None), &key, now()).unwrap(),
            &key,
        )
        .unwrap();
        assert_ne!(a.jti, b.jti);
    }

    #[test]
    fn another_key_or_an_expired_token_does_not_verify() {
        let key = OidcSigningKey::generate();
        let vsid = test_vsid();
        let jwt = issue_token(&params(&vsid, None), &key, now()).unwrap();
        assert!(verify(&jwt, &OidcSigningKey::generate()).is_err());

        let old = issue_token(&params(&vsid, None), &key, now() - 3600).unwrap();
        assert!(verify(&old, &key).is_err());
    }

    /// A token whose header claims another algorithm is not accepted as EdDSA
    /// (algorithm confusion, core#21).
    #[test]
    fn a_token_claiming_another_algorithm_is_refused() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let key = OidcSigningKey::generate();
        let vsid = test_vsid();
        let jwt = issue_token(&params(&vsid, None), &key, now()).unwrap();
        let (_, rest) = jwt.split_once('.').unwrap();
        for alg in ["none", "HS256", "RS256"] {
            let header = Base64UrlUnpadded::encode_string(
                format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#).as_bytes(),
            );
            assert!(verify(&format!("{header}.{rest}"), &key).is_err(), "{alg}");
        }
    }

    #[test]
    fn a_lifetime_that_overflows_is_refused() {
        let key = OidcSigningKey::generate();
        let vsid = test_vsid();
        let mut p = params(&vsid, None);
        p.ttl_secs = u64::MAX;
        assert!(matches!(
            issue_token(&p, &key, now()),
            Err(Error::InvalidTtl)
        ));
        p.ttl_secs = 10;
        assert!(matches!(
            issue_token(&p, &key, i64::MAX),
            Err(Error::InvalidTtl)
        ));
    }
}
