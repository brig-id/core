use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;
use url::Url;

use crate::key::OidcSigningKey;

/// A single JSON Web Key (Ed25519 / OKP).
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    /// Base64url-encoded public key bytes (32 bytes for Ed25519).
    pub x: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
}

/// A JSON Web Key Set.
#[derive(Debug, Clone, Serialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// OpenID Connect Discovery 1.0 metadata, for the one flow this server
/// offers: Authorization Code with PKCE (ADR-005 §2, ADR-008).
#[derive(Debug, Clone, Serialize)]
pub struct OpenIDConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
    /// The authorization response names its issuer (RFC 9207).
    pub authorization_response_iss_parameter_supported: bool,
}

/// Build a JWKS from one or more signing keys.
pub fn build_jwks(keys: &[&OidcSigningKey]) -> JwkSet {
    let jwks = keys
        .iter()
        .map(|k| {
            let vk = k.verifying_key();
            Jwk {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                x: Base64UrlUnpadded::encode_string(vk.as_bytes()),
                kid: k.kid().to_string(),
                alg: "EdDSA".to_string(),
                key_use: "sig".to_string(),
            }
        })
        .collect();
    JwkSet { keys: jwks }
}

/// Build the `.well-known/openid-configuration` response for `base_url`.
pub fn build_openid_configuration(base_url: &Url) -> OpenIDConfiguration {
    let base = base_url.as_str().trim_end_matches('/');
    OpenIDConfiguration {
        issuer: base.to_string(),
        authorization_endpoint: format!("{base}/authorize"),
        token_endpoint: format!("{base}/token"),
        jwks_uri: format!("{base}/.well-known/jwks.json"),
        response_types_supported: vec!["code"],
        grant_types_supported: vec!["authorization_code"],
        // A site receives an identifier and nothing else (ADR-008).
        scopes_supported: vec!["openid"],
        // `sub` is a VSID: one per identity and per client, never an
        // identifier shared between relying parties.
        subject_types_supported: vec!["pairwise"],
        id_token_signing_alg_values_supported: vec!["EdDSA"],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        code_challenge_methods_supported: vec!["S256"],
        claims_supported: vec![
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "jti",
        ],
        authorization_response_iss_parameter_supported: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_contains_correct_key() {
        let key = OidcSigningKey::generate();
        let set = build_jwks(&[&key]);

        assert_eq!(set.keys.len(), 1);
        let jwk = &set.keys[0];
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.alg, "EdDSA");
        assert_eq!(jwk.key_use, "sig");
        assert_eq!(jwk.kid, key.kid());

        // x must be base64url of the 32-byte verifying key
        let decoded = base64ct::Base64UrlUnpadded::decode_vec(&jwk.x).unwrap();
        assert_eq!(decoded, key.verifying_key().as_bytes().to_vec());
    }

    #[test]
    fn jwks_serializes_to_valid_json() {
        let key = OidcSigningKey::generate();
        let set = build_jwks(&[&key]);
        let json = serde_json::to_string(&set).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed["keys"].is_array());
        assert_eq!(parsed["keys"][0]["kty"], "OKP");
        assert_eq!(parsed["keys"][0]["alg"], "EdDSA");
        assert_eq!(parsed["keys"][0]["use"], "sig");
    }

    #[test]
    fn openid_configuration_valid_json() {
        let base_url = Url::parse("https://example.com").unwrap();
        let config = build_openid_configuration(&base_url);
        let json = serde_json::to_string(&config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["issuer"], "https://example.com");
        assert_eq!(
            parsed["jwks_uri"],
            "https://example.com/.well-known/jwks.json"
        );
        assert_eq!(
            parsed["authorization_endpoint"],
            "https://example.com/authorize"
        );
        assert_eq!(parsed["token_endpoint"], "https://example.com/token");
        assert_eq!(
            parsed["response_types_supported"],
            serde_json::json!(["code"])
        );
        assert_eq!(parsed["scopes_supported"], serde_json::json!(["openid"]));
        assert_eq!(
            parsed["subject_types_supported"],
            serde_json::json!(["pairwise"])
        );
        assert_eq!(
            parsed["id_token_signing_alg_values_supported"],
            serde_json::json!(["EdDSA"])
        );
        assert_eq!(
            parsed["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
    }

    #[test]
    fn openid_configuration_trailing_slash() {
        let base_url = Url::parse("https://example.com/").unwrap();
        let config = build_openid_configuration(&base_url);
        // Must not double-slash
        assert!(!config.jwks_uri.contains("//well-known"));
        assert_eq!(config.issuer, "https://example.com");
    }
}
