//! The token endpoint (spec `protocol.md` §6): a relying party exchanges an
//! authorization code for an ID token.

use std::{collections::HashMap, sync::Arc};

use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64ct::{Base64, Encoding};
use brigid_identity::identity_vsid;
use brigid_oidc::{IssuanceParams, issue_token};
use serde_json::json;

use brigid_store::{Client, ClientAuth};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde::Deserialize;

use crate::state::{AppState, random_token};

/// `client_assertion_type` of a signed assertion (RFC 7523 §2.2).
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// An assertion is a proof for one request: one valid longer than this is
/// refused, which also bounds how long its `jti` is remembered.
const MAX_ASSERTION_LIFETIME_SECS: i64 = 600;

/// An ID token is a statement about one sign-in, read once by the relying
/// party: five minutes (spec `protocol.md` §6).
const ID_TOKEN_TTL_SECS: u64 = 300;

/// An OAuth error (RFC 6749 §5.2).
struct TokenError {
    status: StatusCode,
    error: &'static str,
    description: &'static str,
}

impl TokenError {
    fn bad_request(error: &'static str, description: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error,
            description,
        }
    }

    /// The client is unknown or did not prove who it is. One answer for
    /// both, so that the endpoint does not tell which client ids exist.
    fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description: "client authentication failed",
        }
    }

    /// The code is unknown, expired, already used, or was issued for another
    /// client, redirect URI or PKCE challenge. One answer for all of them.
    fn invalid_grant() -> Self {
        Self::bad_request("invalid_grant", "the authorization code is not valid")
    }

    fn internal(cause: impl std::fmt::Display) -> Self {
        tracing::error!(error = %cause, "token endpoint failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "server_error",
            description: "internal server error",
        }
    }
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.error,
            "error_description": self.description,
        }));
        let mut response = (self.status, no_store(), body).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"token\""),
            );
        }
        response
    }
}

fn no_store() -> [(header::HeaderName, HeaderValue); 2] {
    [
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        (header::PRAGMA, HeaderValue::from_static("no-cache")),
    ]
}

/// `POST /token`
pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(params): Form<HashMap<String, String>>,
) -> Response {
    match exchange(&state, &headers, &params).await {
        Ok(body) => (StatusCode::OK, no_store(), Json(body)).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn exchange(
    state: &AppState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<serde_json::Value, TokenError> {
    let param = |name: &str| {
        params
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    };

    // Who is asking: a signed assertion (a client that describes itself and
    // publishes keys), HTTP Basic, or the form; one of them only.
    let basic = basic_credentials(headers)?;
    let client = if let Some(assertion) = param("client_assertion") {
        if param("client_assertion_type") != Some(JWT_BEARER) {
            return Err(TokenError::bad_request(
                "invalid_request",
                "client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ));
        }
        if basic.is_some() || param("client_secret").is_some() {
            return Err(TokenError::bad_request(
                "invalid_request",
                "one client authentication method at a time",
            ));
        }
        // The client is the assertion's issuer; a client_id sent beside it
        // must be the same.
        let issuer = unverified_issuer(assertion).ok_or_else(TokenError::invalid_client)?;
        if param("client_id").is_some_and(|id| id != issuer) {
            return Err(TokenError::invalid_client());
        }
        let client = state
            .client(&issuer)
            .await
            .map_err(TokenError::internal)?
            .ok_or_else(TokenError::invalid_client)?;
        let signs = client
            .document
            .as_ref()
            .is_some_and(|d| d.auth == ClientAuth::PrivateKeyJwt);
        if !signs || !verify_assertion(state, &client, assertion).await? {
            return Err(TokenError::invalid_client());
        }
        client
    } else {
        let (client_id, secret) = match (&basic, param("client_id"), param("client_secret")) {
            (Some(_), _, Some(_)) => {
                return Err(TokenError::bad_request(
                    "invalid_request",
                    "one client authentication method at a time",
                ));
            }
            (Some((id, _)), Some(form_id), None) if id != form_id => {
                return Err(TokenError::invalid_client());
            }
            (Some((id, secret)), _, None) => (id.as_str(), Some(secret.as_str())),
            (None, Some(id), secret) => (id, secret),
            (None, None, _) => return Err(TokenError::invalid_client()),
        };
        let client = state
            .client(client_id)
            .await
            .map_err(TokenError::internal)?
            .ok_or_else(TokenError::invalid_client)?;
        let authenticated = match (&client.document, client.confidential, secret) {
            // A client that describes itself has no secret. One that
            // publishes keys must sign: it cannot fall back to nothing.
            (Some(document), _, None) => document.auth == ClientAuth::None,
            (Some(_), _, Some(_)) => false,
            (None, true, Some(secret)) => state
                .store
                .verify_client_secret(client_id, secret)
                .await
                .map_err(TokenError::internal)?,
            // A public client has no secret: PKCE is what ties it to the code.
            (None, false, None) => true,
            // A confidential client without its secret, or a secret presented
            // for a client that has none.
            _ => false,
        };
        if !authenticated {
            return Err(TokenError::invalid_client());
        }
        client
    };

    if param("grant_type") != Some("authorization_code") {
        return Err(TokenError::bad_request(
            "unsupported_grant_type",
            "only authorization_code is offered",
        ));
    }

    // The code is taken out before anything else is checked: whatever the
    // outcome, it cannot be presented again.
    let code = match param("code") {
        Some(code) => state
            .redeem_code(code)
            .await
            .map_err(TokenError::internal)?,
        None => None,
    }
    .ok_or_else(TokenError::invalid_grant)?;
    let verified = code.client_id == client.client_id
        && param("redirect_uri") == Some(code.redirect_uri.as_str())
        && param("code_verifier")
            .is_some_and(|verifier| brigid_oidc::pkce::verify_s256(verifier, &code.code_challenge));
    if !verified {
        return Err(TokenError::invalid_grant());
    }
    // The account may have been suspended since the code was issued.
    let suspended = state
        .store
        .account_standing(code.account_id)
        .await
        .map_err(TokenError::internal)?
        .is_none_or(|standing| standing.suspended);
    if suspended {
        return Err(TokenError::invalid_grant());
    }
    // The identity may have been deleted since the person chose it.
    state
        .store
        .fetch_identity(code.account_id, code.identity_id)
        .await
        .map_err(TokenError::internal)?
        .ok_or_else(TokenError::invalid_grant)?;

    let vsid = identity_vsid(code.identity_id, &client.client_id, &state.vsid_salt);
    let id_token = issue_token(
        &IssuanceParams {
            vsid: &vsid,
            issuer: state.issuer(),
            client_id: &client.client_id,
            nonce: code.nonce.as_deref(),
            auth_time: code.auth_time,
            ttl_secs: ID_TOKEN_TTL_SECS,
            // What the person accepted when the code was issued, with the
            // values they saw.
            attributes: &code.attributes,
        },
        &state.oidc_key,
        helpers4::time::unix_now().map_or(0, |secs| secs as i64),
    )
    .map_err(TokenError::internal)?;

    // OAuth 2.0 requires an access token in the response and libraries refuse
    // one without it. No endpoint of this server accepts it (spec `protocol.md` §6): it is
    // a random value, kept nowhere.
    let access_token = random_token().ok_or_else(|| TokenError::internal("no entropy"))?;

    Ok(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ID_TOKEN_TTL_SECS,
        "id_token": id_token,
    }))
}

/// The `iss` of a JWT, read without checking anything: only to know which
/// client's keys to check it with.
fn unverified_issuer(jwt: &str) -> Option<String> {
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    let payload = jwt.split('.').nth(1)?;
    let bytes = Base64UrlUnpadded::decode_vec(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("iss")?.as_str().map(str::to_owned)
}

#[derive(Deserialize)]
struct AssertionClaims {
    exp: i64,
    jti: Option<String>,
}

/// Whether `jwt` is a valid client assertion of `client` (RFC 7523,
/// protocol.md §6): signed with EdDSA or ES256 by one of the keys its
/// document gives, `typ` absent or a JWT, issued by and about the client,
/// for this server (its issuer or its token endpoint), not expired, valid
/// at most ten minutes, and a `jti` never seen before.
async fn verify_assertion(
    state: &AppState,
    client: &Client,
    jwt: &str,
) -> Result<bool, TokenError> {
    let Some(document) = &client.document else {
        return Ok(false);
    };
    let Ok(header) = jsonwebtoken::decode_header(jwt) else {
        return Ok(false);
    };
    if !matches!(header.alg, Algorithm::EdDSA | Algorithm::ES256) {
        return Ok(false);
    }
    let typ_ok = header.typ.as_deref().is_none_or(|typ| {
        typ.eq_ignore_ascii_case("JWT") || typ.eq_ignore_ascii_case("client-authentication+jwt")
    });
    if !typ_ok {
        return Ok(false);
    }

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[
        state.issuer().to_owned(),
        format!("{}/token", state.issuer()),
    ]);
    validation.set_issuer(&[client.client_id.as_str()]);
    validation.sub = Some(client.client_id.clone());
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    validation.leeway = 30;
    validation.validate_nbf = true;

    let verify = |set: &JwkSet| -> Option<AssertionClaims> {
        set.keys
            .iter()
            .filter(|key| crate::described::usable_key(key, Some(header.alg)))
            .filter(|key| match (&header.kid, &key.common.key_id) {
                (Some(kid), Some(key_id)) => kid == key_id,
                (Some(_), None) => false,
                (None, _) => true,
            })
            .find_map(|key| {
                let decoding = DecodingKey::from_jwk(key).ok()?;
                jsonwebtoken::decode::<AssertionClaims>(jwt, &decoding, &validation)
                    .ok()
                    .map(|data| data.claims)
            })
    };
    let claims = if let Some(jwks) = &document.jwks {
        let Ok(set) = serde_json::from_value::<JwkSet>(jwks.clone()) else {
            return Ok(false);
        };
        verify(&set)
    } else if let Some(uri) = &document.jwks_uri {
        let cached = state.described.key_set(uri, false).await;
        match cached.as_ref().ok().and_then(&verify) {
            Some(claims) => Some(claims),
            // A key the set does not have may be one the client just
            // added: read the set again (at most once a minute).
            None => match state.described.key_set(uri, true).await {
                Ok(set) => verify(&set),
                Err(reason) => {
                    tracing::info!(client_id = %client.client_id, %reason, "client keys not usable");
                    None
                }
            },
        }
    } else {
        None
    };
    let Some(claims) = claims else {
        return Ok(false);
    };

    let now = helpers4::time::unix_now().map_or(0, |secs| secs as i64);
    let Some(jti) = claims.jti.filter(|jti| !jti.is_empty() && jti.len() <= 256) else {
        return Ok(false);
    };
    if claims.exp - now > MAX_ASSERTION_LIFETIME_SECS {
        return Ok(false);
    }
    state
        .shared
        .first_use(&client.client_id, &jti, claims.exp, now)
        .await
        .map_err(TokenError::internal)
}

/// The client id and secret of an `Authorization: Basic` header, each
/// form-urlencoded before the base64 (RFC 6749 §2.3.1). `None` without such
/// a header; an error when it is there and unreadable.
fn basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, TokenError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let decoded = value
        .to_str()
        .ok()
        .and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("basic").then_some(rest.trim())
        })
        .and_then(|b64| Base64::decode_vec(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(TokenError::invalid_client)?;
    let (id, secret) = decoded
        .split_once(':')
        .ok_or_else(TokenError::invalid_client)?;
    Ok(Some((form_decode(id), form_decode(secret))))
}

/// `application/x-www-form-urlencoded` decoding of one value.
fn form_decode(value: &str) -> String {
    url::form_urlencoded::parse(value.as_bytes())
        .next()
        .map(|(decoded, _)| decoded.into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn basic_credentials_are_decoded() {
        assert!(
            basic_credentials(&HeaderMap::new())
                .ok()
                .flatten()
                .is_none()
        );

        // "client:secret"
        let got = basic_credentials(&basic("Basic Y2xpZW50OnNlY3JldA=="))
            .ok()
            .flatten();
        assert_eq!(got, Some(("client".into(), "secret".into())));

        // "a%3Ab:c+d": the parts are form-urlencoded inside the base64.
        let got = basic_credentials(&basic("basic YSUzQWI6Yytk"))
            .ok()
            .flatten();
        assert_eq!(got, Some(("a:b".into(), "c d".into())));
    }

    #[test]
    fn an_unreadable_basic_header_is_an_authentication_failure() {
        for value in ["Bearer abc", "Basic !!!", "Basic bm9jb2xvbg=="] {
            assert!(basic_credentials(&basic(value)).is_err(), "{value}");
        }
    }
}
