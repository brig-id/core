//! Discovery endpoints: OpenID Connect configuration, JWKS, and DID.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

use brigid_did::did_root_document_handler;
use brigid_oidc::{build_jwks, build_openid_configuration};

use crate::{error::ApiError, state::AppState};

/// `GET /.well-known/openid-configuration`
pub async fn openid_configuration(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let config = build_openid_configuration(&state.base_url);
    Ok((StatusCode::OK, Json(config)))
}

/// `GET /.well-known/jwks.json`
pub async fn jwks(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, ApiError> {
    let key_set = build_jwks(&[&state.oidc_key]);
    Ok((StatusCode::OK, Json(key_set)))
}

/// `GET /.well-known/did.json`
///
/// Exposes the server's own DID document, derived from the OIDC signing key's
/// Ed25519 verifying key.
pub async fn did_document(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    // Extract the server's hostname (including any non-default port) from the
    // base URL — the DID:web identifier must match the URL clients use to
    // resolve `.well-known/did.json`, which includes the port when present.
    let host = state
        .base_url
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("invalid base URL: no host".into()))?;
    let server = match state.base_url.port() {
        Some(port) => format!("{host}%3A{port}"),
        None => host.to_string(),
    };

    // Use the OIDC Ed25519 key bytes as the server's public key.
    let public_key_bytes = state.oidc_key.verifying_key().to_bytes();

    let doc = did_root_document_handler(&server, &public_key_bytes)
        .map_err(|e| ApiError::Internal(Box::new(e)))?;

    Ok((StatusCode::OK, Json(doc)))
}
