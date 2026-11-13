//! Discovery endpoints: the OpenID configuration and the JWKS.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

use brigid_oidc::{build_jwks, build_openid_configuration};

use crate::{error::ApiError, state::AppState};

/// `GET /.well-known/openid-configuration`
pub async fn openid_configuration(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(build_openid_configuration(&state.base_url))
}

/// `GET /.well-known/jwks.json`
pub async fn jwks(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, ApiError> {
    let key_set = build_jwks(&state.oidc_verification_keys());
    Ok((StatusCode::OK, Json(key_set)))
}
