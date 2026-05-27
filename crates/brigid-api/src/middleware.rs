//! Axum extractors for authenticated requests.

use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, request::Parts},
};
use brigid_oidc::{Claims, decode_token};

use crate::{error::ApiError, state::AppState};

/// Extractor that validates the `Authorization: Bearer <token>` header.
///
/// Attaches the validated [`Claims`] to the request for downstream handlers.
/// Returns `401 Unauthorized` if the header is missing, the token is invalid,
/// expired, or has been blacklisted (e.g. after logout).
pub struct AuthenticatedClaims(pub Claims);

impl FromRequestParts<Arc<AppState>> for AuthenticatedClaims {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer(&parts.headers)
            .ok_or(ApiError::Unauthorized)?
            .to_owned();

        let issuer = state.base_url.to_string();
        let issuer = issuer.trim_end_matches('/').to_string();
        let client_id = state.base_url.host_str().unwrap_or("unknown").to_string();

        // Decode and validate the token against the in-memory JTI blacklist.
        // The guard is scoped so it is *definitely* dropped before the async
        // DB check below — MutexGuard is !Send and cannot cross an await point.
        let claims = {
            let jti_store = state.jti_store.lock().unwrap_or_else(|e| e.into_inner());
            decode_token(&token, &issuer, &client_id, &state.oidc_key, &jti_store)
                .map_err(|_| ApiError::Unauthorized)?
        }; // MutexGuard dropped here, before any .await

        // Also check the persistent DB blacklist so revocations survive restarts.
        let db_blacklisted = state
            .store
            .is_jti_blacklisted(&claims.jti)
            .await
            .map_err(|_| ApiError::Unauthorized)?;
        if db_blacklisted {
            return Err(ApiError::Unauthorized);
        }

        Ok(AuthenticatedClaims(claims))
    }
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}
