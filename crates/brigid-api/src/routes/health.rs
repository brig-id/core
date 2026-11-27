//! Health and readiness endpoints.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use std::sync::Arc;

use crate::state::AppState;

/// `GET /health` — always 200.
pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

/// `GET /ready` — 200 when this server takes requests, 503 otherwise, with
/// the reason: the database does not answer, the process is stopping, or,
/// for a node of a server made of several, the schema is not one it serves
/// on ([`AppState::readiness`]).
pub async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.readiness().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(why) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable", "reason": why.reason() })),
        ),
    }
}
