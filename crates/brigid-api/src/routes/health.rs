//! Health and readiness endpoints.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use std::sync::Arc;

use crate::state::AppState;

/// `GET /health` — always 200.
pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

/// `GET /ready` — 200 when the DB is reachable, 503 otherwise.
pub async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // A lightweight query to verify the database connection.
    match state.store.fetch_user(uuid::Uuid::nil()).await {
        Ok(_) | Err(brigid_store::Error::Uuid(_)) => {
            (StatusCode::OK, Json(json!({ "status": "ready" })))
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable" })),
        ),
    }
}
