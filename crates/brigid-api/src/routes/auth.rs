//! WebAuthn authentication and registration routes.

use std::{sync::Arc, time::Instant};

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use brigid_did::build_did_web;
use brigid_identity::{RootId, compute_vsid};
use brigid_oidc::{IssuanceParams, issue_token};
use brigid_store::User;
use brigid_webauthn::{load_passkeys, store_passkey, update_passkey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    middleware::AuthenticatedClaims,
    state::{AppState, PendingAuthentication, PendingRegistration},
};

#[derive(Deserialize)]
pub struct BeginRegisterRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct BeginRegisterResponse {
    pub session_id: Uuid,
    pub challenge: webauthn_rs::prelude::CreationChallengeResponse,
}

#[derive(Deserialize)]
pub struct FinishRegisterRequest {
    pub session_id: Uuid,
    pub credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
pub struct BeginLoginRequest {
    pub username: String,
}

#[derive(Serialize)]
pub struct BeginLoginResponse {
    pub session_id: Uuid,
    pub challenge: webauthn_rs::prelude::RequestChallengeResponse,
}

#[derive(Deserialize)]
pub struct FinishLoginRequest {
    pub session_id: Uuid,
    pub credential: webauthn_rs::prelude::PublicKeyCredential,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub id_token: String,
}

/// `POST /auth/register/begin`
pub async fn register_begin(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BeginRegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let root_id = RootId::parse(&body.username).map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let existing = state
        .store
        .fetch_user_by_username(&root_id.username, &root_id.server)
        .await
        .map_err(|e| internal!(e))?;

    if existing.is_some() {
        return Err(ApiError::Conflict(format!(
            "user {} already exists",
            body.username
        )));
    }

    let user_id = Uuid::new_v4();
    let (ccr, reg_state) = state
        .webauthn
        .begin_registration(user_id, &body.username)
        .map_err(|e| internal!(e))?;

    let session_id = Uuid::new_v4();
    state.evict_expired_pending();
    state.pending_registrations.lock().unwrap().insert(
        session_id,
        PendingRegistration {
            user_id,
            username: root_id.username.clone(),
            server: root_id.server.clone(),
            state: reg_state,
            created_at: Instant::now(),
        },
    );

    Ok((
        StatusCode::OK,
        Json(BeginRegisterResponse {
            session_id,
            challenge: ccr,
        }),
    ))
}

/// `POST /auth/register/finish`
pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    Json(body): Json<FinishRegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let pending = state
        .pending_registrations
        .lock()
        .unwrap()
        .remove(&body.session_id)
        .ok_or(ApiError::BadRequest("unknown session".into()))?;

    let passkey = state
        .webauthn
        .finish_registration(&pending.state, &body.credential)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Use the same user_id that was bound into the WebAuthn challenge —
    // the passkey's stored user handle must match the one in the authenticator.
    let user_id = pending.user_id;
    let did_web = build_did_web(&pending.username, &pending.server).to_string();

    let user = User {
        id: user_id,
        username: pending.username,
        server: pending.server,
        did_web,
        created_at: OffsetDateTime::now_utc(),
    };

    state.store.store_user(&user).await.map_err(|e| match e {
        // The pre-check in `register_begin` is advisory; the authoritative
        // duplicate signal is the UNIQUE constraint on `username_index`.
        // Concurrent registrations of the same username collapse here.
        brigid_store::Error::Duplicate => {
            ApiError::Conflict(format!("user {} already exists", user.username))
        }
        other => internal!(other),
    })?;
    store_passkey(&state.store, user_id, &passkey)
        .await
        .map_err(|e| internal!(e))?;

    Ok(StatusCode::OK)
}

/// `POST /auth/login/begin`
pub async fn login_begin(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BeginLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let root_id = RootId::parse(&body.username).map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let user = state
        .store
        .fetch_user_by_username(&root_id.username, &root_id.server)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::NotFound)?;

    let passkeys = load_passkeys(&state.store, user.id)
        .await
        .map_err(|e| internal!(e))?;

    let (rcr, auth_state) = state
        .webauthn
        .begin_authentication(&passkeys)
        .map_err(|e| internal!(e))?;

    let session_id = Uuid::new_v4();
    state.evict_expired_pending();
    state.pending_authentications.lock().unwrap().insert(
        session_id,
        PendingAuthentication {
            user_id: user.id,
            state: auth_state,
            created_at: Instant::now(),
        },
    );

    Ok((
        StatusCode::OK,
        Json(BeginLoginResponse {
            session_id,
            challenge: rcr,
        }),
    ))
}

/// `POST /auth/login/finish`
pub async fn login_finish(
    State(state): State<Arc<AppState>>,
    Json(body): Json<FinishLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let pending = state
        .pending_authentications
        .lock()
        .unwrap()
        .remove(&body.session_id)
        .ok_or(ApiError::BadRequest("unknown session".into()))?;

    let mut passkeys = load_passkeys(&state.store, pending.user_id)
        .await
        .map_err(|e| internal!(e))?;

    let auth_result = state
        .webauthn
        .finish_authentication(&mut passkeys, &pending.state, &body.credential)
        .map_err(|_| ApiError::Unauthorized)?;

    if auth_result.credential_updated {
        for passkey in &passkeys {
            let cred_id_json =
                serde_json::to_string(passkey.cred_id()).expect("CredentialID always serializes");
            let cred_id = cred_id_json.trim_matches('"').to_string();
            if cred_id == auth_result.credential_id {
                update_passkey(&state.store, pending.user_id, passkey)
                    .await
                    .map_err(|e| internal!(e))?;
                break;
            }
        }
    }

    let user = state
        .store
        .fetch_user(pending.user_id)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::NotFound)?;

    let issuer = state.base_url.to_string();
    let issuer = issuer.trim_end_matches('/').to_string();
    let client_id = state.base_url.host_str().unwrap_or("unknown").to_string();
    let vsid =
        compute_vsid(&user.did_web, &client_id, &state.vsid_salt).map_err(|e| internal!(e))?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let params = IssuanceParams {
        vsid: &vsid,
        issuer: &issuer,
        client_id: &client_id,
        user_did: &user.did_web,
        server: &user.server,
        ttl_secs: 3600,
    };

    let id_token = issue_token(&params, &state.oidc_key, now).map_err(|e| internal!(e))?;

    Ok((StatusCode::OK, Json(LoginResponse { id_token })))
}

/// `POST /auth/logout`
///
/// Blacklists the presented Bearer token's JTI, preventing further use
/// before it expires naturally. The JTI is persisted in the database so
/// it remains blacklisted across server restarts.
pub async fn logout(
    State(state): State<Arc<AppState>>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
) -> Result<impl IntoResponse, ApiError> {
    // In-memory blacklist (fast path for the current process session).
    state
        .jti_store
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .blacklist(&claims.jti, claims.exp);
    // Persistent blacklist — survives server restarts.
    state
        .store
        .blacklist_jti(&claims.jti, claims.exp)
        .await
        .map_err(|e| internal!(e))?;
    Ok(StatusCode::OK)
}
