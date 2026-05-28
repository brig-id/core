//! WebAuthn authentication and registration routes.

use std::{sync::Arc, time::Instant};

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use brigid_did::build_did_web;
use brigid_identity::{RootId, compute_vsid};
use brigid_oidc::{IssuanceParams, issue_token};
use brigid_store::User;
use brigid_webauthn::{load_passkeys, passkey_to_credential, update_passkey};
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
    /// Relying-party identifier (the OIDC `client_id`) that will receive the
    /// resulting ID Token. Required: the `aud` claim and the VSID embedded
    /// in the token are derived from this value, so the same physical user
    /// presents a different opaque `sub` to each RP (AGENTS.md per-RP
    /// correlation invariant).
    pub client_id: String,
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
    state
        .pending_registrations
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
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
        .unwrap_or_else(|e| e.into_inner())
        .remove(&body.session_id)
        .ok_or(ApiError::BadRequest("unknown session".into()))?;

    // Authoritative TTL check at finish time. `evict_expired_pending()` only
    // runs opportunistically when a new challenge is created; in the absence
    // of new traffic an expired pending session would otherwise remain valid.
    if pending.created_at.elapsed() > crate::state::PENDING_SESSION_TTL {
        return Err(ApiError::BadRequest("session expired".into()));
    }

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

    // Atomic registration: writing the user and their first credential in
    // separate operations leaves a window where a transient failure on the
    // credential write would orphan the user row (UNIQUE on `username_index`
    // then blocks every re-registration attempt while every login fails
    // with "no credentials"). The store-level transaction commits both or
    // neither.
    let cred = passkey_to_credential(user_id, &passkey).map_err(|e| internal!(e))?;
    state
        .store
        .register_user_with_credential(&user, &cred)
        .await
        .map_err(|e| match e {
            brigid_store::Error::Duplicate => {
                ApiError::Conflict(format!("user {} already exists", user.username))
            }
            other => internal!(other),
        })?;

    Ok(StatusCode::OK)
}

/// `POST /auth/login/begin`
pub async fn login_begin(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BeginLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let root_id = RootId::parse(&body.username).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    if body.client_id.is_empty() {
        return Err(ApiError::BadRequest("client_id is required".into()));
    }

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
    state
        .pending_authentications
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            session_id,
            PendingAuthentication {
                user_id: user.id,
                client_id: body.client_id,
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
        .unwrap_or_else(|e| e.into_inner())
        .remove(&body.session_id)
        .ok_or(ApiError::BadRequest("unknown session".into()))?;

    // Authoritative TTL check at finish time — see `register_finish`.
    if pending.created_at.elapsed() > crate::state::PENDING_SESSION_TTL {
        return Err(ApiError::BadRequest("session expired".into()));
    }

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
    // Use the relying-party `client_id` captured at `/auth/login/begin` (and
    // bound into the pending session so it cannot be swapped between the
    // begin and finish requests). The `aud` claim and the VSID embedded in
    // the token are both derived from this value so the same physical user
    // presents a different opaque `sub` to each RP (AGENTS.md per-RP
    // correlation invariant).
    let client_id = pending.client_id.clone();
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
    // Persist FIRST. The in-memory blacklist is only the fast-path cache;
    // writing to it before the durable store would make a transient DB error
    // unrecoverable for this token: the response would be 500 but the JTI
    // would already be in the in-memory blacklist, so a retried logout would
    // be rejected by `AuthenticatedClaims` before it could persist the
    // revocation. Persisting first means a 500 still leaves the operator
    // free to retry, and the in-memory cache is only updated on success.
    state
        .store
        .blacklist_jti(&claims.jti, claims.exp)
        .await
        .map_err(|e| internal!(e))?;
    state
        .jti_store
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .blacklist(&claims.jti, claims.exp);
    Ok(StatusCode::OK)
}
