//! Account recovery with a recovery code ([ADR-004] in the spec).
//!
//! A signed-in account creates its code (`POST /account/recovery-code`) and
//! sees whether it has one (`GET`). Someone who lost every passkey enters the
//! code at `/auth/recovery/begin`, which starts a passkey registration for the
//! account the code names; `/auth/recovery/finish` stores that passkey,
//! consumes the code and signs in. The code unlocks nothing else.
//!
//! No per-account lockout: it would let anyone block a victim's recovery, and
//! the 128-bit secret makes guessing hopeless. The ceremony routes' rate limit
//! applies.
//!
//! [ADR-004]: https://github.com/brig-id/spec/blob/main/decisions/004-account-recovery.md

use std::{sync::Arc, time::Instant};

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};
use brigid_identity::RecoveryCode;
use brigid_webauthn::{load_passkeys, passkey_to_credential};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    routes::auth::{
        BeginRegisterResponse, FinishRegisterRequest, apply_label, take_pending_registration,
    },
    session::{AccountSession, open_session},
    state::{AppState, PendingRegistration, RegistrationPurpose},
};

#[derive(Serialize)]
pub struct RecoveryCodeResponse {
    /// Shown once: the server keeps only a verifier.
    pub code: String,
}

#[derive(Serialize)]
pub struct RecoveryStatusResponse {
    /// When the current code was created; `null` when there is none (never
    /// created, or used since).
    pub code_created_at: Option<String>,
    /// When a code last recovered this account.
    pub last_used_at: Option<String>,
}

#[derive(Deserialize)]
pub struct BeginRecoveryRequest {
    pub code: String,
}

/// `POST /account/recovery-code`: a new code for the signed-in account,
/// replacing the previous one. Returned once.
pub async fn create_code(
    State(state): State<Arc<AppState>>,
    session: AccountSession,
) -> Result<impl IntoResponse, ApiError> {
    let user = session.account;
    let code = RecoveryCode::generate().map_err(|e| internal!(e))?;
    state
        .store
        .set_recovery_code(user.id, &code.recovery_id, &code.verifier())
        .await
        .map_err(|e| internal!(e))?;
    Ok((
        StatusCode::OK,
        Json(RecoveryCodeResponse {
            code: code.display().to_string(),
        }),
    ))
}

/// `GET /account/recovery-code`: whether the account has a usable code, and
/// when one was last used. Never the code itself.
pub async fn status(
    State(state): State<Arc<AppState>>,
    session: AccountSession,
) -> Result<impl IntoResponse, ApiError> {
    let user = session.account;
    let status = state
        .store
        .recovery_status(user.id)
        .await
        .map_err(|e| internal!(e))?;
    let fmt = |t: Option<time::OffsetDateTime>| t.and_then(|t| t.format(&Rfc3339).ok());
    Ok((
        StatusCode::OK,
        Json(RecoveryStatusResponse {
            code_created_at: fmt(status.code_created_at),
            last_used_at: fmt(status.last_used_at),
        }),
    ))
}

/// `POST /auth/recovery/begin`: check the code and start registering a new
/// passkey for the account it names.
///
/// A malformed code or a typo is a `400` with its reason (nothing was looked
/// up). An unknown recovery id and a wrong secret are the same `401`.
pub async fn begin(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BeginRecoveryRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let code = RecoveryCode::parse(&body.code).map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let found = state
        .store
        .find_recovery(&code.recovery_id)
        .await
        .map_err(|e| internal!(e))?;
    // Compare against something in every case, so an unknown id and a wrong
    // secret take the same path.
    let (user_id, verifier) = match found {
        Some((user_id, verifier)) => (Some(user_id), verifier),
        None => (None, vec![0u8; 32]),
    };
    let user_id = match user_id {
        Some(id) if code.matches(&verifier) => id,
        _ => return Err(ApiError::Unauthorized),
    };

    let user = state
        .store
        .fetch_user(user_id)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::Unauthorized)?;
    let existing = load_passkeys(&state.store, user.id)
        .await
        .map_err(|e| internal!(e))?;
    let exclude = existing.iter().map(|p| p.cred_id().clone()).collect();
    let (ccr, reg_state) = state
        .webauthn
        .begin_registration(user.id, &user.username, Some(exclude))
        .map_err(|e| internal!(e))?;

    let session_id = Uuid::new_v4();
    state.evict_expired_pending();
    {
        let mut map = state
            .pending_registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if map.len() >= crate::state::PENDING_SESSION_MAX_CAPACITY {
            return Err(ApiError::TooManyRequests);
        }
        map.insert(
            session_id,
            PendingRegistration {
                purpose: RegistrationPurpose::Recovery {
                    recovery_id: code.recovery_id,
                },
                user_id: user.id,
                username: user.username,
                server: user.server,
                state: reg_state,
                created_at: Instant::now(),
            },
        );
    }

    Ok((
        StatusCode::OK,
        Json(BeginRegisterResponse {
            session_id,
            challenge: ccr,
        }),
    ))
}

/// `POST /auth/recovery/finish`: store the new passkey, consume the code (one
/// transaction) and open a session. `409` when the code was used or replaced since
/// `begin`.
pub async fn finish(
    State(state): State<Arc<AppState>>,
    Json(body): Json<FinishRegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let pending = take_pending_registration(&state, body.session_id, |p| {
        matches!(p, RegistrationPurpose::Recovery { .. })
    })?;
    if pending.created_at.elapsed() > crate::state::PENDING_SESSION_TTL {
        return Err(ApiError::BadRequest("session expired".into()));
    }
    let RegistrationPurpose::Recovery { recovery_id } = pending.purpose else {
        unreachable!("checked by take_pending_registration");
    };

    let passkey = state
        .webauthn
        .finish_registration(&pending.state, &body.credential)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let cred = passkey_to_credential(pending.user_id, &passkey).map_err(|e| internal!(e))?;

    let recovered = state
        .store
        .recover_with_credential(&recovery_id, &cred)
        .await
        .map_err(|e| internal!(e))?;
    if !recovered {
        return Err(ApiError::Conflict(
            "this recovery code was used or replaced in the meantime".into(),
        ));
    }
    apply_label(&state, pending.user_id, cred.id, body.label.as_deref()).await?;

    let user = state
        .store
        .fetch_user(pending.user_id)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::Unauthorized)?;
    tracing::info!(user_id = %user.id, "account recovered with a recovery code");
    let cookie = open_session(&state, &user).await?;
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]))
}
