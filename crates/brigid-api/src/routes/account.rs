//! Leaving: a person deletes their own account.
//!
//! Deleting needs more than a session: a passkey ceremony done for that
//! purpose, so that an unattended, signed-in browser is not enough. The
//! ceremony is begun for the session's account and for nothing else; `finish`
//! accepts only an answer from one of that account's passkeys.

use std::{sync::Arc, time::Instant};

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};
use brigid_webauthn::load_passkeys;
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    routes::auth::{BeginLoginResponse, FinishLoginRequest, finish_authentication},
    session::{AccountSession, clear_cookie},
    state::{AppState, AuthenticationPurpose, PendingAuthentication, PendingLogin},
};

/// `POST /account/delete/begin`: the challenge of the ceremony that deletes
/// the signed-in account. Nothing is deleted yet.
pub async fn delete_begin(
    State(state): State<Arc<AppState>>,
    session: AccountSession,
) -> Result<impl IntoResponse, ApiError> {
    let passkeys = load_passkeys(&state.store, session.account.id)
        .await
        .map_err(|e| internal!(e))?;
    let (challenge, auth_state) = state
        .webauthn
        .begin_authentication(&passkeys)
        .map_err(|e| internal!(e))?;

    let session_id = Uuid::new_v4();
    state.evict_expired_pending();
    {
        let mut map = state
            .pending_authentications
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if map.len() >= crate::state::PENDING_SESSION_MAX_CAPACITY {
            return Err(ApiError::TooManyRequests);
        }
        map.insert(
            session_id,
            PendingAuthentication {
                purpose: AuthenticationPurpose::DeleteAccount,
                login: PendingLogin::Named {
                    user_id: session.account.id,
                    state: auth_state,
                },
                created_at: Instant::now(),
            },
        );
    }
    Ok((
        StatusCode::OK,
        Json(BeginLoginResponse {
            session_id,
            challenge,
        }),
    ))
}

/// `POST /account/delete/finish`: the passkey answered; the account is
/// deleted with everything recorded about it, and the cookie is cleared.
///
/// What it removes: the account, its passkeys, its recovery code, its
/// sessions, its identities and their attributes, and what was recorded
/// about the applications they signed in to. What it cannot remove: what an
/// application already received.
pub async fn delete_finish(
    State(state): State<Arc<AppState>>,
    session: AccountSession,
    Json(body): Json<FinishLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let account_id =
        finish_authentication(&state, &body, AuthenticationPurpose::DeleteAccount).await?;
    // The ceremony was begun for one account: the session's. A ceremony of
    // another account, replayed with this session, deletes nothing.
    if account_id != session.account.id {
        return Err(ApiError::Forbidden);
    }
    state
        .store
        .delete_account(account_id)
        .await
        .map_err(|e| internal!(e))?;
    tracing::info!("an account was deleted by its owner");
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, clear_cookie(&state))],
    ))
}
