//! WebAuthn authentication and registration routes.

use std::{sync::Arc, time::Instant};

use axum::{
    Json,
    extract::{Path, State},
    http::{StatusCode, header},
    response::IntoResponse,
};
use brigid_identity::RootId;
use brigid_store::User;
use brigid_webauthn::{load_passkeys, passkey_to_credential, update_passkey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    session::{AccountSession, clear_cookie, open_session},
    state::{
        AppState, PendingAuthentication, PendingLogin, PendingRegistration, RegistrationPurpose,
    },
};

#[derive(Deserialize)]
pub struct BeginRegisterRequest {
    /// `username@this-server`. Absent: the server generates the username
    /// (ADR-003: it is a hidden sign-in handle).
    #[serde(default)]
    pub username: Option<String>,
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
    /// Optional human-readable name for the new passkey ("Pixel 9").
    /// WebAuthn does not carry the authenticator's name, so the user gives it.
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Deserialize)]
pub struct RenamePasskeyRequest {
    /// The new label; empty removes it.
    pub label: String,
}

#[derive(Deserialize)]
pub struct BeginLoginRequest {
    /// `user@server`. Absent: username-less login with a discoverable
    /// credential (passkey autofill), the authenticator names the user.
    #[serde(default)]
    pub username: Option<String>,
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
pub struct PasskeySummary {
    pub id: Uuid,
    pub label: Option<String>,
}

/// What the interface needs to know about this server before anyone signs in.
#[derive(Serialize)]
pub struct ServerInfo {
    /// Whether new accounts can be created here.
    pub sign_up: bool,
}

/// `GET /auth/server`
pub async fn server_info(State(state): State<Arc<AppState>>) -> Json<ServerInfo> {
    Json(ServerInfo {
        sign_up: state.signup_open,
    })
}

/// `POST /auth/register/begin`
pub async fn register_begin(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BeginRegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if !state.signup_open {
        return Err(ApiError::SignupClosed);
    }
    let host = state.host()?.to_string();
    let root_id = match body.username.as_deref() {
        Some(handle) => {
            let root_id = RootId::parse(handle).map_err(|e| ApiError::BadRequest(e.to_string()))?;
            // An account lives on this server. `alice@elsewhere.example` would
            // put a domain this server does not control in the account's DID.
            if root_id.server != host {
                return Err(ApiError::BadRequest(format!(
                    "accounts on this server end with @{host}"
                )));
            }
            if state
                .store
                .fetch_user_by_username(&root_id.username, &root_id.server)
                .await
                .map_err(|e| internal!(e))?
                .is_some()
            {
                return Err(ApiError::Conflict(format!("user {handle} already exists")));
            }
            root_id
        }
        None => generated_root_id(&state, &host).await?,
    };
    let handle = format!("{}@{}", root_id.username, root_id.server);

    let user_id = Uuid::new_v4();
    let (ccr, reg_state) = state
        .webauthn
        .begin_registration(user_id, &handle, None)
        .map_err(|e| internal!(e))?;

    let session_id = Uuid::new_v4();
    state.evict_expired_pending();
    {
        let mut map = state
            .pending_registrations
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if map.len() >= crate::state::PENDING_SESSION_MAX_CAPACITY {
            // Hard cap reached even after TTL eviction — reject with 429 so
            // callers see backpressure instead of the server exhausting
            // memory under a sustained `begin` flood.
            return Err(ApiError::TooManyRequests);
        }
        map.insert(
            session_id,
            PendingRegistration {
                purpose: RegistrationPurpose::Signup,
                user_id,
                username: root_id.username.clone(),
                server: root_id.server.clone(),
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

/// `POST /auth/register/finish`
pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    Json(body): Json<FinishRegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let pending = take_pending_registration(&state, body.session_id, |p| {
        matches!(p, RegistrationPurpose::Signup)
    })?;

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

    let user = User {
        id: user_id,
        username: pending.username,
        server: pending.server,
        created_at: OffsetDateTime::now_utc(),
    };

    // Atomic registration: writing the user and their first credential in
    // separate operations leaves a window where a transient failure on the
    // credential write would orphan the user row (UNIQUE on `username_index`
    // then blocks every re-registration attempt while every login fails
    // with "no credentials"). The store-level transaction commits both or
    // neither.
    let cred = passkey_to_credential(user_id, &passkey).map_err(|e| internal!(e))?;
    let identities = crate::routes::identities::starter_identities(user_id);
    state
        .store
        .register_user_with_credential(&user, &cred, &identities)
        .await
        .map_err(|e| match e {
            brigid_store::Error::Duplicate => {
                ApiError::Conflict(format!("user {} already exists", user.username))
            }
            other => internal!(other),
        })?;
    apply_label(&state, user_id, cred.id, body.label.as_deref()).await?;

    // The new account is signed in by the same ceremony (ADR-003): a
    // session, never a token (ADR-005).
    let cookie = open_session(&state, &user).await?;
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]))
}

/// A free generated username on this server (ADR-003). A clash with an
/// existing account is retried; a few in a row means something else is wrong.
async fn generated_root_id(state: &AppState, host: &str) -> Result<RootId, ApiError> {
    for _ in 0..5 {
        let username = brigid_identity::generate_username().map_err(|e| internal!(e))?;
        let taken = state
            .store
            .fetch_user_by_username(&username, host)
            .await
            .map_err(|e| internal!(e))?
            .is_some();
        if !taken {
            return Ok(RootId {
                username,
                server: host.to_string(),
            });
        }
    }
    Err(internal!(std::io::Error::other(
        "no free generated username after 5 attempts"
    )))
}

/// `POST /auth/passkeys/add/begin`: start registering one more passkey for
/// the signed-in account (never a new account).
pub async fn add_credential_begin(
    State(state): State<Arc<AppState>>,
    session: AccountSession,
) -> Result<impl IntoResponse, ApiError> {
    let user = session.account;

    // Exclude the user's existing credentials so an authenticator that
    // supports it can refuse to re-enrol a key that's already registered.
    let existing = load_passkeys(&state.store, user.id)
        .await
        .map_err(|e| internal!(e))?;
    let exclude_credentials = existing.iter().map(|p| p.cred_id().clone()).collect();

    let (ccr, reg_state) = state
        .webauthn
        .begin_registration(user.id, &user.username, Some(exclude_credentials))
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
                purpose: RegistrationPurpose::AddPasskey,
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

/// `POST /auth/passkeys/add/finish`
///
/// Finishes the ceremony started by `add_credential_begin`. Ownership was
/// already verified at `begin` time and is bound into the opaque
/// `session_id` (same trust model as `register_finish`/`login_finish`), so
/// this handler does not re-check the caller's token.
pub async fn add_credential_finish(
    State(state): State<Arc<AppState>>,
    Json(body): Json<FinishRegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let pending = take_pending_registration(&state, body.session_id, |p| {
        matches!(p, RegistrationPurpose::AddPasskey)
    })?;

    if pending.created_at.elapsed() > crate::state::PENDING_SESSION_TTL {
        return Err(ApiError::BadRequest("session expired".into()));
    }

    let passkey = state
        .webauthn
        .finish_registration(&pending.state, &body.credential)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let cred = passkey_to_credential(pending.user_id, &passkey).map_err(|e| internal!(e))?;
    state
        .store
        .store_credential(&cred)
        .await
        .map_err(|e| internal!(e))?;
    apply_label(&state, pending.user_id, cred.id, body.label.as_deref()).await?;

    Ok(StatusCode::OK)
}

/// Removes and returns the pending registration `session_id` if it was begun
/// for the purpose `expected` accepts. A session of another kind is left in
/// place and reported as unknown, as a missing one is.
pub(crate) fn take_pending_registration(
    state: &AppState,
    session_id: Uuid,
    expected: impl Fn(&RegistrationPurpose) -> bool,
) -> Result<PendingRegistration, ApiError> {
    let mut map = state
        .pending_registrations
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match map.get(&session_id) {
        Some(p) if expected(&p.purpose) => {}
        _ => return Err(ApiError::BadRequest("unknown session".into())),
    }
    Ok(map.remove(&session_id).expect("checked above"))
}

pub(crate) async fn apply_label(
    state: &AppState,
    user_id: Uuid,
    cred_id: Uuid,
    label: Option<&str>,
) -> Result<(), ApiError> {
    let Some(label) = label else { return Ok(()) };
    state
        .store
        .set_credential_label(user_id, cred_id, label)
        .await
        .map_err(|e| match e {
            brigid_store::Error::InvalidLabel => {
                ApiError::BadRequest("label: at most 64 characters, no control characters".into())
            }
            other => internal!(other),
        })
}

/// `PATCH /auth/passkeys/{id}`: rename a passkey of the signed-in account.
pub async fn rename_passkey(
    State(state): State<Arc<AppState>>,
    session: AccountSession,
    Path(passkey_id): Path<Uuid>,
    Json(body): Json<RenamePasskeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user = session.account;
    state
        .store
        .set_credential_label(user.id, passkey_id, &body.label)
        .await
        .map_err(|e| match e {
            brigid_store::Error::NotFound => ApiError::NotFound,
            brigid_store::Error::InvalidLabel => {
                ApiError::BadRequest("label: at most 64 characters, no control characters".into())
            }
            other => internal!(other),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /auth/login/begin`
pub async fn login_begin(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BeginLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let (rcr, login) = match body.username.as_deref() {
        Some(username) => {
            let root_id =
                RootId::parse(username).map_err(|e| ApiError::BadRequest(e.to_string()))?;
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
            (
                rcr,
                PendingLogin::Named {
                    user_id: user.id,
                    state: auth_state,
                },
            )
        }
        None => {
            let (rcr, auth_state) = state
                .webauthn
                .begin_discoverable_authentication()
                .map_err(|e| internal!(e))?;
            (rcr, PendingLogin::Discoverable(auth_state))
        }
    };

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
                login,
                created_at: Instant::now(),
            },
        );
    }

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

    let (user_id, passkeys, auth_result) = match pending.login {
        PendingLogin::Named {
            user_id,
            state: auth_state,
        } => {
            let mut passkeys = load_passkeys(&state.store, user_id)
                .await
                .map_err(|e| internal!(e))?;
            let result = state
                .webauthn
                .finish_authentication(&mut passkeys, &auth_state, &body.credential)
                .map_err(|_| ApiError::Unauthorized)?;
            (user_id, passkeys, result)
        }
        PendingLogin::Discoverable(auth_state) => {
            // The user handle is only a claim until the assertion verifies
            // against that user's own passkeys.
            let user_id = state
                .webauthn
                .identify_discoverable_user(&body.credential)
                .map_err(|_| ApiError::Unauthorized)?;
            let mut passkeys = load_passkeys(&state.store, user_id)
                .await
                .map_err(|e| internal!(e))?;
            let result = state
                .webauthn
                .finish_discoverable_authentication(&mut passkeys, auth_state, &body.credential)
                .map_err(|_| ApiError::Unauthorized)?;
            (user_id, passkeys, result)
        }
    };

    if auth_result.credential_updated {
        for passkey in &passkeys {
            let cred_id_json =
                serde_json::to_string(passkey.cred_id()).expect("CredentialID always serializes");
            let cred_id = cred_id_json.trim_matches('"').to_string();
            if cred_id == auth_result.credential_id {
                update_passkey(&state.store, user_id, passkey)
                    .await
                    .map_err(|e| internal!(e))?;
                break;
            }
        }
    }

    let user = state
        .store
        .fetch_user(user_id)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::NotFound)?;

    // Accounts created before identities existed get the starter set on
    // their first sign-in (ADR-002).
    let existing = state
        .store
        .fetch_identities(user.id)
        .await
        .map_err(|e| internal!(e))?;
    if existing.is_empty() {
        for identity in crate::routes::identities::starter_identities(user.id) {
            state
                .store
                .store_identity(&identity)
                .await
                .map_err(|e| internal!(e))?;
        }
    }

    // A session, never a token: brig·id's API takes no ID token as a
    // credential, and a relying party gets one only through its own flow
    // (ADR-005).
    let cookie = open_session(&state, &user).await?;
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]))
}

/// `DELETE /auth/passkeys/{id}`: delete a passkey of the signed-in account.
/// Another account's passkey is `404`, like an unknown one.
pub async fn delete_passkey(
    State(state): State<Arc<AppState>>,
    session: AccountSession,
    Path(passkey_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let user_id = session.account.id;

    // brig·id is passkey-only — there is no password or other fallback to
    // sign in with. Deleting the last credential would permanently lock the
    // user out of their own account, so refuse it outright. Checked against
    // the actual credential list (not the delete call's own NotFound) so an
    // unknown passkey_id still reports 404, not a misleading 409.
    let remaining = state
        .store
        .fetch_credentials(user_id)
        .await
        .map_err(|e| internal!(e))?;
    if !remaining.iter().any(|c| c.id == passkey_id) {
        return Err(ApiError::NotFound);
    }
    if remaining.len() <= 1 {
        return Err(ApiError::Conflict("cannot delete your last passkey".into()));
    }

    state
        .store
        .delete_credential(user_id, passkey_id)
        .await
        .map_err(|e| match e {
            brigid_store::Error::NotFound => ApiError::NotFound,
            other => internal!(other),
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /auth/passkeys`: the signed-in account's passkeys.
pub async fn list_passkeys(
    State(state): State<Arc<AppState>>,
    session: AccountSession,
) -> Result<impl IntoResponse, ApiError> {
    let user_id = session.account.id;
    let creds = state
        .store
        .fetch_credentials(user_id)
        .await
        .map_err(|e| internal!(e))?;
    let mut labels = state
        .store
        .fetch_credential_labels(user_id)
        .await
        .map_err(|e| internal!(e))?;
    let summaries: Vec<PasskeySummary> = creds
        .iter()
        .map(|c| PasskeySummary {
            id: c.id,
            label: labels.remove(&c.id),
        })
        .collect();
    Ok((StatusCode::OK, Json(summaries)))
}

/// `POST /auth/logout`: end the session and remove its cookie.
pub async fn logout(
    State(state): State<Arc<AppState>>,
    session: AccountSession,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .delete_session(&session.token)
        .await
        .map_err(|e| internal!(e))?;
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, clear_cookie(&state))],
    ))
}

#[derive(Serialize)]
pub struct SessionResponse {
    /// Unix time the session ends if unused (pushed back by every request).
    pub idle_expires_at: i64,
    /// Unix time the session ends in any case: sign in again then.
    pub expires_at: i64,
}

/// `GET /auth/session`: is the session still good? `200` with its deadlines,
/// or `401` (none, expired, or the account is gone) so the client signs out.
pub async fn session(session: AccountSession) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(SessionResponse {
            idle_expires_at: session.idle_expires_at,
            expires_at: session.expires_at,
        }),
    )
}
