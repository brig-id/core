//! Account sessions (ADR-005 §1): a random token in an `HttpOnly` cookie, the
//! account taken from the server-side session, and same-origin checks on
//! requests that change something.

use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, Method, header, request::Parts},
    middleware::Next,
    response::Response,
};
use brigid_store::User;

use crate::{
    error::{ApiError, internal},
    state::AppState,
};

/// The cookie's name: `__Host-` over HTTPS, which browsers only accept with
/// `Secure`, `Path=/` and no `Domain` (so no subdomain can set or read it).
/// Plain HTTP is local development, where a `Secure` cookie would be refused.
pub fn cookie_name(state: &AppState) -> &'static str {
    if state.https() {
        "__Host-brigid_session"
    } else {
        "brigid_session"
    }
}

fn attributes(state: &AppState) -> &'static str {
    if state.https() {
        "; Path=/; HttpOnly; Secure; SameSite=Strict"
    } else {
        "; Path=/; HttpOnly; SameSite=Strict"
    }
}

/// `Set-Cookie` for a new session. `Max-Age` is the absolute lifetime, so the
/// browser forgets the cookie when the session can no longer be used.
pub fn session_cookie(state: &AppState, token: &str) -> HeaderValue {
    let value = format!(
        "{}={token}{}; Max-Age={}",
        cookie_name(state),
        attributes(state),
        state.session_lifetime.as_secs()
    );
    HeaderValue::from_str(&value).expect("token is base64url")
}

/// `Set-Cookie` that removes the session cookie (sign out).
pub fn clear_cookie(state: &AppState) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{}={}; Max-Age=0",
        cookie_name(state),
        attributes(state)
    ))
    .expect("ASCII")
}

/// The session token in the request's `Cookie` header, if any.
pub fn session_token<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
}

/// Opens a session for `account` and returns its `Set-Cookie` header.
pub async fn open_session(state: &AppState, account: &User) -> Result<HeaderValue, ApiError> {
    let token = state
        .store
        .create_session(account.id, state.session_idle, state.session_lifetime)
        .await
        .map_err(|e| internal!(e))?;
    Ok(session_cookie(state, &token))
}

/// The signed-in account of a request, from its session cookie. `401` when
/// there is no cookie, the session is unknown or expired, or the account is
/// gone. Using the session pushes its idle deadline back.
pub struct AccountSession {
    pub account: User,
    /// The session token (to end it at sign-out).
    pub token: String,
    /// Unix time of the passkey ceremony that opened the session.
    pub auth_time: i64,
    /// Unix time the session ends if unused.
    pub idle_expires_at: i64,
    /// Unix time the session ends in any case.
    pub expires_at: i64,
    /// Unix time of the latest passkey ceremony done in this session.
    pub confirmed_at: i64,
    /// Whether the account is an administrator of this server.
    pub admin: bool,
}

impl AccountSession {
    /// The session of a request, from its cookie. `None` when there is no
    /// cookie, the session is unknown or expired, or the account is gone.
    /// Using the session pushes its idle deadline back.
    pub async fn from_headers(
        state: &AppState,
        headers: &HeaderMap,
    ) -> Result<Option<Self>, ApiError> {
        let Some(token) = session_token(headers, cookie_name(state)) else {
            return Ok(None);
        };
        let Some(info) = state
            .store
            .use_session(token, state.session_idle)
            .await
            .map_err(|e| internal!(e))?
        else {
            return Ok(None);
        };
        let Some(account) = state
            .store
            .fetch_user(info.account_id)
            .await
            .map_err(|e| internal!(e))?
        else {
            return Ok(None);
        };
        // A suspended account has no session, whatever cookie it holds.
        let standing = state
            .store
            .account_standing(account.id)
            .await
            .map_err(|e| internal!(e))?
            .unwrap_or_default();
        if standing.suspended {
            return Ok(None);
        }
        Ok(Some(Self {
            account,
            token: token.to_owned(),
            auth_time: info.created_at,
            idle_expires_at: info.idle_expires_at,
            expires_at: info.expires_at,
            confirmed_at: info.confirmed_at,
            admin: standing.admin,
        }))
    }
}

impl FromRequestParts<Arc<AppState>> for AccountSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        Self::from_headers(state, &parts.headers)
            .await?
            .ok_or(ApiError::Unauthorized)
    }
}

/// A signed-in account that finished its onboarding: it has a recovery code.
///
/// An account without one can sign in, manage its passkeys and create its
/// code, and nothing else: no identity, no application. Losing every passkey
/// would otherwise lose the account for good, since nobody else can give
/// access back. `403` until the code exists; `401` without a session.
pub struct Onboarded(pub AccountSession);

impl Onboarded {
    /// Whether `session`'s account has a usable recovery code.
    pub async fn check(state: &AppState, session: &AccountSession) -> Result<bool, ApiError> {
        let status = state
            .store
            .recovery_status(session.account.id)
            .await
            .map_err(|e| internal!(e))?;
        Ok(status.code_created_at.is_some())
    }
}

impl FromRequestParts<Arc<AppState>> for Onboarded {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let session = AccountSession::from_request_parts(parts, state).await?;
        if !Self::check(state, &session).await? {
            return Err(ApiError::RecoveryCodeRequired);
        }
        Ok(Self(session))
    }
}

/// A signed-in administrator. `403` for any other account: what the
/// administration can read is refused to it, not hidden from it.
pub struct Administrator(pub AccountSession);

impl FromRequestParts<Arc<AppState>> for Administrator {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let session = AccountSession::from_request_parts(parts, state).await?;
        if !session.admin {
            return Err(ApiError::Forbidden);
        }
        Ok(Self(session))
    }
}

/// A signed-in administrator who used a passkey in this session a few
/// minutes ago at most: what every administrative change asks for, so that
/// an open, unattended session changes nothing. `403` with the code
/// `confirmation_required` otherwise; `/auth/confirm/*` is the ceremony.
pub struct ConfirmedAdministrator(pub AccountSession);

impl FromRequestParts<Arc<AppState>> for ConfirmedAdministrator {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let Administrator(session) = Administrator::from_request_parts(parts, state).await?;
        let now = helpers4::time::unix_now().map_or(i64::MAX, |secs| secs as i64);
        let ttl = i64::try_from(state.confirmation_ttl.as_secs()).unwrap_or(i64::MAX);
        if now.saturating_sub(session.confirmed_at) >= ttl {
            return Err(ApiError::ConfirmationRequired);
        }
        Ok(Self(session))
    }
}

/// Refuses a request that changes something (any method but GET, HEAD,
/// OPTIONS) unless its `Origin` is this server's: with `SameSite=Strict`, the
/// second barrier against cross-site requests (ADR-005 §1). Browsers send
/// `Origin` on every such request; one without it is refused too.
pub async fn require_same_origin(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return Ok(next.run(request).await);
    }
    let same = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|origin| origin == state.origin());
    if !same {
        return Err(ApiError::Forbidden);
    }
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_session_cookie_among_others() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; __Host-brigid_session=tok; b=2"),
        );
        assert_eq!(session_token(&h, "__Host-brigid_session"), Some("tok"));
        assert_eq!(session_token(&h, "brigid_session"), None);
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-brigid_session="),
        );
        assert_eq!(session_token(&h, "__Host-brigid_session"), None);
    }
}
