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
    /// Unix time the session ends if unused.
    pub idle_expires_at: i64,
    /// Unix time the session ends in any case.
    pub expires_at: i64,
}

impl FromRequestParts<Arc<AppState>> for AccountSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = session_token(&parts.headers, cookie_name(state))
            .ok_or(ApiError::Unauthorized)?
            .to_owned();
        let info = state
            .store
            .use_session(&token, state.session_idle)
            .await
            .map_err(|e| internal!(e))?
            .ok_or(ApiError::Unauthorized)?;
        let account = state
            .store
            .fetch_user(info.account_id)
            .await
            .map_err(|e| internal!(e))?
            .ok_or(ApiError::Unauthorized)?;
        Ok(Self {
            account,
            token,
            idle_expires_at: info.idle_expires_at,
            expires_at: info.expires_at,
        })
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
