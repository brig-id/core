//! The authorization endpoint and the person's answer (ADR-005 §2, ADR-008).
//!
//! A relying party sends the browser to `/authorize`. That navigation comes
//! from another site, so it does not carry the session cookie
//! (`SameSite=Strict`): the request is validated, kept, and the browser is
//! sent to this server's own page, [`UI_PATH`]. From there every call is
//! same-origin and carries the session: the page reads the request, lets the
//! person sign in and choose an identity, and gets back the address to send
//! the browser to.

use std::{collections::HashMap, sync::Arc, time::Instant};

use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use brigid_store::Client;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    routes::identities::IdentityView,
    session::AccountSession,
    state::{AppState, IssuedCode, PendingAuthorization, Prompt},
};

/// The page of this server's interface that answers an authorization
/// request: `?request=<id>` for a request to answer, `?error=<code>` for one
/// that cannot be sent back to the relying party.
pub const UI_PATH: &str = "/continue/";

/// `GET /authorize`
pub async fn begin_get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    begin(&state, &params).await
}

/// `POST /authorize`: the same request, sent as a form.
pub async fn begin_post(
    State(state): State<Arc<AppState>>,
    Form(params): Form<HashMap<String, String>>,
) -> Response {
    begin(&state, &params).await
}

async fn begin(state: &AppState, params: &HashMap<String, String>) -> Response {
    let param = |name: &str| {
        params
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    };

    // Until the client and its redirect URI are known to be registered,
    // nothing is sent anywhere but to this server's own page.
    let client = match param("client_id") {
        Some(id) => state.store.fetch_client(id).await,
        None => Ok(None),
    };
    let client = match client {
        Ok(Some(client)) => client,
        Ok(None) => return see_other(&format!("{UI_PATH}?error=unknown_client")),
        Err(e) => return ApiError::Internal(Box::new(e)).into_response(),
    };
    let Some(redirect_uri) = param("redirect_uri").filter(|uri| registered(&client, uri)) else {
        return see_other(&format!("{UI_PATH}?error=invalid_redirect_uri"));
    };

    // From here an error goes back to the relying party.
    let request_state = param("state");
    let refuse = |error: &str, description: &str| {
        see_other(&error_redirect(
            state,
            redirect_uri,
            request_state,
            error,
            description,
        ))
    };

    if param("request").is_some() {
        return refuse("request_not_supported", "request objects are not supported");
    }
    if param("request_uri").is_some() {
        return refuse(
            "request_uri_not_supported",
            "request objects are not supported",
        );
    }
    if param("response_type") != Some("code") {
        return refuse(
            "unsupported_response_type",
            "only the authorization code flow is offered (response_type=code)",
        );
    }
    if !param("scope").is_some_and(|scope| scope.split(' ').any(|s| s == "openid")) {
        return refuse("invalid_scope", "the openid scope is required");
    }
    let code_challenge = match (param("code_challenge"), param("code_challenge_method")) {
        (Some(challenge), Some("S256")) if brigid_oidc::pkce::is_valid_challenge(challenge) => {
            challenge
        }
        _ => {
            return refuse(
                "invalid_request",
                "PKCE is required: code_challenge with code_challenge_method=S256",
            );
        }
    };
    let Some(prompt) = parse_prompt(param("prompt")) else {
        return refuse("invalid_request", "prompt=none cannot be combined");
    };
    let max_age = match param("max_age").map(str::parse::<i64>) {
        None => None,
        Some(Ok(seconds)) if seconds >= 0 => Some(seconds),
        Some(_) => return refuse("invalid_request", "max_age must be a number of seconds"),
    };

    let held = state.hold_authorization(PendingAuthorization {
        client_id: client.client_id,
        redirect_uri: redirect_uri.to_owned(),
        state: request_state.map(str::to_owned),
        nonce: param("nonce").map(str::to_owned),
        code_challenge: code_challenge.to_owned(),
        prompt,
        max_age,
        created_at: Instant::now(),
        created_unix: now_unix(),
    });
    match held {
        Some(id) => see_other(&format!("{UI_PATH}?request={id}")),
        None => refuse("temporarily_unavailable", "too many requests are waiting"),
    }
}

/// What the page needs to answer an authorization request.
#[derive(Debug, Serialize)]
pub struct RequestView {
    /// The relying party, by the name it was registered with.
    pub client: ClientView,
    /// Whether the request carries a live session.
    pub signed_in: bool,
    /// Whether a passkey ceremony is needed before answering: no session,
    /// `prompt=login`, or a session older than `max_age`.
    pub must_sign_in: bool,
    /// `prompt=none`: show nothing and call `silent`.
    pub silent: bool,
    /// Whether the relying party asked for the choice to be shown even when
    /// one is remembered.
    pub force_choice: bool,
    /// The account's identities. Their names and logos are for the person:
    /// the relying party receives none of this.
    pub identities: Vec<IdentityView>,
    /// The identity last presented to this relying party.
    pub chosen: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct ClientView {
    pub name: String,
}

/// `GET /auth/authorize/{request}`
pub async fn request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RequestView>, ApiError> {
    let pending = state.pending_authorization(&id).ok_or(ApiError::NotFound)?;
    let client = state
        .store
        .fetch_client(&pending.client_id)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::NotFound)?;
    let session = AccountSession::from_headers(&state, &headers).await?;

    let mut view = RequestView {
        client: ClientView { name: client.name },
        signed_in: session.is_some(),
        must_sign_in: must_sign_in(&pending, session.as_ref()),
        silent: pending.prompt == Prompt::None,
        force_choice: pending.prompt == Prompt::Select,
        identities: Vec::new(),
        chosen: None,
    };
    if let Some(session) = session {
        view.identities = state
            .store
            .fetch_identities(session.account.id)
            .await
            .map_err(|e| internal!(e))?
            .into_iter()
            .map(IdentityView::from)
            .collect();
        view.chosen = state
            .store
            .chosen_identity(session.account.id, &pending.client_id)
            .await
            .map_err(|e| internal!(e))?;
    }
    Ok(Json(view))
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    pub identity_id: Uuid,
}

/// Where the page must send the browser.
#[derive(Debug, Serialize)]
pub struct Answer {
    pub redirect_to: String,
}

/// `POST /auth/authorize/{request}/approve`: continue to the relying party
/// as the chosen identity. The choice is remembered for that relying party.
pub async fn approve(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    session: AccountSession,
    Json(body): Json<ApproveRequest>,
) -> Result<Json<Answer>, ApiError> {
    let pending = state.pending_authorization(&id).ok_or(ApiError::NotFound)?;
    if must_sign_in(&pending, Some(&session)) {
        return Err(ApiError::Unauthorized);
    }
    match state
        .store
        .set_chosen_identity(session.account.id, &pending.client_id, body.identity_id)
        .await
    {
        Ok(()) => {}
        Err(brigid_store::Error::NotFound) => return Err(ApiError::NotFound),
        Err(e) => return Err(internal!(e)),
    }
    // Answered once: a second call finds nothing.
    let pending = state.take_authorization(&id).ok_or(ApiError::NotFound)?;
    Ok(Json(Answer {
        redirect_to: grant(&state, &pending, &session, body.identity_id)?,
    }))
}

/// `POST /auth/authorize/{request}/deny`: go back to the relying party
/// without signing in.
pub async fn deny(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Answer>, ApiError> {
    let pending = state.take_authorization(&id).ok_or(ApiError::NotFound)?;
    Ok(Json(Answer {
        redirect_to: error_redirect(
            &state,
            &pending.redirect_uri,
            pending.state.as_deref(),
            "access_denied",
            "the person did not continue",
        ),
    }))
}

/// `POST /auth/authorize/{request}/silent`: the answer to a `prompt=none`
/// request, from what is already known: a live session that needs no new
/// passkey ceremony, and an identity already chosen for this relying party.
/// Anything missing is an error for the relying party, never a page.
pub async fn silent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Answer>, ApiError> {
    let pending = state.pending_authorization(&id).ok_or(ApiError::NotFound)?;
    if pending.prompt != Prompt::None {
        return Err(ApiError::BadRequest(
            "this request asked for an interactive answer".into(),
        ));
    }
    let pending = state.take_authorization(&id).ok_or(ApiError::NotFound)?;
    let refuse = |error: &str, description: &str| {
        Json(Answer {
            redirect_to: error_redirect(
                &state,
                &pending.redirect_uri,
                pending.state.as_deref(),
                error,
                description,
            ),
        })
    };

    let session = AccountSession::from_headers(&state, &headers).await?;
    let Some(session) = session.filter(|s| !must_sign_in(&pending, Some(s))) else {
        return Ok(refuse("login_required", "the person must sign in"));
    };
    let chosen = state
        .store
        .chosen_identity(session.account.id, &pending.client_id)
        .await
        .map_err(|e| internal!(e))?;
    let Some(identity_id) = chosen else {
        return Ok(refuse(
            "interaction_required",
            "the person must choose an identity",
        ));
    };
    Ok(Json(Answer {
        redirect_to: grant(&state, &pending, &session, identity_id)?,
    }))
}

/// Issue a code for `identity_id` and build the address that carries it
/// back to the relying party.
fn grant(
    state: &AppState,
    pending: &PendingAuthorization,
    session: &AccountSession,
    identity_id: Uuid,
) -> Result<String, ApiError> {
    let code = state
        .issue_code(IssuedCode {
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge.clone(),
            nonce: pending.nonce.clone(),
            account_id: session.account.id,
            identity_id,
            auth_time: session.auth_time,
            created_at: Instant::now(),
        })
        .ok_or(ApiError::TooManyRequests)?;
    let mut pairs = vec![("code", code.as_str())];
    if let Some(s) = pending.state.as_deref() {
        pairs.push(("state", s));
    }
    pairs.push(("iss", state.issuer()));
    Ok(with_query(&pending.redirect_uri, &pairs))
}

/// Whether a passkey ceremony is needed before this request can be answered.
fn must_sign_in(pending: &PendingAuthorization, session: Option<&AccountSession>) -> bool {
    let Some(session) = session else { return true };
    if pending.prompt == Prompt::Login && session.auth_time < pending.created_unix {
        return true;
    }
    pending
        .max_age
        .is_some_and(|max_age| now_unix() - session.auth_time > max_age)
}

/// `prompt` is a space-separated list. `none` stands alone or the request is
/// invalid (`None`); `login` wins over `consent` and `select_account`, which
/// both mean "show the choice"; unknown values are ignored.
fn parse_prompt(value: Option<&str>) -> Option<Prompt> {
    let values: Vec<&str> = value
        .unwrap_or("")
        .split(' ')
        .filter(|v| !v.is_empty())
        .collect();
    if values.contains(&"none") {
        return (values.len() == 1).then_some(Prompt::None);
    }
    Some(if values.contains(&"login") {
        Prompt::Login
    } else if values.contains(&"consent") || values.contains(&"select_account") {
        Prompt::Select
    } else {
        Prompt::Default
    })
}

/// Exact comparison with the registered redirect URIs: no prefix, no
/// normalisation, no wildcard.
fn registered(client: &Client, redirect_uri: &str) -> bool {
    client.redirect_uris.iter().any(|uri| uri == redirect_uri)
}

/// The relying party's redirect URI with an OAuth error. `iss` lets the
/// relying party check who answers (RFC 9207).
fn error_redirect(
    state: &AppState,
    redirect_uri: &str,
    request_state: Option<&str>,
    error: &str,
    description: &str,
) -> String {
    let mut pairs = vec![("error", error), ("error_description", description)];
    if let Some(s) = request_state {
        pairs.push(("state", s));
    }
    pairs.push(("iss", state.issuer()));
    with_query(redirect_uri, &pairs)
}

/// `uri` with `pairs` appended to its query. `uri` is a registered redirect
/// URI, validated as an absolute URL when the client was created.
fn with_query(uri: &str, pairs: &[(&str, &str)]) -> String {
    match Url::parse(uri) {
        Ok(mut url) => {
            url.query_pairs_mut().extend_pairs(pairs);
            url.into()
        }
        Err(_) => uri.to_owned(),
    }
}

/// `303 See Other`, never cached, and without a referrer: the address of an
/// authorization request does not leak to the next page.
fn see_other(location: &str) -> Response {
    let Ok(location) = HeaderValue::from_str(location) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            ),
        ],
    )
        .into_response()
}

fn now_unix() -> i64 {
    helpers4::time::unix_now().map_or(0, |secs| secs as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_values() {
        assert_eq!(parse_prompt(None), Some(Prompt::Default));
        assert_eq!(parse_prompt(Some("")), Some(Prompt::Default));
        assert_eq!(parse_prompt(Some("login")), Some(Prompt::Login));
        assert_eq!(parse_prompt(Some("consent")), Some(Prompt::Select));
        assert_eq!(parse_prompt(Some("select_account")), Some(Prompt::Select));
        assert_eq!(parse_prompt(Some("login consent")), Some(Prompt::Login));
        assert_eq!(parse_prompt(Some("none")), Some(Prompt::None));
        assert_eq!(parse_prompt(Some("none login")), None);
        assert_eq!(parse_prompt(Some("something")), Some(Prompt::Default));
    }

    #[test]
    fn query_is_appended_and_escaped() {
        assert_eq!(
            with_query(
                "https://shop.example/cb",
                &[("code", "a b"), ("state", "x&y")]
            ),
            "https://shop.example/cb?code=a+b&state=x%26y"
        );
        assert_eq!(
            with_query("https://shop.example/cb?keep=1", &[("code", "c")]),
            "https://shop.example/cb?keep=1&code=c"
        );
    }
}
