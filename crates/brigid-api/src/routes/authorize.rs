//! The authorization endpoint and the person's answer.
//!
//! A relying party sends the browser to `/authorize`. That navigation comes
//! from another site, so it does not carry the session cookie
//! (`SameSite=Strict`): the request is validated, kept, and the browser is
//! sent to this server's own page, [`UI_PATH`]. From there every call is
//! same-origin and carries the session: the page reads the request, lets the
//! person sign in, choose an identity and decide which of the attributes
//! asked for they share, and gets back the address to send the browser to.
//!
//! An attribute reaches a relying party on three conditions, checked in
//! [`standing`]: its registration lets it ask, this request asks, and the
//! person accepted the value the identity has now.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};

use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use brigid_identity::{Attribute, Attributes, Need, Scope};
use brigid_store::{Client, Grant, Identity};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    routes::identities::{IdentityView, attribute_named},
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
    let scopes: Vec<&str> = param("scope").unwrap_or("").split(' ').collect();
    if !scopes.contains(&"openid") {
        return refuse("invalid_scope", "the openid scope is required");
    }
    // A scope that carries attributes asks for the ones of it that the
    // application is registered for. Registered for none, it asked for more
    // than it may: refused, not ignored. Scopes this server does not know
    // are ignored, as OpenID Connect recommends.
    let mut asked = BTreeMap::new();
    for scope in scopes.iter().filter_map(|s| Scope::parse(s)) {
        let before = asked.len();
        asked.extend(
            client
                .attributes
                .iter()
                .filter(|(attribute, _)| attribute.scope() == scope)
                .map(|(attribute, need)| (*attribute, *need)),
        );
        if asked.len() == before {
            return refuse(
                "invalid_scope",
                &format!(
                    "this application is not registered to ask for the {} scope",
                    scope.as_str()
                ),
            );
        }
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
        asked,
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
    /// The account's identities, with their attributes. Their names and
    /// logos are for the person: the relying party receives none of this.
    pub identities: Vec<IdentityView>,
    /// The identity last presented to this relying party.
    pub chosen: Option<Uuid>,
    /// The attributes the relying party asks for. Empty when it asks for
    /// the identifier only.
    pub asked: Vec<AskedView>,
    /// Per identity, what the person already decided about the attributes
    /// asked for: `true` when they accepted the value the identity has now,
    /// `false` when they refused. An attribute that is absent is undecided:
    /// never asked, or accepted with a value that changed since.
    pub decisions: BTreeMap<Uuid, BTreeMap<Attribute, bool>>,
}

#[derive(Debug, Serialize)]
pub struct AskedView {
    pub name: Attribute,
    /// Whether the relying party needs it: refusing it stops the sign-in.
    pub required: bool,
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
        asked: pending
            .asked
            .iter()
            .map(|(attribute, need)| AskedView {
                name: *attribute,
                required: *need == Need::Required,
            })
            .collect(),
        decisions: BTreeMap::new(),
    };
    if let Some(session) = session {
        let identities = state
            .store
            .fetch_identities(session.account.id)
            .await
            .map_err(|e| internal!(e))?;
        if !pending.asked.is_empty() {
            let grants = state
                .store
                .grants_for_client(session.account.id, &pending.client_id)
                .await
                .map_err(|e| internal!(e))?;
            for grant in &grants {
                let Some(identity) = identities.iter().find(|i| i.id == grant.identity_id) else {
                    continue;
                };
                let decided: BTreeMap<Attribute, bool> = pending
                    .asked
                    .keys()
                    .filter_map(|attribute| {
                        let current = identity.attributes.get(attribute).map(String::as_str);
                        if current.is_some() && grant.shared(*attribute) == current {
                            Some((*attribute, true))
                        } else if grant.refused(*attribute) {
                            Some((*attribute, false))
                        } else {
                            None
                        }
                    })
                    .collect();
                view.decisions.insert(identity.id, decided);
            }
        }
        view.identities = identities.into_iter().map(IdentityView::from).collect();
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
    /// The attributes, of the ones asked for, that the person accepts to
    /// share, by claim name. The others asked for are refused.
    #[serde(default)]
    pub attributes: Vec<String>,
}

/// Where the page must send the browser.
#[derive(Debug, Serialize)]
pub struct Answer {
    pub redirect_to: String,
}

/// `POST /auth/authorize/{request}/approve`: continue to the relying party
/// as the chosen identity, sharing the attributes accepted. The choice and
/// the decisions are remembered for that relying party.
///
/// Refusing an optional attribute continues without it. Refusing a required
/// one is a conflict (409): the request stays, for another answer or for
/// `deny`.
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
    let account_id = session.account.id;
    let identity = state
        .store
        .fetch_identity(account_id, body.identity_id)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::NotFound)?;

    // What the person decides now, about each attribute asked for.
    let accepted = body
        .attributes
        .iter()
        .map(|name| attribute_named(name))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(extra) = accepted.iter().find(|a| !pending.asked.contains_key(a)) {
        return Err(ApiError::BadRequest(format!(
            "{extra} was not asked for by this request"
        )));
    }
    let mut decided = BTreeMap::new();
    for (attribute, need) in &pending.asked {
        let value = identity.attributes.get(attribute);
        if accepted.contains(attribute) {
            let value = value.ok_or_else(|| {
                ApiError::BadRequest(format!("this identity has no {attribute} to share"))
            })?;
            decided.insert(*attribute, Some(value.clone()));
        } else if *need == Need::Required {
            return Err(ApiError::Conflict(format!(
                "{attribute} is required by this application"
            )));
        } else if value.is_some() {
            decided.insert(*attribute, None);
        }
        // Optional, and the identity has none: nothing was refused.
    }

    // Answered once: a second call finds nothing.
    let pending = state.take_authorization(&id).ok_or(ApiError::NotFound)?;
    match state
        .store
        .set_chosen_identity(account_id, &pending.client_id, identity.id)
        .await
    {
        Ok(()) => {}
        Err(brigid_store::Error::NotFound) => return Err(ApiError::NotFound),
        Err(e) => return Err(internal!(e)),
    }
    let recorded = state
        .store
        .record_grant(account_id, identity.id, &pending.client_id, &decided)
        .await
        .map_err(|e| internal!(e))?;
    // What is sent is read back from what was recorded, not from the body.
    let standing = standing(&pending.asked, &identity, Some(&recorded));
    Ok(Json(Answer {
        redirect_to: grant(&state, &pending, &session, identity.id, standing.share)?,
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
/// passkey ceremony, an identity already chosen for this relying party, and
/// a decision already made about every attribute asked for. Anything
/// missing is an error for the relying party, never a page.
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
    let identity = match chosen {
        Some(identity_id) => state
            .store
            .fetch_identity(session.account.id, identity_id)
            .await
            .map_err(|e| internal!(e))?,
        None => None,
    };
    let Some(identity) = identity else {
        return Ok(refuse(
            "interaction_required",
            "the person must choose an identity",
        ));
    };
    let grants = state
        .store
        .grants_for_client(session.account.id, &pending.client_id)
        .await
        .map_err(|e| internal!(e))?;
    let recorded = grants.iter().find(|g| g.identity_id == identity.id);
    let standing = standing(&pending.asked, &identity, recorded);
    if !standing.undecided.is_empty() {
        return Ok(refuse(
            "consent_required",
            "the person must decide what to share",
        ));
    }
    // The sign-in is recorded; no decision changes.
    state
        .store
        .record_grant(
            session.account.id,
            identity.id,
            &pending.client_id,
            &BTreeMap::new(),
        )
        .await
        .map_err(|e| internal!(e))?;
    Ok(Json(Answer {
        redirect_to: grant(&state, &pending, &session, identity.id, standing.share)?,
    }))
}

/// Where a request for attributes stands for one identity.
#[derive(Debug, Default, PartialEq, Eq)]
struct Standing {
    /// What is sent: asked for, and accepted with the value the identity
    /// has now.
    share: Attributes,
    /// What still needs the person: asked for, and neither accepted with
    /// today's value nor settled otherwise.
    undecided: Vec<Attribute>,
}

/// Compares what a request asks (`asked`) with what `identity` has and what
/// its `grant` for the relying party records.
///
/// - Accepted, and the accepted value is the identity's value now: shared.
///   The person accepted a value, not a field name: after a change, the
///   earlier acceptance counts for nothing.
/// - Optional, and refused or absent from the identity: settled, not shared.
/// - Anything else is undecided, a required attribute the identity lacks
///   included: nothing but the person can settle it.
fn standing(
    asked: &BTreeMap<Attribute, Need>,
    identity: &Identity,
    grant: Option<&Grant>,
) -> Standing {
    let mut standing = Standing::default();
    for (attribute, need) in asked {
        let current = identity.attributes.get(attribute);
        let accepted = grant.and_then(|g| g.shared(*attribute));
        match current {
            Some(value) if accepted == Some(value.as_str()) => {
                standing.share.insert(*attribute, value.clone());
            }
            _ if *need == Need::Optional
                && (current.is_none() || grant.is_some_and(|g| g.refused(*attribute))) => {}
            _ => standing.undecided.push(*attribute),
        }
    }
    standing
}

/// Issue a code for `identity_id`, which will give a token carrying
/// `attributes`, and build the address that takes it back to the relying
/// party.
fn grant(
    state: &AppState,
    pending: &PendingAuthorization,
    session: &AccountSession,
    identity_id: Uuid,
    attributes: Attributes,
) -> Result<String, ApiError> {
    let code = state
        .issue_code(IssuedCode {
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge.clone(),
            nonce: pending.nonce.clone(),
            account_id: session.account.id,
            identity_id,
            attributes,
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
    fn what_is_shared_is_what_was_accepted_with_todays_value() {
        use brigid_store::Decision;
        use time::OffsetDateTime;

        let identity = |attributes: &[(Attribute, &str)]| Identity {
            id: Uuid::from_bytes([1; 16]),
            account_id: Uuid::from_bytes([2; 16]),
            name: "Work".into(),
            logo: "icon:ph:briefcase".into(),
            description: None,
            attributes: attributes
                .iter()
                .map(|(a, v)| (*a, (*v).to_owned()))
                .collect(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let grant = |decisions: &[(Attribute, Option<&str>)]| Grant {
            identity_id: Uuid::from_bytes([1; 16]),
            client_id: "shop".into(),
            decisions: decisions
                .iter()
                .map(|(a, v)| {
                    (
                        *a,
                        Decision {
                            value: v.map(str::to_owned),
                            at: 0,
                        },
                    )
                })
                .collect(),
            created_at: 0,
            last_used_at: 0,
        };
        let asked = BTreeMap::from([
            (Attribute::Email, Need::Required),
            (Attribute::GivenName, Need::Optional),
        ]);
        let ada = identity(&[
            (Attribute::Email, "ada@example.org"),
            (Attribute::GivenName, "Ada"),
            (Attribute::FamilyName, "Lovelace"),
        ]);

        // Nothing recorded: everything asked is undecided, nothing is sent.
        let s = standing(&asked, &ada, None);
        assert!(s.share.is_empty());
        assert_eq!(s.undecided, [Attribute::GivenName, Attribute::Email]);

        // Accepted with today's values: sent. What was not asked is not
        // sent, accepted or not.
        let all = grant(&[
            (Attribute::Email, Some("ada@example.org")),
            (Attribute::GivenName, Some("Ada")),
            (Attribute::FamilyName, Some("Lovelace")),
        ]);
        let s = standing(&asked, &ada, Some(&all));
        assert!(s.undecided.is_empty());
        assert_eq!(
            s.share,
            Attributes::from([
                (Attribute::Email, "ada@example.org".to_owned()),
                (Attribute::GivenName, "Ada".to_owned()),
            ])
        );

        // The value changed since: the earlier acceptance counts for nothing.
        let moved = identity(&[
            (Attribute::Email, "ada@new.example"),
            (Attribute::GivenName, "Ada"),
        ]);
        let s = standing(&asked, &moved, Some(&all));
        assert_eq!(s.undecided, [Attribute::Email]);
        assert!(!s.share.contains_key(&Attribute::Email));

        // An optional attribute refused is settled; a required one is not.
        let refused = grant(&[(Attribute::Email, None), (Attribute::GivenName, None)]);
        let s = standing(&asked, &ada, Some(&refused));
        assert!(s.share.is_empty());
        assert_eq!(s.undecided, [Attribute::Email]);

        // An identity without an optional attribute has nothing to decide;
        // without a required one, the person must do something.
        let bare = identity(&[]);
        let s = standing(&asked, &bare, None);
        assert!(s.share.is_empty());
        assert_eq!(s.undecided, [Attribute::Email]);

        // No attribute asked: nothing shared, whatever is recorded.
        let s = standing(&BTreeMap::new(), &ada, Some(&all));
        assert_eq!(s, Standing::default());
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
