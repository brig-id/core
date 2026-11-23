//! Identity management for an account: `/account/identities`.
//!
//! An identity belongs to a private account. Its name, logo and description
//! are labels for the person. A relying party receives an identifier derived
//! from the identity and, of its attributes, the ones the person accepted to
//! share with it. Every endpoint acts on the account of the session.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use brigid_identity::{Attribute, Attributes};
use brigid_store::{Error as StoreError, Grant, Identity};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    session::Onboarded,
    state::AppState,
};

/// An identity as its own account sees it.
#[derive(Debug, Serialize)]
pub struct IdentityView {
    pub id: Uuid,
    pub name: String,
    pub logo: String,
    pub description: Option<String>,
    /// Claim name to value; an attribute without a value is absent.
    pub attributes: Attributes,
    /// RFC 3339.
    pub created_at: String,
    /// RFC 3339.
    pub updated_at: String,
}

impl From<Identity> for IdentityView {
    fn from(i: Identity) -> Self {
        Self {
            id: i.id,
            name: i.name,
            logo: i.logo,
            description: i.description,
            attributes: i.attributes,
            created_at: i.created_at.format(&Rfc3339).unwrap_or_default(),
            updated_at: i.updated_at.format(&Rfc3339).unwrap_or_default(),
        }
    }
}

/// Create from scratch (`name` and `logo` required) or from a `template`,
/// whose defaults fill whatever the request leaves out.
#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub logo: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Claim name to value.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct TemplateView {
    /// The group it is shown in: `everyday`, `work`, `leisure`, `online`.
    pub group: &'static str,
    pub key: &'static str,
    pub name: &'static str,
    pub logo: &'static str,
    pub description: &'static str,
    /// One of the identities the onboarding proposes to a new account. The
    /// browser creates the ones the person keeps; the server creates none.
    pub starter: bool,
}

/// A new identity of `account_id` with a fresh id (ADR-007: the id is what
/// its VSIDs are derived from).
pub(crate) fn new_identity(
    account_id: Uuid,
    name: String,
    logo: String,
    description: Option<String>,
    attributes: Attributes,
) -> Identity {
    let now = OffsetDateTime::now_utc();
    Identity {
        id: Uuid::new_v4(),
        account_id,
        name,
        logo,
        description,
        attributes,
        created_at: now,
        updated_at: now,
    }
}

/// `GET /account/identity-templates`: the templates offered at creation,
/// the starters first, in the order the onboarding proposes them.
pub async fn list_templates() -> impl IntoResponse {
    let starters = brigid_identity::templates::DEFAULT_TEMPLATE_KEYS;
    let view = |t: &'static brigid_identity::IdentityTemplate| TemplateView {
        group: t.group,
        key: t.key,
        name: t.name,
        logo: t.logo,
        description: t.description,
        starter: starters.contains(&t.key),
    };
    let views: Vec<TemplateView> = brigid_identity::default_templates()
        .chain(
            brigid_identity::TEMPLATES
                .iter()
                .filter(|t| !starters.contains(&t.key)),
        )
        .map(view)
        .collect();
    Json(views)
}

/// Every field is optional; an empty `description` clears it. `attributes`
/// holds the ones to change: a value sets the attribute, an empty one
/// removes it, and the attributes left out stay as they are.
#[derive(Debug, Deserialize)]
pub struct UpdateIdentityRequest {
    pub name: Option<String>,
    pub logo: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

/// The attribute carried by the claim `name`, or the error to answer.
pub(crate) fn attribute_named(name: &str) -> Result<Attribute, ApiError> {
    Attribute::parse(name).ok_or_else(|| ApiError::BadRequest(format!("unknown attribute: {name}")))
}

/// Applies `changes` to `attributes`: a value sets, an empty value removes.
fn apply_attributes(
    attributes: &mut Attributes,
    changes: BTreeMap<String, String>,
) -> Result<(), ApiError> {
    for (name, value) in changes {
        let attribute = attribute_named(&name)?;
        if value.trim().is_empty() {
            attributes.remove(&attribute);
        } else {
            attributes.insert(attribute, value);
        }
    }
    Ok(())
}

fn map_store(e: StoreError) -> ApiError {
    match e {
        StoreError::InvalidIdentity(err) => ApiError::BadRequest(err.to_string()),
        StoreError::NotFound => ApiError::NotFound,
        other => internal!(other),
    }
}

/// `GET /account/identities`
pub async fn list_identities(
    State(state): State<Arc<AppState>>,
    Onboarded(session): Onboarded,
) -> Result<impl IntoResponse, ApiError> {
    let identities = state
        .store
        .fetch_identities(session.account.id)
        .await
        .map_err(map_store)?;
    let views: Vec<IdentityView> = identities.into_iter().map(Into::into).collect();
    Ok((StatusCode::OK, Json(views)))
}

/// `POST /account/identities`
pub async fn create_identity(
    State(state): State<Arc<AppState>>,
    Onboarded(session): Onboarded,
    Json(body): Json<CreateIdentityRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let account_id = session.account.id;

    let template = match body.template.as_deref() {
        Some(key) => Some(
            brigid_identity::template(key)
                .ok_or_else(|| ApiError::BadRequest(format!("unknown template: {key}")))?,
        ),
        None => None,
    };
    let name = body
        .name
        .or_else(|| template.map(|t| t.name.to_string()))
        .ok_or_else(|| ApiError::BadRequest("name is required".into()))?;
    let logo = body
        .logo
        .or_else(|| template.map(|t| t.logo.to_string()))
        .ok_or_else(|| ApiError::BadRequest("logo is required".into()))?;
    let description = body
        .description
        .or_else(|| template.map(|t| t.description.to_string()));
    let mut attributes = Attributes::new();
    apply_attributes(&mut attributes, body.attributes)?;
    let identity = new_identity(account_id, name, logo, description, attributes);
    let id = identity.id;
    state
        .store
        .store_identity(&identity)
        .await
        .map_err(map_store)?;

    let stored = state
        .store
        .fetch_identity(account_id, id)
        .await
        .map_err(map_store)?
        .ok_or(ApiError::NotFound)?;
    Ok((StatusCode::CREATED, Json(IdentityView::from(stored))))
}

/// `PATCH /account/identities/{id}`
pub async fn update_identity(
    State(state): State<Arc<AppState>>,
    Onboarded(session): Onboarded,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateIdentityRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let account_id = session.account.id;

    let mut identity = state
        .store
        .fetch_identity(account_id, id)
        .await
        .map_err(map_store)?
        .ok_or(ApiError::NotFound)?;
    if let Some(name) = body.name {
        identity.name = name;
    }
    if let Some(logo) = body.logo {
        identity.logo = logo;
    }
    if let Some(description) = body.description {
        identity.description = Some(description);
    }
    apply_attributes(&mut identity.attributes, body.attributes)?;
    state
        .store
        .update_identity(&identity)
        .await
        .map_err(map_store)?;

    let stored = state
        .store
        .fetch_identity(account_id, id)
        .await
        .map_err(map_store)?
        .ok_or(ApiError::NotFound)?;
    Ok((StatusCode::OK, Json(IdentityView::from(stored))))
}

/// `DELETE /account/identities/{id}`
pub async fn delete_identity(
    State(state): State<Arc<AppState>>,
    Onboarded(session): Onboarded,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .delete_identity(session.account.id, id)
        .await
        .map_err(map_store)?;
    Ok(StatusCode::NO_CONTENT)
}

/// What an identity gave one application.
#[derive(Debug, Serialize)]
pub struct ApplicationView {
    pub client_id: String,
    /// The name the application is registered under.
    pub name: String,
    /// The first sign-in there (Unix seconds).
    pub linked_at: i64,
    /// The latest sign-in there (Unix seconds).
    pub last_used_at: i64,
    /// The attributes the person accepted to share, with the value that was
    /// accepted. It may differ from the identity's value today: then it is
    /// no longer sent until the person accepts the new one.
    pub shared: Vec<SharedView>,
    /// The attributes the person refused to share.
    pub refused: Vec<Attribute>,
}

#[derive(Debug, Serialize)]
pub struct SharedView {
    pub name: Attribute,
    pub value: String,
    /// When that value was accepted (Unix seconds).
    pub since: i64,
}

impl ApplicationView {
    fn new(grant: Grant, name: String) -> Self {
        let mut shared = Vec::new();
        let mut refused = Vec::new();
        for (attribute, decision) in grant.decisions {
            match decision.value {
                Some(value) => shared.push(SharedView {
                    name: attribute,
                    value,
                    since: decision.at,
                }),
                None => refused.push(attribute),
            }
        }
        Self {
            client_id: grant.client_id,
            name,
            linked_at: grant.created_at,
            last_used_at: grant.last_used_at,
            shared,
            refused,
        }
    }
}

/// `GET /account/identities/{id}/applications`: the applications the
/// identity signed in to and what each one was given, the latest first.
pub async fn list_applications(
    State(state): State<Arc<AppState>>,
    Onboarded(session): Onboarded,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let account_id = session.account.id;
    state
        .store
        .fetch_identity(account_id, id)
        .await
        .map_err(map_store)?
        .ok_or(ApiError::NotFound)?;
    let views: Vec<ApplicationView> = state
        .store
        .grants_of_identity(account_id, id)
        .await
        .map_err(map_store)?
        .into_iter()
        .map(|(grant, name)| ApplicationView::new(grant, name))
        .collect();
    Ok(Json(views))
}

/// `DELETE /account/identities/{id}/applications/{client_id}`: withdraw
/// everything the identity gave the application. The next sign-in there
/// starts from nothing; what the application already received stays with it.
pub async fn withdraw_application(
    State(state): State<Arc<AppState>>,
    Onboarded(session): Onboarded,
    Path((id, client_id)): Path<(Uuid, String)>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .withdraw_grant(session.account.id, id, &client_id, None)
        .await
        .map_err(map_store)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /account/identities/{id}/applications/{client_id}/attributes/{name}`:
/// forget what was decided about one attribute. It is no longer sent, and
/// the person is asked again the next time the application asks for it.
pub async fn withdraw_attribute(
    State(state): State<Arc<AppState>>,
    Onboarded(session): Onboarded,
    Path((id, client_id, name)): Path<(Uuid, String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let attribute = attribute_named(&name)?;
    state
        .store
        .withdraw_grant(session.account.id, id, &client_id, Some(attribute))
        .await
        .map_err(map_store)?;
    Ok(StatusCode::NO_CONTENT)
}
