//! Identity management for an account: `/account/identities`.
//!
//! An identity belongs to a private account. Its name and logo are labels for
//! the person: a relying party only ever receives an identifier derived from it
//! (ADR-002). Every endpoint acts on the account of the session (ADR-005).

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use brigid_store::{Error as StoreError, Identity};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    session::AccountSession,
    state::AppState,
};

/// Public shape of an identity. The DID is deliberately not exposed: it is the
/// VSID input and must not travel with display data.
#[derive(Debug, Serialize)]
pub struct IdentityView {
    pub id: Uuid,
    pub name: String,
    pub logo: String,
    pub description: Option<String>,
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
}

#[derive(Debug, Serialize)]
pub struct TemplateView {
    pub key: &'static str,
    pub name: &'static str,
    pub logo: &'static str,
    pub description: &'static str,
}

/// A new identity of `account_id` with a fresh id (ADR-007: the id is what
/// its VSIDs are derived from).
pub(crate) fn new_identity(
    account_id: Uuid,
    name: String,
    logo: String,
    description: Option<String>,
) -> Identity {
    let now = OffsetDateTime::now_utc();
    Identity {
        id: Uuid::new_v4(),
        account_id,
        name,
        logo,
        description,
        created_at: now,
        updated_at: now,
    }
}

/// The starter identities of a new account (ADR-002, core#48).
pub(crate) fn starter_identities(account_id: Uuid) -> Vec<Identity> {
    brigid_identity::default_templates()
        .map(|t| {
            new_identity(
                account_id,
                t.name.to_string(),
                t.logo.to_string(),
                Some(t.description.to_string()),
            )
        })
        .collect()
}

/// `GET /account/identity-templates`: the templates offered at creation.
pub async fn list_templates() -> impl IntoResponse {
    let views: Vec<TemplateView> = brigid_identity::TEMPLATES
        .iter()
        .map(|t| TemplateView {
            key: t.key,
            name: t.name,
            logo: t.logo,
            description: t.description,
        })
        .collect();
    Json(views)
}

/// Every field is optional; an empty `description` clears it.
#[derive(Debug, Deserialize)]
pub struct UpdateIdentityRequest {
    pub name: Option<String>,
    pub logo: Option<String>,
    pub description: Option<String>,
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
    session: AccountSession,
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
    session: AccountSession,
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
    let identity = new_identity(account_id, name, logo, description);
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
    session: AccountSession,
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
    session: AccountSession,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .delete_identity(session.account.id, id)
        .await
        .map_err(map_store)?;
    Ok(StatusCode::NO_CONTENT)
}
