//! Identity management for an account: `/account/identities`.
//!
//! An identity is what a relying party sees; it belongs to a private account
//! (ADR-002). These endpoints are authorised the same way as the passkey
//! endpoints: the caller names its `user_id` and the handler checks it against
//! the bearer token's VSID. Splitting account sessions from RP tokens is a
//! separate step.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use brigid_identity::{account_subject, identity_vsid};
use brigid_store::{Error as StoreError, Identity};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    middleware::AuthenticatedClaims,
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

#[derive(Debug, Deserialize)]
pub struct AccountQuery {
    pub user_id: Uuid,
}

/// Create from scratch (`name` and `logo` required) or from a `template`,
/// whose defaults fill whatever the request leaves out.
#[derive(Debug, Deserialize)]
pub struct CreateIdentityRequest {
    pub user_id: Uuid,
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

/// Every field but `user_id` is optional; an empty `description` clears it.
#[derive(Debug, Deserialize)]
pub struct UpdateIdentityRequest {
    pub user_id: Uuid,
    pub name: Option<String>,
    pub logo: Option<String>,
    pub description: Option<String>,
}

/// Checks that the bearer token belongs to account `user_id`.
async fn authorize(
    state: &AppState,
    claims: &brigid_oidc::Claims,
    user_id: Uuid,
) -> Result<(), ApiError> {
    let user = state
        .store
        .fetch_user(user_id)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::NotFound)?;
    let expected = account_subject(user.id, &claims.aud, &state.vsid_salt);
    if expected.as_str() != claims.sub {
        return Err(ApiError::Forbidden);
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

/// `GET /account/identities?user_id=`
pub async fn list_identities(
    State(state): State<Arc<AppState>>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Query(q): Query<AccountQuery>,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&state, &claims, q.user_id).await?;
    let identities = state
        .store
        .fetch_identities(q.user_id)
        .await
        .map_err(map_store)?;
    let views: Vec<IdentityView> = identities.into_iter().map(Into::into).collect();
    Ok((StatusCode::OK, Json(views)))
}

/// `POST /account/identities`
pub async fn create_identity(
    State(state): State<Arc<AppState>>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Json(body): Json<CreateIdentityRequest>,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&state, &claims, body.user_id).await?;

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
    let identity = new_identity(body.user_id, name, logo, description);
    let id = identity.id;
    state
        .store
        .store_identity(&identity)
        .await
        .map_err(map_store)?;

    let stored = state
        .store
        .fetch_identity(body.user_id, id)
        .await
        .map_err(map_store)?
        .ok_or(ApiError::NotFound)?;
    Ok((StatusCode::CREATED, Json(IdentityView::from(stored))))
}

/// `PATCH /account/identities/{id}`
pub async fn update_identity(
    State(state): State<Arc<AppState>>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateIdentityRequest>,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&state, &claims, body.user_id).await?;

    let mut identity = state
        .store
        .fetch_identity(body.user_id, id)
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
        .fetch_identity(body.user_id, id)
        .await
        .map_err(map_store)?
        .ok_or(ApiError::NotFound)?;
    Ok((StatusCode::OK, Json(IdentityView::from(stored))))
}

#[derive(Debug, Deserialize)]
pub struct IdentityTokenRequest {
    pub user_id: Uuid,
    /// The relying party that will receive the token (`aud`).
    pub client_id: String,
}

#[derive(Debug, Serialize)]
pub struct IdentityTokenResponse {
    pub id_token: String,
}

/// `POST /account/identities/{id}/token`: an ID token **for this identity**
/// at `client_id` (ADR-002). Its `sub` is the VSID of the identity's DID, so
/// two identities of one account are different subjects at the same relying
/// party, and the account itself is never presented.
pub async fn identity_token(
    State(state): State<Arc<AppState>>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(id): Path<Uuid>,
    Json(body): Json<IdentityTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&state, &claims, body.user_id).await?;
    if body.client_id.is_empty() {
        return Err(ApiError::BadRequest("client_id is required".into()));
    }
    let identity = state
        .store
        .fetch_identity(body.user_id, id)
        .await
        .map_err(map_store)?
        .ok_or(ApiError::NotFound)?;
    let vsid = identity_vsid(identity.id, &body.client_id, &state.vsid_salt);
    let issuer = state.base_url.to_string();
    let issuer = issuer.trim_end_matches('/').to_string();
    let params = brigid_oidc::IssuanceParams {
        vsid: &vsid,
        issuer: &issuer,
        client_id: &body.client_id,
        server: state.host()?,
        ttl_secs: 3600,
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let id_token =
        brigid_oidc::issue_token(&params, &state.oidc_key, now).map_err(|e| internal!(e))?;
    Ok((StatusCode::OK, Json(IdentityTokenResponse { id_token })))
}

/// `DELETE /account/identities/{id}?user_id=`
pub async fn delete_identity(
    State(state): State<Arc<AppState>>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(id): Path<Uuid>,
    Query(q): Query<AccountQuery>,
) -> Result<impl IntoResponse, ApiError> {
    authorize(&state, &claims, q.user_id).await?;
    state
        .store
        .delete_identity(q.user_id, id)
        .await
        .map_err(map_store)?;
    Ok(StatusCode::NO_CONTENT)
}
