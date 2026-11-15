//! Administration: `/admin/…`.
//!
//! An administrator runs the server: accounts, the role, applications, who
//! may sign up. What an administrator can reach stops at the account. **No
//! endpoint here returns an identity, a label, an attribute, or where an
//! identity is used**, and none can give access back to an account.
//!
//! - Reading needs an administrator's session.
//! - Every change also needs a passkey ceremony done in that session a few
//!   minutes ago at most ([`ConfirmedAdministrator`]), and is written to the
//!   log.
//!
//! The log names accounts by their identifier. Names are looked up when it
//! is read, so an entry about a deleted account names nobody; and entries
//! older than the retention period are deleted.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use brigid_identity::{Attribute, Need};
use brigid_store::{AdminAction, Client, Error as StoreError, Link, LinkKind, SignupPolicy};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::{
    error::{ApiError, internal},
    session::{Administrator, ConfirmedAdministrator, Onboarded},
    state::{AppState, OPERATOR_LINK_TTL},
};

/// An invitation lasts seven days unless its maker says otherwise.
const INVITATION_DAYS: u32 = 7;
/// The longest an invitation can last, and the most accounts it can create.
const INVITATION_MAX_DAYS: u32 = 90;
const INVITATION_MAX_USES: u32 = 100;
/// How many entries of the log one request returns.
const LOG_PAGE: u32 = 200;

/// Writes an administrative action to the log, after deleting the entries
/// older than the retention period. A failure to log is logged for the
/// operator and does not undo the action.
pub(crate) async fn log(
    state: &AppState,
    action: &str,
    actor: Option<Uuid>,
    account: Option<Uuid>,
    detail: Option<String>,
) {
    let now = helpers4::time::unix_now().map_or(0, |secs| secs as i64);
    let keep = i64::try_from(state.admin_log_retention.as_secs()).unwrap_or(i64::MAX);
    let written = async {
        state
            .store
            .purge_admin_log(now.saturating_sub(keep))
            .await?;
        state
            .store
            .log_admin_action(&AdminAction {
                action: action.to_owned(),
                actor,
                account,
                detail,
            })
            .await
    };
    if let Err(e) = written.await {
        tracing::error!(error = %e, action, "an administrative action could not be logged");
    }
}

/// A setup link for a server that has no account yet: the earlier one is
/// revoked, so a restart renews it. `None` once an account exists: the
/// first administrator is then made with [`administrator_link`].
pub async fn setup_link(
    store: &brigid_store::EncryptedStore,
) -> Result<Option<String>, StoreError> {
    if store.count_accounts().await? > 0 {
        return Ok(None);
    }
    store.revoke_links(LinkKind::Setup).await?;
    let (_, token) = store
        .create_link(LinkKind::Setup, 1, OPERATOR_LINK_TTL, None)
        .await?;
    Ok(Some(token.to_string()))
}

/// A link that grants the administrator role to the signed-in account that
/// opens it: for a server that has accounts and no administrator, or whose
/// administrators all lost their passkeys. Made on the machine; reaching it
/// is the proof of being the operator.
pub async fn administrator_link(
    store: &brigid_store::EncryptedStore,
) -> Result<String, StoreError> {
    let (_, token) = store
        .create_link(LinkKind::Admin, 1, OPERATOR_LINK_TTL, None)
        .await?;
    store
        .log_admin_action(&AdminAction {
            action: "administrator.link".into(),
            actor: None,
            account: None,
            detail: None,
        })
        .await?;
    Ok(token.to_string())
}

// -- Becoming an administrator ---------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ClaimRequest {
    pub link: String,
}

/// `POST /admin/claim`: the signed-in account presents a link made on the
/// machine and becomes an administrator.
pub async fn claim(
    State(state): State<Arc<AppState>>,
    Onboarded(session): Onboarded,
    Json(body): Json<ClaimRequest>,
) -> Result<impl IntoResponse, ApiError> {
    match state
        .store
        .claim_administrator(&body.link, session.account.id)
        .await
    {
        Ok(()) => {}
        Err(StoreError::LinkSpent) => return Err(ApiError::LinkInvalid),
        Err(e) => return Err(internal!(e)),
    }
    log(
        &state,
        "administrator.claimed",
        None,
        Some(session.account.id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// -- Accounts ----------------------------------------------------------------------

/// An account as an administrator sees it. Nothing of its identities.
#[derive(Debug, Serialize)]
pub struct AccountView {
    pub id: Uuid,
    /// The generated username.
    pub username: String,
    /// RFC 3339.
    pub created_at: String,
    pub admin: bool,
    /// Unix seconds since when it is suspended.
    pub suspended_at: Option<i64>,
    /// Unix seconds.
    pub last_sign_in_at: Option<i64>,
    pub passkeys: i64,
    pub recovery_code: bool,
    /// Whether this is the account of the session: it is not suspended or
    /// deleted from here.
    pub own: bool,
}

/// `GET /admin/accounts`
pub async fn list_accounts(
    State(state): State<Arc<AppState>>,
    Administrator(session): Administrator,
) -> Result<impl IntoResponse, ApiError> {
    let accounts = state
        .store
        .list_accounts()
        .await
        .map_err(|e| internal!(e))?;
    let views: Vec<AccountView> = accounts
        .into_iter()
        .map(|a| AccountView {
            own: a.id == session.account.id,
            id: a.id,
            username: a.username,
            created_at: a.created_at.format(&Rfc3339).unwrap_or_default(),
            admin: a.admin,
            suspended_at: a.suspended_at,
            last_sign_in_at: a.last_sign_in_at,
            passkeys: a.passkeys,
            recovery_code: a.recovery_code,
        })
        .collect();
    Ok(Json(views))
}

fn account_error(e: StoreError) -> ApiError {
    match e {
        StoreError::NotFound => ApiError::NotFound,
        StoreError::LastAdministrator => ApiError::Conflict(
            "this is the last administrator who can sign in: name another one first".into(),
        ),
        other => internal!(other),
    }
}

/// An administrator does not suspend or delete their own account from the
/// administration: the first would lock them out at once, and the second is
/// done from their own account page, with what it says.
fn not_own(session_account: Uuid, id: Uuid) -> Result<(), ApiError> {
    if session_account == id {
        return Err(ApiError::Conflict(
            "this is your own account: it is not suspended or deleted from here".into(),
        ));
    }
    Ok(())
}

/// `POST /admin/accounts/{id}/suspend`
pub async fn suspend(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    not_own(session.account.id, id)?;
    state
        .store
        .suspend_account(id)
        .await
        .map_err(account_error)?;
    log(
        &state,
        "account.suspend",
        Some(session.account.id),
        Some(id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /admin/accounts/{id}/unsuspend`
pub async fn unsuspend(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .unsuspend_account(id)
        .await
        .map_err(account_error)?;
    log(
        &state,
        "account.unsuspend",
        Some(session.account.id),
        Some(id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct RoleRequest {
    pub admin: bool,
}

/// `PUT /admin/accounts/{id}/administrator`: grant or withdraw the role.
/// An administrator may give up their own, unless they are the last.
pub async fn set_role(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Path(id): Path<Uuid>,
    Json(body): Json<RoleRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .set_administrator(id, body.admin)
        .await
        .map_err(account_error)?;
    log(
        &state,
        if body.admin {
            "administrator.grant"
        } else {
            "administrator.withdraw"
        },
        Some(session.account.id),
        Some(id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /admin/accounts/{id}`: delete an account and everything recorded
/// about it. It cannot be undone, and gives nobody access to anything.
pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    not_own(session.account.id, id)?;
    if !state
        .store
        .remove_account(id)
        .await
        .map_err(account_error)?
    {
        return Err(ApiError::NotFound);
    }
    // The entry keeps the identifier of an account that no longer exists:
    // it names nobody.
    log(
        &state,
        "account.delete",
        Some(session.account.id),
        Some(id),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// -- Applications ------------------------------------------------------------------

/// A registered application. Never its secret, of which only a hash exists.
#[derive(Debug, Serialize)]
pub struct ApplicationView {
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// Whether it authenticates with a secret.
    pub confidential: bool,
    /// What it may ask people to share, and whether it needs each one.
    pub attributes: BTreeMap<Attribute, Need>,
    /// Unix seconds.
    pub created_at: i64,
}

impl From<Client> for ApplicationView {
    fn from(c: Client) -> Self {
        Self {
            client_id: c.client_id,
            name: c.name,
            redirect_uris: c.redirect_uris,
            confidential: c.confidential,
            attributes: c.attributes,
            created_at: c.created_at,
        }
    }
}

/// `GET /admin/applications`
pub async fn list_applications(
    State(state): State<Arc<AppState>>,
    Administrator(_): Administrator,
) -> Result<impl IntoResponse, ApiError> {
    let views: Vec<ApplicationView> = state
        .store
        .list_clients()
        .await
        .map_err(|e| internal!(e))?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(Json(views))
}

#[derive(Debug, Deserialize)]
pub struct RegisterApplication {
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// `false` for an application that cannot keep a secret (it runs in a
    /// browser or on a phone).
    #[serde(default = "yes")]
    pub confidential: bool,
    #[serde(default)]
    pub attributes: BTreeMap<Attribute, Need>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct RegisteredApplication {
    #[serde(flatten)]
    pub application: ApplicationView,
    /// The secret of a confidential application. Shown this once: only its
    /// hash is stored.
    pub client_secret: Option<String>,
}

/// `POST /admin/applications`
pub async fn register_application(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Json(body): Json<RegisterApplication>,
) -> Result<impl IntoResponse, ApiError> {
    let (mut client, secret) = state
        .store
        .create_client(&body.name, &body.redirect_uris, body.confidential)
        .await
        .map_err(|e| match e {
            StoreError::InvalidClient(why) => ApiError::BadRequest(why.to_owned()),
            other => internal!(other),
        })?;
    if !body.attributes.is_empty() {
        state
            .store
            .set_client_attributes(&client.client_id, &body.attributes)
            .await
            .map_err(|e| internal!(e))?;
        client.attributes = body.attributes;
    }
    log(
        &state,
        "application.register",
        Some(session.account.id),
        None,
        Some(client.name.clone()),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(RegisteredApplication {
            application: client.into(),
            client_secret: secret.map(|s| s.to_string()),
        }),
    ))
}

/// `PUT /admin/applications/{client_id}/attributes`: what the application
/// may ask for from now on. This replaces what it could ask before.
pub async fn set_application_attributes(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Path(client_id): Path<String>,
    Json(attributes): Json<BTreeMap<Attribute, Need>>,
) -> Result<impl IntoResponse, ApiError> {
    let client = state
        .store
        .fetch_client(&client_id)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::NotFound)?;
    state
        .store
        .set_client_attributes(&client_id, &attributes)
        .await
        .map_err(|e| internal!(e))?;
    log(
        &state,
        "application.attributes",
        Some(session.account.id),
        None,
        Some(client.name),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /admin/applications/{client_id}`: nobody signs in to it through
/// this server any more, and what was recorded about it is removed.
pub async fn remove_application(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Path(client_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let client = state
        .store
        .fetch_client(&client_id)
        .await
        .map_err(|e| internal!(e))?
        .ok_or(ApiError::NotFound)?;
    state
        .store
        .delete_client(&client_id)
        .await
        .map_err(|e| internal!(e))?;
    log(
        &state,
        "application.remove",
        Some(session.account.id),
        None,
        Some(client.name),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// -- Who may sign up ---------------------------------------------------------------

/// An invitation as its maker sees it afterwards: never the link.
#[derive(Debug, Serialize)]
pub struct InvitationView {
    pub id: Uuid,
    /// How many more accounts it can create.
    pub uses_left: i64,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
}

impl From<Link> for InvitationView {
    fn from(link: Link) -> Self {
        Self {
            id: link.id,
            uses_left: link.uses_left,
            created_at: link.created_at,
            expires_at: link.expires_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SignupView {
    pub policy: SignupPolicy,
    /// The invitations that can still be used.
    pub invitations: Vec<InvitationView>,
}

/// `GET /admin/sign-up`
pub async fn signup(
    State(state): State<Arc<AppState>>,
    Administrator(_): Administrator,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(SignupView {
        policy: state
            .store
            .signup_policy()
            .await
            .map_err(|e| internal!(e))?,
        invitations: state
            .store
            .list_links(LinkKind::Invitation)
            .await
            .map_err(|e| internal!(e))?
            .into_iter()
            .map(Into::into)
            .collect(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct PolicyRequest {
    pub policy: SignupPolicy,
}

/// `PUT /admin/sign-up`
pub async fn set_signup(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Json(body): Json<PolicyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .store
        .set_signup_policy(body.policy)
        .await
        .map_err(|e| internal!(e))?;
    log(
        &state,
        "signup.policy",
        Some(session.account.id),
        None,
        Some(body.policy.as_str().to_owned()),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct InviteRequest {
    /// How many accounts the invitation can create.
    #[serde(default = "one")]
    pub uses: u32,
    /// How many days it lasts.
    #[serde(default = "invitation_days")]
    pub days: u32,
}

fn one() -> u32 {
    1
}

fn invitation_days() -> u32 {
    INVITATION_DAYS
}

#[derive(Debug, Serialize)]
pub struct Invited {
    #[serde(flatten)]
    pub invitation: InvitationView,
    /// What goes in the address given to the people invited. Shown this
    /// once: only its hash is stored. The server does not know who gets it.
    pub link: String,
}

/// `POST /admin/invitations`
pub async fn invite(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Json(body): Json<InviteRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if !(1..=INVITATION_MAX_USES).contains(&body.uses) {
        return Err(ApiError::BadRequest(format!(
            "an invitation creates 1 to {INVITATION_MAX_USES} accounts"
        )));
    }
    if !(1..=INVITATION_MAX_DAYS).contains(&body.days) {
        return Err(ApiError::BadRequest(format!(
            "an invitation lasts 1 to {INVITATION_MAX_DAYS} days"
        )));
    }
    let (link, token) = state
        .store
        .create_link(
            LinkKind::Invitation,
            body.uses,
            Duration::from_secs(u64::from(body.days) * 24 * 3600),
            Some(session.account.id),
        )
        .await
        .map_err(|e| internal!(e))?;
    log(
        &state,
        "invitation.create",
        Some(session.account.id),
        None,
        Some(format!("{} accounts, {} days", body.uses, body.days)),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(Invited {
            invitation: link.into(),
            link: token.to_string(),
        }),
    ))
}

/// `DELETE /admin/invitations/{id}`
pub async fn revoke_invitation(
    State(state): State<Arc<AppState>>,
    ConfirmedAdministrator(session): ConfirmedAdministrator,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    if !state
        .store
        .revoke_link(LinkKind::Invitation, id)
        .await
        .map_err(|e| internal!(e))?
    {
        return Err(ApiError::NotFound);
    }
    log(
        &state,
        "invitation.revoke",
        Some(session.account.id),
        None,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// -- The log -----------------------------------------------------------------------

/// An entry of the log, with the names it can still be given.
#[derive(Debug, Serialize)]
pub struct LogView {
    /// Unix seconds.
    pub at: i64,
    /// What was done, e.g. `account.suspend`.
    pub action: String,
    /// Who did it: `machine` for the command line, `administrator` for an
    /// account, `deleted` for an account that no longer exists.
    pub by: &'static str,
    /// The administrator's generated username, when the account exists.
    pub by_username: Option<String>,
    /// Whether the action was about an account.
    pub about_account: bool,
    /// That account's generated username, when it still exists.
    pub account_username: Option<String>,
    pub detail: Option<String>,
}

/// `GET /admin/log`: the latest administrative actions, the newest first.
pub async fn read_log(
    State(state): State<Arc<AppState>>,
    Administrator(_): Administrator,
) -> Result<impl IntoResponse, ApiError> {
    let entries = state
        .store
        .admin_log(LOG_PAGE)
        .await
        .map_err(|e| internal!(e))?;
    let mut ids: Vec<Uuid> = entries
        .iter()
        .flat_map(|e| [e.action.actor, e.action.account])
        .flatten()
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let names: BTreeMap<Uuid, String> = state
        .store
        .usernames(&ids)
        .await
        .map_err(|e| internal!(e))?
        .into_iter()
        .collect();
    let views: Vec<LogView> = entries
        .into_iter()
        .map(|e| {
            let by_username = e.action.actor.and_then(|id| names.get(&id).cloned());
            LogView {
                at: e.at,
                by: match (e.action.actor, &by_username) {
                    (None, _) => "machine",
                    (Some(_), Some(_)) => "administrator",
                    (Some(_), None) => "deleted",
                },
                by_username,
                about_account: e.action.account.is_some(),
                account_username: e.action.account.and_then(|id| names.get(&id).cloned()),
                action: e.action.action,
                detail: e.action.detail,
            }
        })
        .collect();
    Ok(Json(views))
}
