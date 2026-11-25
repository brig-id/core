//! Application-wide error type and [`axum::response::IntoResponse`] impl.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// All errors that can be returned by the API handlers.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("internal server error")]
    Internal(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error("not found")]
    NotFound,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    /// The account has no recovery code yet: it can do nothing else first.
    #[error("a recovery code is required first")]
    RecoveryCodeRequired,

    /// The server takes no new account (its sign-up policy is `closed`).
    #[error("sign-up is closed on this server")]
    SignupClosed,

    /// The server takes new accounts by invitation, and none was presented.
    #[error("an invitation is required to create an account on this server")]
    InvitationRequired,

    /// A link (setup, administrator, invitation) is unknown, expired, used
    /// up, or not for this.
    #[error("this link is not valid (any more)")]
    LinkInvalid,

    /// The account is suspended by an administrator of this server.
    #[error("this account is suspended")]
    Suspended,

    /// An administrative change needs a passkey ceremony done in this
    /// session a few minutes ago at most.
    #[error("confirm with your passkey")]
    ConfirmationRequired,

    #[error("too many requests")]
    TooManyRequests,

    /// What an account, or an address, may create on this server is used
    /// up (`limit` is its name, `value` its value). `409` for what belongs
    /// to an account, `429` for sign-ups from one address.
    #[error("{}", limit_sentence(*.limit, *.value))]
    LimitReached {
        limit: brigid_store::Limit,
        value: u32,
    },

    /// A limit an administrator set is unknown, or outside 1 to its maximum.
    #[error("{message}")]
    InvalidLimit {
        /// The name given.
        limit: String,
        /// The limit's maximum, when the name is known.
        max: Option<u32>,
        message: String,
    },

    #[error("service unavailable")]
    ServiceUnavailable,
}

/// "This server allows at most 20 identities per account."
fn limit_sentence(limit: brigid_store::Limit, value: u32) -> String {
    use brigid_store::Limit;
    let what = match limit {
        Limit::IdentitiesPerAccount => "identities per account",
        Limit::PasskeysPerAccount => "passkeys per account",
        Limit::SignUpsPerIpPerDay => "new accounts per day from one address",
    };
    format!("this server allows at most {value} {what}")
}

/// A store error as the API answers it: a limit reached is said so, any
/// other failure is internal.
pub(crate) fn from_store(e: brigid_store::Error) -> ApiError {
    match e {
        brigid_store::Error::LimitReached(limit, value) => ApiError::LimitReached { limit, value },
        other => ApiError::Internal(Box::new(other)),
    }
}

impl ApiError {
    /// A stable name for the refusals the interface acts on.
    fn code(&self) -> Option<&'static str> {
        Some(match self {
            ApiError::SignupClosed => "signup_closed",
            ApiError::InvitationRequired => "invitation_required",
            ApiError::LinkInvalid => "link_invalid",
            ApiError::Suspended => "suspended",
            ApiError::ConfirmationRequired => "confirmation_required",
            ApiError::RecoveryCodeRequired => "recovery_code_required",
            ApiError::LimitReached { .. } => "limit_reached",
            ApiError::InvalidLimit { .. } => "invalid_limit",
            _ => return None,
        })
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::Forbidden
            | ApiError::SignupClosed
            | ApiError::InvitationRequired
            | ApiError::LinkInvalid
            | ApiError::Suspended
            | ApiError::ConfirmationRequired
            | ApiError::RecoveryCodeRequired => (StatusCode::FORBIDDEN, self.to_string()),
            ApiError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            ApiError::LimitReached { limit, .. } => (
                if *limit == brigid_store::Limit::SignUpsPerIpPerDay {
                    StatusCode::TOO_MANY_REQUESTS
                } else {
                    StatusCode::CONFLICT
                },
                self.to_string(),
            ),
            ApiError::InvalidLimit { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiError::ServiceUnavailable => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            ApiError::Internal(cause) => {
                // The cause goes to the log only; the client gets a fixed message.
                tracing::error!(error = %cause, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
        };
        // `code` tells the interface which refusal this is, so that it can
        // act on it (run a ceremony, send the person somewhere) without
        // reading the sentence.
        let mut body = match self.code() {
            Some(code) => json!({ "error": message, "code": code }),
            None => json!({ "error": message }),
        };
        // Which limit, so that the interface can say it in its own words.
        match &self {
            ApiError::LimitReached { limit, value } => {
                body["limit"] = json!(limit.name());
                body["value"] = json!(value);
            }
            ApiError::InvalidLimit {
                limit,
                max,
                message,
            } => {
                // `error` is the code here, as the administration's
                // contract says; the sentence is `message`.
                body["error"] = json!("invalid_limit");
                body["message"] = json!(message);
                body["limit"] = json!(limit);
                if let Some(max) = max {
                    body["max"] = json!(max);
                }
            }
            _ => {}
        }
        (status, Json(body)).into_response()
    }
}

/// Convenience macro to box any `Error + Send + Sync` into [`ApiError::Internal`].
macro_rules! internal {
    ($e:expr) => {
        ApiError::Internal(Box::new($e))
    };
}

pub(crate) use internal;
