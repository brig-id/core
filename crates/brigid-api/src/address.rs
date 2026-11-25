//! The address a request comes from: what the rate limits key on, and what
//! sign-ups are counted by (`sign_ups_per_ip_per_day`). Never stored as it
//! is.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{Extensions, HeaderMap, request::Parts},
};

use crate::{error::ApiError, state::AppState};

/// The first address of `x-forwarded-for` when `trust_header` (a reverse
/// proxy that overwrites it stands in front), else the TCP peer. `None`
/// when neither is known: the server was not given the peer address.
pub(crate) fn client_address(
    headers: &HeaderMap,
    extensions: &Extensions,
    trust_header: bool,
) -> Option<String> {
    // Only consulted when a trusted reverse proxy is known to set it (see
    // `AppState::trust_forwarded_for`). Otherwise an attacker could forge
    // the header to evade the limits.
    if trust_header
        && let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    {
        return Some(ip);
    }
    // Real TCP peer address injected by
    // `into_make_service_with_connect_info::<SocketAddr>()`.
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|addr| addr.0.ip().to_string())
}

/// What a request with no known address is keyed on: all such requests
/// share it. In production the server wires `ConnectInfo<SocketAddr>`, so
/// this does not happen; tests (oneshot) and misconfigured servers do.
pub(crate) const UNKNOWN: &str = "0.0.0.0";

/// The address of the request, as the rate limits see it.
pub struct ClientAddress(pub String);

impl FromRequestParts<Arc<AppState>> for ClientAddress {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            client_address(&parts.headers, &parts.extensions, state.trust_forwarded_for)
                .unwrap_or_else(|| UNKNOWN.to_owned()),
        ))
    }
}
