//! Router construction.
//!
//! Assembles all routes, middleware, and security headers into a single
//! [`axum::Router`].

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::ConnectInfo,
    http::{HeaderName, HeaderValue, Request, header::ACCESS_CONTROL_ALLOW_ORIGIN},
    routing::{delete, get, patch, post, put},
};
use tower_governor::{
    GovernorError, GovernorLayer, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
};
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};

use crate::{
    routes::{account, admin, auth, authorize, discovery, health, identities, recovery, token},
    session,
    state::AppState,
};

/// Key extractor that reads the first IP from `x-forwarded-for` when the
/// deployment topology trusts a reverse proxy to set that header. Otherwise
/// it ignores client-supplied headers and keys solely on the TCP peer address.
///
/// Falls back to the real TCP peer address (via [`ConnectInfo`]) when the
/// header is absent or untrusted (e.g. direct connections, tests). This
/// ensures each distinct client gets its own rate-limit bucket and prevents
/// header-forgery rate-limit bypass.
#[derive(Clone)]
struct ForwardedForExtractor {
    trust_header: bool,
}

impl KeyExtractor for ForwardedForExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        // Only consult x-forwarded-for when a trusted reverse proxy is known to
        // set it (see `AppState::trust_forwarded_for`). Otherwise an attacker
        // could forge the header to evade rate limits.
        if self.trust_header
            && let Some(ip) = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        {
            return Ok(ip);
        }
        // Real TCP peer address injected by
        // `into_make_service_with_connect_info::<SocketAddr>()`.
        if let Some(addr) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
            return Ok(addr.0.ip().to_string());
        }
        // No identifying information for this request. In production the
        // server wires `ConnectInfo<SocketAddr>` via
        // `into_make_service_with_connect_info::<SocketAddr>()` so this
        // branch is unreachable; if it ever fires it means the server is
        // misconfigured and every anonymous request would share one global
        // rate-limit bucket (one client can then throttle every other
        // client). Emit a loud warning so operators surface and fix it.
        // Tests (oneshot, no `ConnectInfo`) and dev environments still get
        // a key so the request can be served.
        tracing::warn!(
            "ForwardedForExtractor: neither a trusted x-forwarded-for header \
             nor ConnectInfo<SocketAddr> is available; falling back to a \
             shared rate-limit bucket. Wire `into_make_service_with_connect_info` \
             in the server to restore per-IP rate limiting."
        );
        Ok("0.0.0.0".to_string())
    }
}

/// Build the Axum router for the brig·id API. The interface is served from
/// the same origin: the account's routes answer no other one. The token
/// endpoint and the keys answer any origin, for pages that sign in.
pub fn build_router(state: Arc<AppState>) -> Router {
    // Security headers applied to every response.
    let security_headers = tower::ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            // The routes defined here answer with JSON or a redirect, never
            // with a page: nothing may be loaded, framed or submitted from
            // one of their responses. Whoever serves the interface sets the
            // interface's own policy on those responses (the server builds it
            // from the build's `dist/csp-hashes.json`), and `if_not_present`
            // keeps this one off them.
            HeaderValue::from_static(
                "default-src 'none'; \
                 frame-ancestors 'none'; \
                 base-uri 'none'; \
                 form-action 'none'",
            ),
        ));

    // Two rate limits, each per client IP.
    //
    // The WebAuthn ceremonies are open to anyone and each one costs a
    // challenge kept for minutes or a signature check: 20 requests per minute,
    // in bursts of 5 (a sign-up followed by a sign-in is 4).
    //
    // The account routes need a session and are what the UI calls on every
    // page (session check, lists, edits): 60 per minute, in bursts of 30.
    // Sharing the ceremonies' quota would throttle a user who has just
    // signed in.
    let limit = |period: Duration, burst: u32| {
        GovernorLayer::new(
            GovernorConfigBuilder::default()
                .period(period)
                .burst_size(burst)
                .key_extractor(ForwardedForExtractor {
                    trust_header: state.trust_forwarded_for,
                })
                .finish()
                .expect("period and burst are non-zero"),
        )
    };

    let ceremony_routes = Router::new()
        .route("/auth/register/begin", post(auth::register_begin))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/begin", post(auth::login_begin))
        .route("/auth/login/finish", post(auth::login_finish))
        // Carries no token: the pending ceremony was authorised at `begin`.
        .route(
            "/auth/passkeys/add/finish",
            post(auth::add_credential_finish),
        )
        // Recovery is a ceremony too, and its code is what an attacker would
        // guess: it shares this stricter limit (spec `protocol.md` §7: no lockout).
        .route("/auth/recovery/begin", post(recovery::begin))
        .route("/auth/recovery/finish", post(recovery::finish))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            session::require_same_origin,
        ))
        .layer(limit(Duration::from_secs(3), 5));

    let account_routes = Router::new()
        .route("/auth/logout", post(auth::logout))
        .route("/auth/session", get(auth::session))
        .route("/auth/server", get(auth::server_info))
        .route("/auth/passkeys", get(auth::list_passkeys))
        .route(
            "/auth/passkeys/{id}",
            delete(auth::delete_passkey).patch(auth::rename_passkey),
        )
        .route("/auth/passkeys/add/begin", post(auth::add_credential_begin))
        .route(
            "/account/recovery-code",
            get(recovery::status).post(recovery::create_code),
        )
        // Confirming, in the open session, that the person is there.
        .route("/auth/confirm/begin", post(account::confirm_begin))
        .route("/auth/confirm/finish", post(account::confirm_finish))
        // Administration. Reading needs an administrator; every change also
        // needs a passkey ceremony a few minutes old at most.
        .route("/admin/claim", post(admin::claim))
        .route("/admin/accounts", get(admin::list_accounts))
        .route("/admin/accounts/{id}", delete(admin::delete_account))
        .route("/admin/accounts/{id}/suspend", post(admin::suspend))
        .route("/admin/accounts/{id}/unsuspend", post(admin::unsuspend))
        .route("/admin/accounts/{id}/administrator", put(admin::set_role))
        .route(
            "/admin/applications",
            get(admin::list_applications).post(admin::register_application),
        )
        .route(
            "/admin/applications/{client_id}",
            delete(admin::remove_application),
        )
        .route(
            "/admin/applications/{client_id}/attributes",
            put(admin::set_application_attributes),
        )
        .route(
            "/admin/described",
            get(admin::described).put(admin::set_described),
        )
        .route("/admin/described/list", put(admin::set_described_list))
        .route("/admin/sign-up", get(admin::signup).put(admin::set_signup))
        .route("/admin/invitations", post(admin::invite))
        .route("/admin/invitations/{id}", delete(admin::revoke_invitation))
        .route("/admin/log", get(admin::read_log))
        // Leaving: a passkey ceremony of its own, then nothing is left.
        .route("/account/delete/begin", post(account::delete_begin))
        .route("/account/delete/finish", post(account::delete_finish))
        .route(
            "/account/identities",
            get(identities::list_identities).post(identities::create_identity),
        )
        .route(
            "/account/identities/{id}",
            patch(identities::update_identity).delete(identities::delete_identity),
        )
        // What an identity gave each application, and its withdrawal.
        .route(
            "/account/identities/{id}/applications",
            get(identities::list_applications),
        )
        .route(
            "/account/identities/{id}/applications/{client_id}",
            delete(identities::withdraw_application),
        )
        .route(
            "/account/identities/{id}/applications/{client_id}/attributes/{name}",
            delete(identities::withdraw_attribute),
        )
        // The person's answer to an authorization request (spec `protocol.md` §6),
        // from this server's own page.
        .route("/auth/authorize/{request}", get(authorize::request))
        .route(
            "/auth/authorize/{request}/approve",
            post(authorize::approve),
        )
        .route("/auth/authorize/{request}/deny", post(authorize::deny))
        .route("/auth/authorize/{request}/silent", post(authorize::silent))
        // Account sessions live in a cookie: every request that changes
        // something must come from this server's own pages (spec `protocol.md` §5).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            session::require_same_origin,
        ))
        .layer(limit(Duration::from_secs(1), 30));

    // What relying parties call. A public client runs in a browser, on
    // another origin: these responses may be read from anywhere. None of them
    // depends on a cookie: the token endpoint is protected by the code, the
    // PKCE verifier and the client secret, the rest is public.
    let readable_anywhere = || {
        SetResponseHeaderLayer::overriding(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        )
    };

    // A relying party sends the browser here, from its own site: no
    // same-origin check. Each request that passes validation is held in
    // memory until the person answers, hence a limit of its own.
    let authorization_routes = Router::new()
        .route(
            "/authorize",
            get(authorize::begin_get).post(authorize::begin_post),
        )
        .layer(limit(Duration::from_secs(1), 30));

    // Called by relying parties' servers, many people behind one address:
    // 10 per second, in bursts of 100. A code has 256 random bits and is
    // taken out at its first presentation; the limit protects resources.
    let token_routes = Router::new()
        .route("/token", post(token::token))
        .layer(readable_anywhere())
        .layer(limit(Duration::from_millis(100), 100));

    let discovery_routes = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(discovery::jwks))
        .layer(readable_anywhere());

    let health_routes = Router::new()
        .route("/health", get(health::health))
        .route("/ready", get(health::ready));

    Router::new()
        .merge(ceremony_routes)
        .merge(account_routes)
        .merge(authorization_routes)
        .merge(token_routes)
        .merge(discovery_routes)
        .merge(health_routes)
        .layer(security_headers)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
