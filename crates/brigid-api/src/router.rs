//! Router construction.
//!
//! Assembles all routes, middleware, and security headers into a single
//! [`axum::Router`].

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::ConnectInfo,
    http::{
        HeaderName, HeaderValue, Request,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    routing::{delete, get, patch, post},
};
use tower_governor::{
    GovernorError, GovernorLayer, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
};
use tower_http::{cors::CorsLayer, set_header::SetResponseHeaderLayer, trace::TraceLayer};
use url::Url;

use crate::{
    routes::{auth, discovery, health, identities, recovery},
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

/// Build the Axum router for the brig·id API.
///
/// `cors_origins` is the list of allowed CORS origins. Pass an empty slice to
/// disable CORS (useful in tests).
pub fn build_router(state: Arc<AppState>, cors_origins: &[Url]) -> Router {
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
            // Strict CSP for the routes defined here, which return JSON only:
            // no inline sources are needed. The Qwik UI does emit inline
            // scripts and styles; whoever serves it sets its own CSP on those
            // responses (server-leaf builds it from the UI build's
            // `dist/csp-hashes.json`, allowing exactly those by hash), and
            // `if_not_present` keeps this one off them.
            //
            // img-src/connect-src additionally allow Unsplash: the login/
            // register pages fetch a daily background photo directly from
            // the browser (`app/src/lib/unsplash.ts`) — there's no
            // app-side server to proxy it through, this static UI is served
            // as files by this very binary.
            HeaderValue::from_static(
                "default-src 'self'; \
                 script-src 'self'; \
                 style-src 'self'; \
                 img-src 'self' data: https://images.unsplash.com; \
                 font-src 'self'; \
                 connect-src 'self' https://api.unsplash.com; \
                 frame-ancestors 'none'; \
                 object-src 'none'; \
                 base-uri 'self'",
            ),
        ));

    // CORS — only add if origins are provided.
    let cors = if cors_origins.is_empty() {
        CorsLayer::new()
    } else {
        let origins: Vec<_> = cors_origins
            .iter()
            .map(|u| {
                u.as_str()
                    .trim_end_matches('/')
                    .parse::<HeaderValue>()
                    .expect("CORS origin is not a valid header value — check configuration")
            })
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PATCH,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([CONTENT_TYPE, AUTHORIZATION])
    };

    // Two rate limits, each per client IP.
    //
    // The WebAuthn ceremonies are open to anyone and each one costs a
    // challenge held in memory or a signature check: 20 requests per minute,
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
        // guess: it shares this stricter limit (ADR-004: no lockout).
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
        .route(
            "/account/identity-templates",
            get(identities::list_templates),
        )
        .route(
            "/account/identities",
            get(identities::list_identities).post(identities::create_identity),
        )
        .route(
            "/account/identities/{id}",
            patch(identities::update_identity).delete(identities::delete_identity),
        )
        // Account sessions live in a cookie: every request that changes
        // something must come from this server's own pages (ADR-005 §1).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            session::require_same_origin,
        ))
        .layer(limit(Duration::from_secs(1), 30));

    let discovery_routes = Router::new()
        .route("/.well-known/jwks.json", get(discovery::jwks))
        .route("/.well-known/did.json", get(discovery::did_document));

    let health_routes = Router::new()
        .route("/health", get(health::health))
        .route("/ready", get(health::ready));

    Router::new()
        .merge(ceremony_routes)
        .merge(account_routes)
        .merge(discovery_routes)
        .merge(health_routes)
        // `cors` is added before `security_headers` so that `security_headers`
        // becomes the outermost layer. `CorsLayer` short-circuits preflight
        // OPTIONS requests with its own response *inside* the layer it wraps;
        // if `security_headers` were inside `cors`, those preflight responses
        // would bypass the security headers entirely. Wrapping the other way
        // round guarantees every response — including CORS preflights and
        // CORS-rejected requests — carries the full security header set.
        .layer(cors)
        .layer(security_headers)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
