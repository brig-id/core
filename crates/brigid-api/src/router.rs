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
    routing::{get, post},
};
use tower_governor::{
    GovernorError, GovernorLayer, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
};
use tower_http::{cors::CorsLayer, set_header::SetResponseHeaderLayer, trace::TraceLayer};
use url::Url;

use crate::{
    routes::{auth, discovery, health},
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
        if self.trust_header {
            if let Some(ip) = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                return Ok(ip);
            }
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
            // Static CSP suitable for the JSON API endpoints currently exposed
            // (no inline scripts, no hydration). When the Leptos SSR UI
            // (`brigid-ui`, Phase 6) is mounted on this router it must replace
            // `script-src 'self'` with a per-response `nonce-<base64>` policy
            // — see AGENTS.md "CSP header" invariant. Tracked in phase-6.md.
            HeaderValue::from_static(
                "default-src 'self'; \
                 script-src 'self'; \
                 style-src 'self'; \
                 img-src 'self' data:; \
                 font-src 'self'; \
                 connect-src 'self'; \
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
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([CONTENT_TYPE, AUTHORIZATION])
    };

    // Rate limiter for /auth/* routes: 1 token every 3 s per IP, burst of 5.
    // Sustained rate = 60s / 3s = 20 req/min per IP, matching the security
    // requirement in AGENTS.md §"Hard security constraints". The previous
    // `.per_second(3)` configured a sustained 3 req/s = 180 req/min, which
    // violated that requirement. `tower_governor::GovernorConfigBuilder` does
    // not expose a sub-per-second helper, so the replenishment cadence is set
    // via `period(Duration)` directly.
    let governor_conf = GovernorConfigBuilder::default()
        .period(Duration::from_secs(3))
        .burst_size(5)
        .key_extractor(ForwardedForExtractor {
            trust_header: state.trust_forwarded_for,
        })
        .finish()
        .unwrap();

    // Protected auth routes with rate limiting.
    let auth_routes = Router::new()
        .route("/auth/register/begin", post(auth::register_begin))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/begin", post(auth::login_begin))
        .route("/auth/login/finish", post(auth::login_finish))
        .route("/auth/logout", post(auth::logout))
        .layer(GovernorLayer::new(governor_conf));

    let discovery_routes = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(discovery::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(discovery::jwks))
        .route("/.well-known/did.json", get(discovery::did_document));

    let health_routes = Router::new()
        .route("/health", get(health::health))
        .route("/ready", get(health::ready));

    Router::new()
        .merge(auth_routes)
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
