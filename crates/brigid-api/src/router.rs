//! Router construction.
//!
//! Assembles all routes, middleware, and security headers into a single
//! [`axum::Router`].

use std::{net::SocketAddr, sync::Arc};

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

/// Key extractor that reads the first IP from `x-forwarded-for`.
///
/// Falls back to the real TCP peer address (via [`ConnectInfo`]) when the header
/// is absent (e.g. direct connections, tests). This ensures each distinct client
/// gets its own rate-limit bucket even without a proxy.
#[derive(Clone)]
struct ForwardedForExtractor;

impl KeyExtractor for ForwardedForExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        // Prefer x-forwarded-for (set by the Caddy reverse proxy in production).
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
        // Fall back to the real TCP peer address injected by
        // `into_make_service_with_connect_info::<SocketAddr>()`.
        if let Some(addr) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
            return Ok(addr.0.ip().to_string());
        }
        // Last resort for environments where connect_info is not wired up.
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

    // Rate limiter for /auth/* routes: 1 token per 3 s per IP, burst of 5 ≈ 20 req/min.
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(3)
        .burst_size(5)
        .key_extractor(ForwardedForExtractor)
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
        .layer(security_headers)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
