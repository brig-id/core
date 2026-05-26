//! brigid-api: Axum HTTP server wiring all brig·id business logic crates.

pub mod error;
pub mod middleware;
pub mod router;
pub mod state;

pub mod routes;

pub use middleware::AuthenticatedClaims;
pub use router::build_router;
pub use state::AppState;
