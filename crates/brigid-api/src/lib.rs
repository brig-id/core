//! brigid-api: Axum HTTP server wiring all brig·id business logic crates.

pub mod described;
pub mod error;
pub mod router;
pub mod session;
pub mod state;

pub mod routes;

pub use router::build_router;
pub use routes::admin::{administrator_link, setup_link};
pub use session::AccountSession;
pub use state::AppState;
