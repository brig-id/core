//! brigid-store: zero-trust storage for brig·id, on SQLite or PostgreSQL.
//!
//! All sensitive fields are encrypted with AES-256-GCM before INSERT.
//! A raw dump of the database must never reveal readable secrets.
//!
//! One store, two databases (spec `forest.md` §3). Every statement is
//! written once and runs on both: parameters are `$1, $2…`, columns are
//! text, 64-bit integers or bytes, a truth value comes back as 0 or 1 and
//! never as a boolean, and nothing is used that only one of them knows.
//! Only the schema is written twice, and a test holds the second to the
//! first (`migrations-postgres/` is `migrations/` with three type names
//! changed). The whole test suite runs on both.

pub mod admin;
pub mod error;
pub mod model;
pub mod store;

pub use error::{Error, Result};
pub use model::{
    AccountStanding, AccountSummary, AcmeSecret, AdminAction, AdminLogEntry, ApplicationType,
    Client, ClientAuth, ClientDocument, ClientList, ClientPolicy, Credential, Decision, Grant,
    Identity, Link, LinkKind, RecoveryStatus, SignupPolicy, StoredOidcKey, User,
};
pub use store::{EncryptedStore, SessionInfo, fetch_user, fetch_user_by_username, store_user};

/// SQLx migrator — embeds all `migrations/` SQL files at compile time.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// The same schema as PostgreSQL holds it: `migrations-postgres/`.
#[cfg(feature = "postgres")]
pub static MIGRATOR_POSTGRES: sqlx::migrate::Migrator = sqlx::migrate!("./migrations-postgres");

/// Whether `database_url` names a PostgreSQL database.
pub fn is_postgres(database_url: &str) -> bool {
    database_url.starts_with("postgres:") || database_url.starts_with("postgresql:")
}

/// Where tests keep their data.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    /// The address of an empty database for one test: SQLite in memory, or,
    /// when `BRIGID_TEST_POSTGRES` names a PostgreSQL database, a schema of
    /// its own in it. The same tests run on both.
    pub async fn url() -> String {
        let Ok(base) = std::env::var("BRIGID_TEST_POSTGRES") else {
            return "sqlite::memory:".to_owned();
        };
        sqlx::any::install_default_drivers();
        let schema = format!("t{}", uuid::Uuid::new_v4().simple());
        let admin = sqlx::AnyPool::connect(&base)
            .await
            .expect("BRIGID_TEST_POSTGRES names a database that answers");
        // The schema's name is drawn here, never input.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .expect("a schema for the test");
        admin.close().await;
        format!("{base}?options=-c%20search_path%3D{schema}")
    }
}
