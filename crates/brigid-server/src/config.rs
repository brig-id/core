//! Configuration loading, the same for every edition of the server.
//!
//! Configuration is assembled from up to two sources, in this order
//! (later entries override earlier ones):
//! 1. A TOML file, **only when** an explicit `--config <path>` is supplied
//!    on the command line (`load(Some(path))`). There is **no** auto-discovery
//!    of a configuration file from the working directory.
//! 2. Environment variables with the `BRIGID_` prefix, using `__` as the
//!    nesting separator (e.g. `BRIGID_SERVER__PORT=9000` → `server.port`).
//!
//! When `--config` is omitted, the configuration comes entirely from
//! `BRIGID_*` environment variables (plus the `#[serde(default)]` defaults).
//!
//! `BRIGID_MASTER_KEY` is **always** read separately from the environment —
//! it must never appear in the configuration file.

use std::path::PathBuf;

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;

/// Top-level configuration struct.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    // `database` and `security` are optional in the source: the module-level
    // docs promise an env-only deployment path, which only works if these
    // tables can be entirely absent from the TOML / `BRIGID_*` environment.
    // Their fields all carry per-field defaults, and the sub-structs impl
    // `Default`, so figment can synthesise them from nothing.
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

/// HTTP/TLS server settings.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Bind host (e.g. `"0.0.0.0"` or `"127.0.0.1"`).
    #[serde(default = "default_host")]
    pub host: String,

    /// Bind port (e.g. `8080`).
    #[serde(default = "default_port")]
    pub port: u16,

    /// Public domain name — used as the WebAuthn RP ID and OIDC issuer.
    pub domain: String,

    /// Override for the public base URL (e.g. `"https://example.com"`).
    ///
    /// When set, this is used as the OIDC issuer and WebAuthn origin instead
    /// of the value inferred from `domain` and `port`. Use this when the server
    /// binary runs behind a reverse proxy that handles TLS and serves on a
    /// different public port (e.g. Caddy on 443 → the server on 8080).
    pub public_url: Option<String>,

    /// Path to the TLS certificate PEM file. Required for HTTPS.
    pub tls_cert: Option<PathBuf>,

    /// Path to the TLS private key PEM file. Required for HTTPS.
    pub tls_key: Option<PathBuf>,

    /// Path to the pre-built Qwik UI static files (e.g. `"ui/dist"`).
    ///
    /// When set, requests that do not match any API route are served from this
    /// directory. Unknown paths fall back to `index.html` (SPA routing).
    /// Omit or leave unset to disable static file serving (API-only mode).
    #[serde(default)]
    pub ui_dist_dir: Option<PathBuf>,

    /// Port of the internal Prometheus listener (`GET /metrics`), on the same
    /// host as the main listener. Unset: no metrics listener. Never publish
    /// this port; scrape it from the internal network only.
    #[serde(default)]
    pub metrics_port: Option<u16>,
}

/// Database settings.
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// SQLite database file path (e.g. `"/data/brigid.db"`).
    /// Use `":memory:"` for in-memory databases (tests only).
    #[serde(default = "default_db_path")]
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
        }
    }
}

/// Security settings.
#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    /// An account session ends after this many seconds without use
    /// (default: 3600). Each request pushes the deadline back.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_seconds: u64,

    /// An account session ends this many seconds after the passkey ceremony
    /// that opened it, used or not (default: 43200, 12 hours).
    #[serde(default = "default_session_lifetime")]
    pub session_lifetime_seconds: u64,

    /// Allowed CORS origins (e.g. `["https://example.com"]`).
    #[serde(default)]
    pub cors_origins: Vec<String>,

    /// Rate-limit per client IP taken from `X-Forwarded-For` instead of the
    /// TCP peer address.
    ///
    /// Set to `true` when the server is only reachable through a reverse proxy
    /// that overwrites that header (Caddy does): every request then comes
    /// from the proxy's address, and without this all clients share a single
    /// rate-limit bucket. Leave `false` when clients connect to the server
    /// directly, where they could forge the header to dodge the limit.
    #[serde(default)]
    pub trust_forwarded_for: bool,

    /// How many days the log of administrative actions is kept (default:
    /// 365). Older entries are deleted. The log names accounts by an
    /// identifier: it is kept as long as it serves, not for ever.
    #[serde(default = "default_admin_log_retention_days")]
    pub admin_log_retention_days: u64,

    /// How long a passkey ceremony covers administrative changes, in
    /// seconds (default: 300). An administrator who signed in or confirmed
    /// longer ago than this is asked for their passkey again before a
    /// change is made.
    #[serde(default = "default_admin_confirmation_seconds")]
    pub admin_confirmation_seconds: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            session_ttl_seconds: default_session_ttl(),
            session_lifetime_seconds: default_session_lifetime(),
            cors_origins: Vec::new(),
            trust_forwarded_for: false,
            admin_log_retention_days: default_admin_log_retention_days(),
            admin_confirmation_seconds: default_admin_confirmation_seconds(),
        }
    }
}

fn default_admin_confirmation_seconds() -> u64 {
    300
}

fn default_admin_log_retention_days() -> u64 {
    365
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_db_path() -> String {
    "/data/brigid.db".to_string()
}

fn default_session_ttl() -> u64 {
    3600
}

fn default_session_lifetime() -> u64 {
    12 * 3600
}

/// The configuration sections. An environment variable configures the server
/// only if, after its prefix, it starts with one of these followed by `__`:
/// `BRIGID_MASTER_KEY` and other `BRIGID_*` variables that are not settings
/// never enter the configuration tree.
const SECTIONS: [&str; 3] = ["server", "database", "security"];

/// Environment settings under `prefix`: `<PREFIX>SECTION__KEY`.
fn env_settings(prefix: &'static str) -> Env {
    Env::prefixed(prefix)
        .filter(|key| {
            let key = key.as_str().to_ascii_lowercase();
            SECTIONS.iter().any(|section| {
                key.strip_prefix(section)
                    .is_some_and(|rest| rest.starts_with("__"))
            })
        })
        .split("__")
}

/// Builds the shared TOML+env figment used by both [`load`] and
/// [`load_database`], so the two never drift on precedence/prefix rules.
fn figment(config_path: Option<&std::path::Path>) -> Figment {
    let mut figment = Figment::new();
    if let Some(path) = config_path {
        figment = figment.merge(Toml::file(path));
    }
    figment.merge(env_settings("BRIGID_"))
}

/// Load the merged configuration.
///
/// `config_path` is optional — when `None`, configuration is read entirely
/// from `BRIGID_*` environment variables (intended for container deployments
/// where TOML files complicate secret management).
#[allow(clippy::result_large_err)] // figment::Error is inherently large; not reducible.
pub fn load(config_path: Option<&std::path::Path>) -> Result<Config, figment::Error> {
    figment(config_path).extract()
}

/// Load just [`DatabaseConfig`] — used by `rotate-key`, which needs the
/// database path and nothing else. Extracting `Config` in full would demand
/// `server.domain` (required, no default) even though rotate-key never
/// touches the server/TLS/CORS settings that field and its siblings exist
/// for.
///
/// `.focus("database")` matters here: the shared figment tree is shaped for
/// `Config` as a whole, so `BRIGID_DATABASE__PATH` nests under a `database`
/// key (`{"database": {"path": ...}}`) rather than sitting at the top level.
/// Extracting `DatabaseConfig` straight from that tree would look for a
/// top-level `path` key, silently miss it, and fall back to
/// `default_db_path()` instead of erroring — `.focus` re-roots the tree at
/// `database` first so the field actually lines up.
#[allow(clippy::result_large_err)]
pub fn load_database(
    config_path: Option<&std::path::Path>,
) -> Result<DatabaseConfig, figment::Error> {
    figment(config_path).focus("database").extract()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use figment::providers::Serialized;

    fn minimal() -> serde_json::Value {
        serde_json::json!({
            "server": { "domain": "localhost" },
            "database": {},
            "security": {}
        })
    }

    fn load_value(v: serde_json::Value) -> Config {
        Figment::new()
            .merge(Serialized::defaults(v))
            .extract()
            .expect("config parse failed")
    }

    #[test]
    fn defaults_are_applied() {
        let cfg = load_value(minimal());
        assert_eq!(cfg.server.host, "0.0.0.0");
        assert_eq!(cfg.server.port, 8080);
        assert_eq!(cfg.security.session_ttl_seconds, 3600);
        assert!(cfg.security.cors_origins.is_empty());
        assert!(!cfg.security.trust_forwarded_for);
        assert!(cfg.server.tls_cert.is_none());
        assert!(cfg.server.tls_key.is_none());
    }

    #[test]
    fn sections_can_be_entirely_absent() {
        // The `minimal()` fixture sends empty `database` / `security` tables.
        // A real configuration file is also allowed to omit those tables entirely
        // (the entire `[database]` or `[security]` header may be missing).
        // This test pins that behaviour so a future refactor of `Config`
        // cannot accidentally make those tables structurally required.
        let cfg = load_value(serde_json::json!({
            "server": { "domain": "localhost" }
        }));
        assert_eq!(cfg.server.host, "0.0.0.0");
        assert_eq!(cfg.server.port, 8080);
        // Defaults must apply for the omitted sections just like for empty ones.
        assert_eq!(cfg.security.session_ttl_seconds, 3600);
        assert!(cfg.security.cors_origins.is_empty());
        assert!(!cfg.database.path.is_empty());
    }

    #[test]
    fn domain_is_required() {
        let result: Result<Config, _> = Figment::new()
            .merge(Serialized::defaults(serde_json::json!({
                "server": {},
                "database": {},
                "security": {}
            })))
            .extract();
        assert!(result.is_err(), "missing domain must produce an error");
    }

    #[test]
    fn custom_values_are_respected() {
        let cfg = load_value(serde_json::json!({
            "server": {
                "host": "127.0.0.1",
                "port": 9090,
                "domain": "example.com",
                "tls_cert": "/certs/cert.pem",
                "tls_key": "/certs/key.pem"
            },
            "database": { "path": "/data/brigid.db" },
            "security": {
                "session_ttl_seconds": 7200,
                "cors_origins": ["https://example.com"]
            }
        }));
        assert_eq!(cfg.server.host, "127.0.0.1");
        assert_eq!(cfg.server.port, 9090);
        assert_eq!(cfg.server.domain, "example.com");
        assert_eq!(cfg.security.session_ttl_seconds, 7200);
        assert_eq!(cfg.security.cors_origins, ["https://example.com"]);
        assert!(cfg.server.tls_cert.is_some());
    }

    #[test]
    fn ui_dist_dir_defaults_to_none() {
        let cfg = load_value(minimal());
        assert!(cfg.server.ui_dist_dir.is_none());
    }

    #[test]
    fn ui_dist_dir_is_parsed_when_set() {
        let cfg = load_value(serde_json::json!({
            "server": { "domain": "localhost", "ui_dist_dir": "/app/ui/dist" },
            "database": {},
            "security": {}
        }));
        assert_eq!(
            cfg.server.ui_dist_dir.as_deref(),
            Some(std::path::Path::new("/app/ui/dist")),
        );
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail closure must return figment::Error.
    fn env_vars_override_toml_defaults() {
        // Validates that environment variables in the BRIGID_SECTION__KEY format
        // correctly override TOML defaults via figment's Env provider.
        // Jail serialises env-var access to prevent interference with parallel tests.
        figment::Jail::expect_with(|jail| {
            jail.set_env("BRIGID_SERVER__HOST", "10.0.0.1");
            jail.set_env("BRIGID_SERVER__PORT", "9999");
            jail.set_env("BRIGID_SERVER__DOMAIN", "env.example.com");
            jail.set_env("BRIGID_DATABASE__PATH", "/tmp/env-test.db");
            jail.set_env("BRIGID_SECURITY__SESSION_TTL_SECONDS", "7200");
            jail.set_env("BRIGID_SECURITY__TRUST_FORWARDED_FOR", "true");

            let cfg: Config = Figment::new()
                .merge(Serialized::defaults(minimal()))
                .merge(env_settings("BRIGID_"))
                .extract()?;

            assert_eq!(cfg.server.host, "10.0.0.1");
            assert_eq!(cfg.server.port, 9999);
            assert_eq!(cfg.server.domain, "env.example.com");
            assert_eq!(cfg.database.path, "/tmp/env-test.db");
            assert_eq!(cfg.security.session_ttl_seconds, 7200);
            assert!(cfg.security.trust_forwarded_for);
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail closure must return figment::Error.
    fn cors_origins_can_be_set_via_env() {
        // `cors_origins` is a `Vec<String>`. Figment's Env provider with
        // `split("__")` accepts a TOML-array-literal-encoded string for
        // sequence fields (e.g. `["https://a","https://b"]`); the
        // `deploy/compose.yaml` template relies on this encoding to push the
        // production origin list through `BRIGID_SECURITY__CORS_ORIGINS`.
        figment::Jail::expect_with(|jail| {
            jail.set_env(
                "BRIGID_SECURITY__CORS_ORIGINS",
                "[\"https://a.example\",\"https://b.example\"]",
            );
            let cfg: Config = Figment::new()
                .merge(Serialized::defaults(minimal()))
                .merge(env_settings("BRIGID_"))
                .extract()?;

            assert_eq!(
                cfg.security.cors_origins,
                vec![
                    "https://a.example".to_string(),
                    "https://b.example".to_string(),
                ]
            );
            Ok(())
        });
    }

    /// `BRIGID_MASTER_KEY` shares the prefix of the settings and must never
    /// become one.
    #[test]
    #[allow(clippy::result_large_err)]
    fn only_settings_are_read_from_the_environment() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("BRIGID_MASTER_KEY", "ab".repeat(32));
            jail.set_env("BRIGID_MASTER_KEY_FILE", "/run/secrets/key");
            jail.set_env("BRIGID_SERVER__DOMAIN", "id.example.com");
            jail.set_env("BRIGID_SERVER__PORT", "9001");
            jail.set_env("BRIGID_SECURITY__ADMIN_LOG_RETENTION_DAYS", "180");
            // A setting of an earlier version, left in a deployment: ignored.
            jail.set_env("BRIGID_SECURITY__SIGNUP_OPEN", "false");

            let figment = figment(None);
            assert!(figment.find_value("master_key").is_err());
            assert!(figment.find_value("master_key_file").is_err());

            let cfg: Config = figment.extract()?;
            assert_eq!(cfg.server.domain, "id.example.com");
            assert_eq!(cfg.server.port, 9001);
            assert_eq!(cfg.security.admin_log_retention_days, 180);
            Ok(())
        });
    }

    #[test]
    fn the_administration_log_is_kept_a_year_by_default() {
        let cfg: Config = Figment::from(Serialized::defaults(minimal()))
            .extract()
            .unwrap();
        assert_eq!(cfg.security.admin_log_retention_days, 365);
    }

    #[test]
    fn a_passkey_ceremony_covers_administrative_changes_for_five_minutes_by_default() {
        let cfg: Config = Figment::from(Serialized::defaults(minimal()))
            .extract()
            .unwrap();
        assert_eq!(cfg.security.admin_confirmation_seconds, 300);
    }
}
