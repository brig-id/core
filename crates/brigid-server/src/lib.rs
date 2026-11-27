//! brig·id server: what every edition (seedling, grove, forest) runs, the
//! same code.
//!
//! An edition is a small executable: its name, its version, the interface it
//! carries and where it looks for things on a machine (`Edition`), its own
//! commands next to the shared ones (`Command`), and a call to `run`. What
//! makes editions differ lives in their own repositories: how they are
//! installed and packaged, never how they behave.
//!
//! An edition made of several nodes on one database calls [`run_node`]
//! instead, with [`NodeCommand`]: the same server, which creates nothing
//! when it starts and keeps nothing in its memory that another node needs
//! (`nodes`, spec `forest.md`).
//!
//! # Startup sequence
//!
//! 1. Load and validate configuration (TOML + `BRIGID_*` environment).
//! 2. Load the master key (environment, mounted secret, or the edition's file).
//! 3. Open the database: a single node brings its schema up to date, a node
//!    of several waits for the schema its initialisation made.
//! 4. Read the VSID secret and the OIDC signing keys from it.
//! 5. Build the Axum application (router + state + interface + metrics).
//! 6. Start TLS (if cert/key configured) or plain HTTP server.
//! 7. Await graceful shutdown on `SIGTERM` / `CTRL-C`.

pub mod acme;
pub mod backup;
pub mod config;
pub mod lock;
pub mod metrics;
pub mod nodes;
pub mod owner;
pub mod probe;
pub mod ui;

pub use ui::{EmbeddedUi, Ui, UiError, apply_ui};

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use clap::Subcommand;
use tracing_subscriber::{EnvFilter, fmt};
use url::Url;

use brigid_api::{AppState, build_router};
use brigid_crypto::MasterKey;
use brigid_identity::{Attribute, Need};
use brigid_oidc::OidcSigningKey;
use brigid_store::{ClientList, ClientPolicy, EncryptedStore};
use brigid_webauthn::WebauthnService;

/// What makes an executable one edition of the server.
pub struct Edition {
    /// `seedling`, `grove`: in messages, in logs, and public at
    /// `GET /auth/server`.
    pub name: &'static str,
    /// The edition's version (its `CARGO_PKG_VERSION`), public like its name.
    pub version: &'static str,
    /// The interface the executable carries.
    pub ui: EmbeddedUi,
    /// The configuration file read when `--config` is not given and the file
    /// exists. `None`: configured by its environment alone (a container).
    pub config_path: Option<&'static str>,
    /// The master key file read when the environment names none.
    pub key_path: Option<&'static str>,
    /// The master key sealed by `systemd-creds` (with the machine's TPM when
    /// it has one), read when the environment names none and `key_path` does
    /// not exist: unsealed with `systemd-creds decrypt`, which only root on
    /// that machine can do. The service itself receives the key from systemd
    /// (`LoadCredentialEncrypted=`), through `BRIGID_MASTER_KEY_FILE`.
    pub sealed_key_path: Option<&'static str>,
    /// Ends the message given when no master key is found: how this edition
    /// makes one (", or create /etc/brigid/master.key with `seedling init`").
    pub key_hint: &'static str,
    /// Ends the message given when the server is started as root: how this
    /// edition runs it otherwise.
    pub root_hint: &'static str,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// The commands every edition offers, besides starting the server. An
/// edition adds its own next to them (`#[command(flatten)]`).
#[derive(Subcommand)]
pub enum Command {
    /// Re-encrypt every row under a new master key, replacing the old one.
    ///
    /// Reads the database path from `--config`/`BRIGID_DATABASE__PATH` like a
    /// normal run — `BRIGID_MASTER_KEY` is intentionally *not* read from the
    /// environment for this subcommand, since both keys are needed
    /// simultaneously and only one can live in a single env var.
    RotateKey {
        /// Path to a file containing the current master key (64 hex chars).
        #[arg(long)]
        old: PathBuf,
        /// Path to a file containing the new master key (64 hex chars).
        #[arg(long)]
        new: PathBuf,
    },

    /// Make a new OIDC signing key current. The previous one keeps verifying
    /// tokens for the grace period (tokens live one hour), then is removed.
    /// A server made of one node signs with the new key once restarted; the
    /// nodes of a server made of several read it by themselves, and the
    /// command says when they sign with it.
    RotateOidcKey,

    /// Manage the relying parties: the sites that may ask this server to
    /// sign people in. Works on the database directly, with the server
    /// running or stopped; needs the master key like a normal run.
    Client {
        #[command(subcommand)]
        action: ClientCommand,
    },

    /// Administration from the machine. Reaching it is the proof of being
    /// the operator.
    Admin {
        #[command(subcommand)]
        action: AdminCommand,
    },

    /// Say who may create an account: `open` (anyone), `invitation` (whoever
    /// an administrator invited; the default) or `closed` (nobody). Without
    /// a value, prints the current one. An administrator sets the same from
    /// the interface.
    Signup {
        /// `open`, `invitation` or `closed`.
        policy: Option<String>,
    },

    /// Set what one account, or one address, can create on this server.
    /// Without arguments, prints each limit as
    /// `name<TAB>value<TAB>default<TAB>max`. An administrator sets the same
    /// from the interface.
    ///
    /// The limits: `identities_per_account`, `passkeys_per_account`,
    /// `sign_ups_per_ip_per_day`. An account above a lowered limit keeps
    /// what it has and adds nothing.
    Limits {
        #[command(subcommand)]
        action: Option<LimitsCommand>,
    },

    /// For a server whose database is a SQLite file (a database server has
    /// its own tools). Write a copy of the database to FILE, consistent
    /// while the server runs. It is encrypted under the same master key: keep the key with
    /// it, apart. FILE is created with mode 0600 and never written over.
    /// Prints the path written on standard output.
    Backup {
        /// The file to create.
        file: PathBuf,
    },

    /// For a server whose database is a SQLite file. Put a backup in place
    /// of the database. Stop the server first: this
    /// refuses while the server, or anything else, uses the database. The
    /// backup must open with the master key, belong to this server's
    /// domain and have a schema this version knows. The database it
    /// replaces is kept as `<database>.before-restore-<time>`, whose path is
    /// printed on standard output.
    Restore {
        /// A file written by `backup`.
        file: PathBuf,
    },

    /// Liveness probe for Docker's HEALTHCHECK: GET the local `/health`,
    /// exit 0 on 200, 1 otherwise. Reads only `BRIGID_SERVER__PORT` (default
    /// 8080), so it needs neither the config file nor the master key.
    Healthcheck {
        /// Port of the plain-HTTP listener to probe.
        #[arg(long, env = "BRIGID_SERVER__PORT", default_value_t = 8080)]
        port: u16,
    },
}

/// The commands of an edition made of several nodes: the shared ones, and
/// the two that prepare the database the nodes share.
#[derive(Subcommand)]
pub enum NodeCommand {
    /// Prepare the database, before the nodes start and before each update:
    /// create or update the schema, the tables of what the nodes share, the
    /// secret of the identifiers and the first signing key. Nodes create
    /// none of it and wait for it. Run it once at a time, as a database role
    /// that owns the schema; a second run changes nothing. On a server with
    /// no administrator it prints, on standard output, the setup link that
    /// creates the first one.
    Init {
        /// The database role the nodes connect as: it is given the right to
        /// read and write rows, and not to change the schema.
        #[arg(long, value_name = "ROLE")]
        grant: Option<String>,
        /// Keep what lives minutes in an ordinary table instead of an
        /// unlogged one: for a PostgreSQL service that offers none. Read
        /// only when the table is created.
        #[arg(long)]
        logged_pending: bool,
    },

    /// Copy a backup of a seedling or a grove (the FILE its `backup`
    /// command wrote) into this server's database: accounts, passkeys,
    /// identities, sites, settings, the secret of the identifiers and the
    /// signing keys. For a server that has no account yet, after `init`,
    /// under the same master key and the same domain as the server the
    /// backup comes from: nothing changes for the people and the sites.
    Import {
        /// A file written by `seedling backup` or `grove backup`.
        file: PathBuf,
        /// Import a backup whose accounts were created on another domain
        /// than this server's. Their passkeys will not work here.
        #[arg(long)]
        any_domain: bool,
    },

    #[command(flatten)]
    Shared(Command),
}

/// How many processes serve the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Nodes {
    /// One: it brings the schema up to date and creates what is missing
    /// when it starts, and keeps what lives minutes in its memory.
    One,
    /// Several: none of them changes the schema or creates a secret
    /// (`init` does), and what lives minutes is in the database.
    Several,
}

/// `limits …`
#[derive(Subcommand)]
pub enum LimitsCommand {
    /// Set a limit, from 1 to its maximum.
    Set {
        /// `identities_per_account`, `passkeys_per_account` or
        /// `sign_ups_per_ip_per_day`.
        name: String,
        value: String,
    },
}

/// `admin …`
#[derive(Subcommand)]
pub enum AdminCommand {
    /// Print a link that makes an administrator. On a server with no
    /// account yet: a new setup link, which creates the first account (the
    /// one the server printed at its start stops working). Otherwise: a link
    /// that makes an administrator of the signed-in account that opens it,
    /// for a server whose administrators all lost their passkeys. One use,
    /// one hour.
    Link,
}

/// `client …`
#[derive(Subcommand)]
pub enum ClientCommand {
    /// Register a site. Prints `client_id=…` and, unless `--public`,
    /// `client_secret=…` on standard output. The secret is stored hashed:
    /// this is the only time it can be read.
    Add {
        /// The site's name, shown to people when they sign in to it.
        #[arg(long)]
        name: String,
        /// Where the site may send people back, compared exactly. Repeat for
        /// several. `https` only, except `http://localhost` for development.
        #[arg(long = "redirect-uri", required = true)]
        redirect_uris: Vec<String>,
        /// A site that cannot keep a secret (an application running in the
        /// browser or on a phone): no secret is issued.
        #[arg(long)]
        public: bool,
        #[command(flatten)]
        asks: Asks,
    },
    /// Say what a registered site may ask people to share. This replaces
    /// what it could ask before; with no option, it may ask for nothing
    /// more than an identifier. What people already accepted stays
    /// recorded, and an attribute taken away is no longer sent.
    Attributes {
        /// The `client_id` printed by `add` and `list`.
        client_id: String,
        #[command(flatten)]
        asks: Asks,
    },
    /// List the registered sites: identifier, kind, name, redirect URIs and
    /// what each may ask for, separated by tabs.
    List,
    /// Remove a site. People can no longer sign in to it through this
    /// server, and the identity each person chose for it is forgotten.
    Remove {
        /// The `client_id` printed by `add` and `list`.
        client_id: String,
    },
    /// Say which sites that describe themselves (their `client_id` is the
    /// URL of a document they publish) may sign people in, with no
    /// registration: `open` (any, except the refused ones; the default),
    /// `listed` (only the accepted ones) or `registered` (none: only the
    /// sites added here). Without a value, prints the current one and the
    /// lists.
    Policy {
        /// `open`, `listed` or `registered`.
        policy: Option<String>,
    },
    /// Accept a site that describes itself: under `listed`, only accepted
    /// sites sign people in; an accepted site's logo is shown.
    Accept {
        /// The site's `client_id`: the URL of its document.
        client_id: String,
    },
    /// Refuse a site that describes itself, whatever the policy.
    Refuse {
        /// The site's `client_id`: the URL of its document.
        client_id: String,
    },
    /// Take a site off the accepted or refused list.
    Unlist {
        /// The site's `client_id`: the URL of its document.
        client_id: String,
    },
    /// Say what a site that describes itself may ask people to share, at
    /// most, whatever its document says. Without an option, prints it.
    Limit {
        /// An attribute such sites may ask for. Repeat for several.
        #[arg(long = "allow", value_name = "ATTRIBUTE")]
        allow: Vec<String>,
        /// No limit: any attribute (the default).
        #[arg(long, conflicts_with = "allow")]
        all: bool,
        /// An identifier only: no attribute at all.
        #[arg(long, conflicts_with_all = ["allow", "all"])]
        none: bool,
    },
}

/// What a site may ask people to share about the identity they present.
/// Without any of it, a site receives an identifier and nothing else.
///
/// The attributes are `given_name`, `family_name`, `preferred_username`,
/// `email`, `locale` and `zoneinfo`. A site asks for them with the `profile`
/// and `email` scopes, and each person decides what they share.
#[derive(clap::Args)]
pub struct Asks {
    /// An attribute the site may ask for and works without: a person can
    /// refuse it and still sign in. Repeat for several.
    #[arg(long = "optional", value_name = "ATTRIBUTE")]
    pub optional: Vec<String>,
    /// An attribute the site cannot work without: a person who refuses it
    /// does not sign in. Repeat for several.
    #[arg(long = "required", value_name = "ATTRIBUTE")]
    pub required: Vec<String>,
}

impl Asks {
    /// The attributes named, or what is wrong with the options.
    fn attributes(&self) -> Result<BTreeMap<Attribute, Need>, String> {
        let mut attributes = BTreeMap::new();
        let named = self
            .optional
            .iter()
            .map(|name| (name, Need::Optional))
            .chain(self.required.iter().map(|name| (name, Need::Required)));
        for (name, need) in named {
            let attribute = Attribute::parse(name).ok_or_else(|| {
                let known: Vec<&str> = Attribute::ALL.into_iter().map(Attribute::claim).collect();
                format!(
                    "{name} is not an attribute. They are: {}.",
                    known.join(", ")
                )
            })?;
            if attributes.insert(attribute, need).is_some() {
                return Err(format!("{name} is named twice."));
            }
        }
        Ok(attributes)
    }
}

/// `email=required,given_name=optional`, or `-` for a site that may ask for
/// nothing.
fn describe_attributes(attributes: &BTreeMap<Attribute, Need>) -> String {
    if attributes.is_empty() {
        return "-".to_owned();
    }
    attributes
        .iter()
        .map(|(attribute, need)| {
            let need = match need {
                Need::Required => "required",
                Need::Optional => "optional",
            };
            format!("{attribute}={need}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The database named by the configuration at `config`, or the end of the
/// command with what is wrong with it.
fn load_database(config: Option<&Path>) -> config::Database {
    config::load_database(config)
        .expect("configuration error")
        .database()
        .unwrap_or_else(|e| fail(&e))
}

/// Opens the store for a command or for the server. A single node brings
/// the schema up to date. A node of several never does: it opens the
/// database as it is, and a command refuses to work on a schema that is not
/// the one its version serves on.
async fn open_store(
    nodes: Nodes,
    database: &config::Database,
    master: MasterKey,
) -> EncryptedStore {
    match nodes {
        Nodes::One => EncryptedStore::new(&database.address, master)
            .await
            .expect("failed to open or migrate database"),
        Nodes::Several => {
            let store = nodes::connect(database, master).await;
            if let Err(why) = nodes::initialised(&store).await {
                fail(&format!("{why}."));
            }
            store
        }
    }
}

/// Handles `rotate-key --old <path> --new <path>`.
async fn rotate_key(
    edition: &Edition,
    nodes: Nodes,
    db: &config::Database,
    old_master: MasterKey,
    new_master: MasterKey,
) {
    let mut store = open_store(nodes, db, old_master).await;

    store
        .rotate_master_key(new_master)
        .await
        .expect("key rotation failed — the transaction was rolled back, the database is unchanged");

    eprintln!("✓ MASTER_KEY rotated successfully.");
    eprintln!();
    eprintln!("Nothing changes for users or relying parties: the OIDC signing keys and the");
    eprintln!("VSID secret are stored and were re-encrypted, so issued tokens stay valid and");
    eprintln!("every VSID (the OIDC `sub` claim) keeps its value. Rotate the signing keys");
    eprintln!("separately with `{} rotate-oidc-key`.", edition.name);
    eprintln!();
    eprintln!(
        "Update BRIGID_MASTER_KEY to the new key before starting {} again.",
        edition.name
    );
    if nodes == Nodes::Several {
        eprintln!(
            "Every node must have been stopped: one that ran meanwhile wrote under the old key."
        );
    }
}

/// For a command run as root: reads the master key while it still can
/// (`with_key`), then becomes the owner of the database's directory, so that
/// no file of the database ends up belonging to root. Does nothing for any
/// other user.
fn as_owner_of_database(edition: &Edition, database: &Path, with_key: bool) {
    if owner::effective_uid() != 0 {
        return;
    }
    if with_key {
        match master_key_hex(edition) {
            Ok(hex) => {
                let _ = PRELOADED_KEY.set(hex);
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    if let Err(e) = owner::become_owner_of_database(database) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

/// How long a retired OIDC key keeps verifying: the one-hour token lifetime
/// plus a margin for clock skew and refresh in flight.
const OIDC_GRACE: time::Duration = time::Duration::hours(2);

/// A key read before this process became the owner of the database (see
/// `owner::become_owner_of_database`): the file may be readable by root only.
static PRELOADED_KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The master key, in hex, from the first of: `BRIGID_MASTER_KEY_FILE` (a
/// mounted secret, or the credential systemd hands the service),
/// `BRIGID_MASTER_KEY`, the edition's own key file (`Edition::key_path`), or
/// its sealed key (`Edition::sealed_key_path`). Never from the configuration
/// file.
fn master_key_hex(edition: &Edition) -> Result<String, String> {
    let read =
        |path: &Path| std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()));
    if let Some(path) = std::env::var_os("BRIGID_MASTER_KEY_FILE") {
        return read(Path::new(&path));
    }
    if let Ok(hex) = std::env::var("BRIGID_MASTER_KEY") {
        return Ok(hex);
    }
    if let Some(default) = edition.key_path.map(Path::new)
        && default.exists()
    {
        return read(default);
    }
    if let Some(sealed) = edition.sealed_key_path.map(Path::new)
        && sealed.exists()
    {
        return unseal(sealed);
    }
    Err(format!(
        "no master key: set BRIGID_MASTER_KEY_FILE to a file holding it, or BRIGID_MASTER_KEY{}",
        edition.key_hint
    ))
}

/// The name a sealed master key carries: `systemd-creds` binds it, and the
/// unit's `LoadCredentialEncrypted=master.key:…` must use the same.
pub const SEALED_KEY_NAME: &str = "master.key";

/// The key sealed at `path`, unsealed by `systemd-creds` (it needs root, and
/// this machine's TPM or host key: a copy of the file elsewhere is useless).
pub fn unseal(path: &Path) -> Result<String, String> {
    unseal_with(std::ffi::OsStr::new("systemd-creds"), path)
}

fn unseal_with(program: &std::ffi::OsStr, path: &Path) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .arg("decrypt")
        .arg(format!("--name={SEALED_KEY_NAME}"))
        .arg(path)
        .arg("-")
        .output()
        .map_err(|e| format!("cannot run systemd-creds to unseal {}: {e}", path.display()))?;
    if !out.status.success() {
        return Err(format!(
            "systemd-creds could not unseal {} (root, on the machine that sealed it): {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|_| format!("{}: not a key", path.display()))
}

fn load_master_key(edition: &Edition) -> MasterKey {
    let hex = match PRELOADED_KEY.get() {
        Some(hex) => hex.clone(),
        None => master_key_hex(edition).unwrap_or_else(|e| panic!("{e}")),
    };
    MasterKey::from_hex(hex.trim())
        .expect("the master key must be a 64-character hex string (32 bytes)")
}

/// The current OIDC key and the retired ones still in grace. A database
/// that has none yet gets a new random one.
async fn load_oidc_keys(store: &EncryptedStore) -> (OidcSigningKey, Vec<OidcSigningKey>) {
    let pruned = store
        .prune_oidc_keys(time::OffsetDateTime::now_utc() - OIDC_GRACE)
        .await
        .expect("failed to prune retired OIDC keys");
    if pruned > 0 {
        tracing::info!(
            pruned,
            "retired OIDC signing keys past their grace period removed"
        );
    }
    let mut keys = store
        .oidc_signing_keys()
        .await
        .expect("failed to read OIDC signing keys");
    if keys.is_empty() {
        let seed = OidcSigningKey::generate().to_raw_bytes();
        store
            .add_oidc_signing_key(OidcSigningKey::from_seed(&seed).kid(), &seed)
            .await
            .expect("failed to store the initial OIDC signing key");
        keys = store
            .oidc_signing_keys()
            .await
            .expect("failed to read OIDC signing keys");
    }
    let mut keys = keys
        .into_iter()
        .map(|k| OidcSigningKey::from_raw_bytes(k.kid, &k.seed));
    let current = keys.next().expect("at least one OIDC key is stored");
    (current, keys.collect())
}

/// Handles `rotate-oidc-key`.
async fn rotate_oidc_key(edition: &Edition, nodes: Nodes, db: &config::Database) {
    let store = open_store(nodes, db, load_master_key(edition)).await;
    let seed = OidcSigningKey::generate().to_raw_bytes();
    let key = OidcSigningKey::from_seed(&seed);
    store
        .add_oidc_signing_key(key.kid(), &seed)
        .await
        .expect("failed to store the new OIDC signing key");
    eprintln!("✓ New OIDC signing key {} is current.", key.kid());
    if nodes == Nodes::Several {
        eprintln!(
            "  No restart: every node publishes it within a minute and signs with it {} minutes",
            nodes::KEY_PUBLISHED_FOR.whole_minutes()
        );
        eprintln!(
            "  after its creation. Tokens signed by the previous key keep verifying for {} hours.",
            OIDC_GRACE.whole_hours()
        );
        return;
    }
    eprintln!(
        "  Restart {} to sign with it. Tokens signed by the previous key keep",
        edition.name
    );
    eprintln!(
        "  verifying for {} hours, then that key is removed at a later start.",
        OIDC_GRACE.whole_hours()
    );
}

/// The address people reach this server at, with its final slash:
/// `server.public_url` when set, else what `domain` and `port` say.
/// How the listener holds its certificate.
enum TlsMode {
    /// Plain HTTP, behind a proxy that holds it.
    Off,
    /// Certificate files the operator renews.
    Files { cert: PathBuf, key: PathBuf },
    /// Obtained and renewed by the server (ACME).
    Acme(acme::AcmeSettings),
}

impl TlsMode {
    fn name(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Files { .. } => "files",
            Self::Acme(_) => "acme",
        }
    }
}

/// The TLS mode the configuration asks for. A configuration that names
/// half of one, or two at once, stops the server: falling back to plain HTTP
/// would silently disable TLS whenever an operator mistypes a single path.
fn tls_mode(server: &config::ServerConfig) -> TlsMode {
    match (server.acme, server.tls_cert.clone(), server.tls_key.clone()) {
        (true, None, None) => {
            let domain = server.domain.trim().to_ascii_lowercase();
            if domain.parse::<std::net::IpAddr>().is_ok()
                || !domain.contains('.')
                || domain.ends_with(".localhost")
            {
                panic!(
                    "server.acme needs a public DNS name in server.domain, not {domain:?}: \
                     the certificate authority must reach it"
                );
            }
            TlsMode::Acme(acme::AcmeSettings {
                domain,
                directory: server
                    .acme_directory
                    .clone()
                    .unwrap_or_else(|| acme::LETS_ENCRYPT.to_owned()),
                contact: server.acme_contact.clone(),
                ca: server.acme_ca.clone(),
            })
        }
        (true, _, _) => panic!(
            "server.acme and server.tls_cert/tls_key are both set: the certificate comes from \
             one or the other"
        ),
        (false, Some(cert), Some(key)) => TlsMode::Files { cert, key },
        (false, None, None) => TlsMode::Off,
        (false, Some(_), None) => panic!(
            "server.tls_cert is set but server.tls_key is missing — \
             both must be set together (HTTPS) or both omitted (plain HTTP)"
        ),
        (false, None, Some(_)) => panic!(
            "server.tls_key is set but server.tls_cert is missing — \
             both must be set together (HTTPS) or both omitted (plain HTTP)"
        ),
    }
}

fn public_url(cfg: &config::Config) -> Url {
    match cfg.server.public_url {
        Some(ref u) => u
            .parse()
            .expect("invalid `server.public_url` in configuration"),
        None => {
            let scheme = if cfg.server.acme
                || (cfg.server.tls_cert.is_some() && cfg.server.tls_key.is_some())
            {
                "https"
            } else {
                "http"
            };
            format!("{}://{}:{}", scheme, cfg.server.domain, cfg.server.port)
                .parse()
                .expect("invalid domain/port in configuration")
        }
    }
}

/// At start: says how the server gets its first administrator while it has
/// none, and deletes what the log of administrative actions kept too long.
///
/// - No account at all: a setup link, printed here and nowhere else. It
///   creates the first account, as administrator; it works once, for an
///   hour, and each start replaces it.
/// - Accounts and no administrator (a server upgraded from a version without
///   administration, or whose administrators left): `<server> admin link`.
async fn announce_administration(edition: &Edition, nodes: Nodes, state: &AppState) {
    let name = edition.name;
    let store = &state.store;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let keep = i64::try_from(state.admin_log_retention.as_secs()).unwrap_or(i64::MAX);
    match store.purge_admin_log(now.saturating_sub(keep)).await {
        Ok(0) => {}
        Ok(deleted) => tracing::info!(deleted, "old entries of the administration log deleted"),
        Err(e) => tracing::error!(error = %e, "the administration log could not be purged"),
    }

    let administrators = store
        .count_administrators()
        .await
        .expect("failed to read the accounts");
    if administrators > 0 {
        return;
    }
    if nodes == Nodes::Several {
        // Each new setup link cancels the one before: of several nodes
        // starting together, none makes one. `init` printed it.
        tracing::warn!(
            "no administrator yet: `{name} init` printed the setup link, `{name} admin link` makes a new one"
        );
        return;
    }
    match brigid_api::setup_link(store)
        .await
        .expect("failed to make the setup link")
    {
        Some(link) => {
            // The secret is in the fragment of the address: a browser never
            // sends it, so it is in no access log, here or in a proxy.
            let address = format!("{}/setup/#link={link}", state.issuer());
            // On standard error for whoever started the server by hand, and
            // in the log for whoever reads it from a service manager.
            eprintln!(
                "\nThis server has no administrator yet. To become it, open:\n\n  {address}\n\n\
                 The link works once, for an hour; `{name} admin link` makes a new one.\n"
            );
            tracing::warn!(setup_link = %address, "no administrator yet: open the setup link");
        }
        None => {
            eprintln!(
                "\nThis server has accounts and no administrator. Run `{name} admin link`,\n\
                 then open the address it prints, signed in as the account that will administer.\n"
            );
            tracing::warn!("accounts and no administrator: run `{name} admin link`");
        }
    }
}

/// Handles `signup [policy]`.
async fn signup_command(
    edition: &Edition,
    nodes: Nodes,
    db: &config::Database,
    policy: Option<&str>,
) {
    use brigid_store::SignupPolicy;
    let store = open_store(nodes, db, load_master_key(edition)).await;
    if let Some(value) = policy {
        let policy = SignupPolicy::parse(value)
            .unwrap_or_else(|| fail(&format!("{value} is not open, invitation or closed.")));
        store
            .set_signup_policy(policy)
            .await
            .expect("failed to set who may sign up");
        store
            .log_admin_action(&brigid_store::AdminAction {
                action: "signup.policy".into(),
                actor: None,
                account: None,
                detail: Some(policy.as_str().to_owned()),
            })
            .await
            .expect("failed to log the change");
    }
    let current = store
        .signup_policy()
        .await
        .expect("failed to read who may sign up");
    println!("{}", current.as_str());
}

/// Handles `limits [set <name> <value>]`. One limit per line on standard
/// output: `name<TAB>value<TAB>default<TAB>max`.
async fn limits_command(
    edition: &Edition,
    nodes: Nodes,
    db: &config::Database,
    action: Option<LimitsCommand>,
) {
    use brigid_store::Limit;
    let store = open_store(nodes, db, load_master_key(edition)).await;
    if let Some(LimitsCommand::Set { name, value }) = action {
        let limit = Limit::parse(&name).unwrap_or_else(|| {
            let known: Vec<&str> = Limit::ALL.into_iter().map(Limit::name).collect();
            fail(&format!(
                "{name} is not a limit. They are: {}.",
                known.join(", ")
            ))
        });
        let value = value
            .parse::<u32>()
            .ok()
            .filter(|v| (1..=limit.max()).contains(v))
            .unwrap_or_else(|| {
                fail(&format!(
                    "{name} is a whole number from 1 to {}.",
                    limit.max()
                ))
            });
        store
            .set_limit(limit, value)
            .await
            .expect("failed to set the limit");
        store
            .log_admin_action(&brigid_store::AdminAction {
                action: "limit.set".into(),
                actor: None,
                account: None,
                detail: Some(format!("{limit}={value}")),
            })
            .await
            .expect("failed to log the change");
        eprintln!("✓ {limit} is {value}.");
    }
    for (limit, value) in store.limits().await.expect("failed to read the limits") {
        println!(
            "{limit}\t{value}\t{}\t{}",
            limit.default_value(),
            limit.max()
        );
    }
}

/// Handles `backup <file>`: `out` is the file, created before this process
/// became the database's owner.
async fn backup_command(database: &Path, out: std::fs::File, path: &Path) {
    if let Err(e) = backup::backup(database, out, path).await {
        fail(&e);
    }
    let written = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    println!("{}", written.display());
    eprintln!(
        "✓ {} copied. It opens only with this server's master key: keep the key too, apart.",
        database.display()
    );
}

/// Handles `restore <file>`: `source` is the backup, opened before this
/// process became the database's owner.
async fn restore_command(
    edition: &Edition,
    cfg: &config::Config,
    database: &Path,
    source: std::fs::File,
) {
    let base = public_url(cfg);
    let domain = base.host_str().unwrap_or(&cfg.server.domain).to_owned();
    let restored = match backup::restore(database, source, &load_master_key(edition), &domain).await
    {
        Ok(restored) => restored,
        Err(e) => fail(&e),
    };
    let inspection = &restored.inspection;
    if let Some(aside) = &restored.aside {
        println!("{}", aside.display());
    }
    eprintln!(
        "✓ Restored: {} accounts, {} identities.",
        inspection.accounts, inspection.identities
    );
    if inspection.domains.is_empty() {
        eprintln!("  It has no account: nothing said which domain it was made for.");
    }
    if inspection.schema < inspection.known_schema {
        eprintln!(
            "  It was made by an earlier version: its schema is brought up to date at the next start."
        );
    }
    match &restored.aside {
        Some(aside) => eprintln!("  The database it replaced is kept at {}.", aside.display()),
        None => eprintln!("  There was no database before it."),
    }
    eprintln!("  Start {} again.", edition.name);
}

/// Holds the lock of the database shared for as long as the value lives
/// (`lock`). A lock that cannot be made is said, and nothing is refused for
/// it: the server runs as it did before locks existed.
fn hold_database(database: &config::Database) -> Option<std::fs::File> {
    // Only a file is locked: PostgreSQL has its own locks, and no command
    // replaces it under a running server.
    let file = database.file.as_deref()?;
    match lock::shared(file) {
        Ok(file) => Some(file),
        Err(e) => {
            tracing::warn!(error = %e, "the database lock cannot be held: a restore cannot see this process");
            None
        }
    }
}

/// Says what is wrong on standard error and ends with the status of a
/// refused command.
fn fail(message: &str) -> ! {
    eprintln!("✗ {message}");
    std::process::exit(2);
}

/// Handles `client …`. Results go to standard output, one `key=value`
/// or one site per line, so that a script can read them; everything meant
/// for a person goes to standard error.
async fn client_command(
    edition: &Edition,
    nodes: Nodes,
    db: &config::Database,
    action: ClientCommand,
) {
    let store = open_store(nodes, db, load_master_key(edition)).await;
    match action {
        ClientCommand::Add {
            name,
            redirect_uris,
            public,
            asks,
        } => {
            // Checked before anything is written: a mistake registers nothing.
            let attributes = asks.attributes().unwrap_or_else(|e| fail(&e));
            let (client, secret) = store
                .create_client(&name, &redirect_uris, !public)
                .await
                .unwrap_or_else(|e| fail(&e.to_string()));
            store
                .set_client_attributes(&client.client_id, &attributes)
                .await
                .expect("failed to record what the site may ask for");
            println!("client_id={}", client.client_id);
            eprintln!("✓ Registered \"{}\".", client.name);
            if let Some(secret) = secret {
                println!("client_secret={}", *secret);
                eprintln!("  The secret is shown this once and stored hashed: keep it now.");
            }
            if !attributes.is_empty() {
                eprintln!("  It may ask for: {}.", describe_attributes(&attributes));
            }
        }
        ClientCommand::Attributes { client_id, asks } => {
            let attributes = asks.attributes().unwrap_or_else(|e| fail(&e));
            let existed = store
                .set_client_attributes(&client_id, &attributes)
                .await
                .expect("failed to record what the site may ask for");
            if !existed {
                fail(&format!("No site is registered as {client_id}."));
            }
            if attributes.is_empty() {
                eprintln!("✓ {client_id} may ask for nothing but an identifier.");
            } else {
                eprintln!(
                    "✓ {client_id} may ask for: {}.",
                    describe_attributes(&attributes)
                );
            }
        }
        ClientCommand::List => {
            let clients = store.list_clients().await.expect("failed to list clients");
            for client in &clients {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    client.client_id,
                    match (client.described(), client.confidential) {
                        (true, true) => "described, signs",
                        (true, false) => "described, public",
                        (false, true) => "confidential",
                        (false, false) => "public",
                    },
                    client.name,
                    client.redirect_uris.join(" "),
                    describe_attributes(&client.attributes)
                );
            }
            if clients.is_empty() {
                eprintln!("No site is registered.");
            }
        }
        ClientCommand::Policy { policy } => {
            if let Some(policy) = policy {
                let policy = ClientPolicy::parse(&policy).unwrap_or_else(|| {
                    fail("The policy is open, listed or registered.");
                });
                store
                    .set_client_policy(policy)
                    .await
                    .expect("failed to record the policy");
                eprintln!("✓ Sites that describe themselves: {}.", policy.as_str());
            }
            let policy = store
                .client_policy()
                .await
                .expect("failed to read the policy");
            println!("policy={}", policy.as_str());
            for (client_id, list) in store
                .client_lists()
                .await
                .expect("failed to read the lists")
            {
                println!("{}={client_id}", list.as_str());
            }
        }
        ClientCommand::Accept { client_id } => {
            list_client(&store, &client_id, Some(ClientList::Accepted)).await;
        }
        ClientCommand::Refuse { client_id } => {
            list_client(&store, &client_id, Some(ClientList::Refused)).await;
        }
        ClientCommand::Unlist { client_id } => {
            list_client(&store, &client_id, None).await;
        }
        ClientCommand::Limit { allow, all, none } => {
            let cap: Option<std::collections::BTreeSet<Attribute>> = if all {
                Some(Attribute::ALL.into_iter().collect())
            } else if none {
                Some(std::collections::BTreeSet::new())
            } else if allow.is_empty() {
                None
            } else {
                Some(
                    allow
                        .iter()
                        .map(|name| {
                            Attribute::parse(name)
                                .unwrap_or_else(|| fail(&format!("{name} is not an attribute.")))
                        })
                        .collect(),
                )
            };
            if let Some(cap) = &cap {
                store
                    .set_described_attributes(cap)
                    .await
                    .expect("failed to record the limit");
            }
            let cap = store
                .described_attributes()
                .await
                .expect("failed to read the limit");
            let names: Vec<&str> = cap.iter().map(|a| a.claim()).collect();
            println!("attributes={}", names.join(" "));
        }
        ClientCommand::Remove { client_id } => {
            let existed = store
                .delete_client(&client_id)
                .await
                .expect("failed to remove the client");
            if existed {
                eprintln!("✓ Removed {client_id}.");
            } else {
                eprintln!("✗ No site is registered as {client_id}.");
                std::process::exit(2);
            }
        }
    }
}

/// Puts a site that describes itself on a list, or on none.
async fn list_client(store: &EncryptedStore, client_id: &str, list: Option<ClientList>) {
    if brigid_api::described::client_id_url(client_id).is_none() {
        fail(&format!(
            "{client_id} is not the URL of a client document (https, a domain, a path)."
        ));
    }
    store
        .set_client_list(client_id, list)
        .await
        .expect("failed to record the list");
    match list {
        Some(list) => eprintln!("✓ {client_id} is {}.", list.as_str()),
        None => eprintln!("✓ {client_id} is on no list."),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Runs `command`, or the server itself when there is none. `config` is the
/// `--config` the edition's command line was given.
pub async fn run(edition: &Edition, config: Option<PathBuf>, command: Option<Command>) {
    run_as(
        edition,
        Nodes::One,
        config,
        command.map(NodeCommand::Shared),
    )
    .await;
}

/// [`run`], for an edition made of several nodes on one database: the
/// server it starts is one of them.
pub async fn run_node(edition: &Edition, config: Option<PathBuf>, command: Option<NodeCommand>) {
    run_as(edition, Nodes::Several, config, command).await;
}

async fn run_as(
    edition: &Edition,
    nodes: Nodes,
    config: Option<PathBuf>,
    command: Option<NodeCommand>,
) {
    // One rustls crypto provider for the whole process, aws-lc-rs: the
    // server's TLS (axum-server), the client that reads documents of sites
    // (reqwest) and the connection to a PostgreSQL database. Installed
    // explicitly, so that a dependency enabling another provider later can
    // never leave rustls choosing at the first handshake.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("no CryptoProvider should be installed yet — this runs once at startup");

    // The two commands of an edition made of several nodes, apart from the
    // shared ones.
    let (command, prepare) = match command {
        Some(NodeCommand::Shared(command)) => (Some(command), None),
        Some(other) => (None, Some(other)),
        None => (None, None),
    };

    struct Cli {
        config: Option<PathBuf>,
        command: Option<Command>,
    }
    let cli = Cli { config, command };

    // The probe runs every few seconds: no logging setup, no config, no key.
    if let Some(Command::Healthcheck { port }) = cli.command {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        match probe::check(addr, Duration::from_secs(3)) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("unhealthy: {e}");
                std::process::exit(1);
            }
        }
    }

    // The server never runs as root.
    if cli.command.is_none() && prepare.is_none() && owner::effective_uid() == 0 {
        eprintln!(
            "{} does not run as root. Start it as an unprivileged user{}",
            edition.name, edition.root_hint
        );
        std::process::exit(1);
    }

    // Without --config: the edition's own configuration file, if there is
    // one. A container has none, and is configured by its environment.
    let mut cli = cli;
    if cli.config.is_none()
        && let Some(path) = edition.config_path
        && Path::new(path).exists()
    {
        cli.config = Some(path.into());
    }

    // Structured JSON logs — verbosity controlled by RUST_LOG.
    fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // -- Configuration -------------------------------------------------------
    // figment's TOML file provider treats a missing file as "no data" rather
    // than an error, so an explicit --config typo would otherwise fall
    // through silently to an unrelated "missing field `server`" error with
    // no mention of the path that was actually looked up.
    if let Some(path) = cli.config.as_deref()
        && !path.exists()
    {
        panic!("config file not found: {}", path.display());
    }

    // rotate-key only ever needs the database path — extracting the full
    // `Config` here would demand `server.domain` (required, no default) for
    // no reason, since rotate-key never touches server/TLS/CORS settings.
    match prepare {
        Some(NodeCommand::Init {
            grant,
            logged_pending,
        }) => {
            let cfg = config::load(cli.config.as_deref()).expect("configuration error");
            nodes::init(edition, &cfg, grant.as_deref(), logged_pending).await;
            return;
        }
        Some(NodeCommand::Import { file, any_domain }) => {
            let cfg = config::load(cli.config.as_deref()).expect("configuration error");
            nodes::import(edition, &cfg, &file, any_domain).await;
            return;
        }
        Some(NodeCommand::Shared(_)) | None => {}
    }

    if let Some(Command::RotateKey { old, new }) = cli.command {
        let db = load_database(cli.config.as_deref());
        // Read as whoever runs this (root may be the only one who can), then
        // the database is touched as its owner.
        let old_master = MasterKey::from_file(&old)
            .expect("failed to read the old master key file (64 hex chars expected)");
        let new_master = MasterKey::from_file(&new)
            .expect("failed to read the new master key file (64 hex chars expected)");
        if let Some(file) = &db.file {
            as_owner_of_database(edition, file, false);
        }
        let _lock = hold_database(&db);
        rotate_key(edition, nodes, &db, old_master, new_master).await;
        return;
    }
    // A backup is the file of a SQLite database, and a restore puts one in
    // place: neither exists for a database that is not a file.
    if matches!(
        cli.command,
        Some(Command::Backup { .. } | Command::Restore { .. })
    ) && load_database(cli.config.as_deref()).file.is_none()
    {
        fail(
            "backup and restore work on the file of a SQLite database. This server's database \
             is not a file: back it up and restore it with the database's own tools \
             (for PostgreSQL: pg_dump, or continuous archiving)",
        );
    }
    // `backup` and `restore` name a file of the operator's: opened as
    // whoever runs this, who may be the only one allowed to.
    let operator_file = match &cli.command {
        Some(Command::Backup { file }) => {
            Some(backup::create_output(file).unwrap_or_else(|e| fail(&e)))
        }
        Some(Command::Restore { file }) => Some(
            std::fs::File::open(file).unwrap_or_else(|e| fail(&format!("{}: {e}", file.display()))),
        ),
        _ => None,
    };
    // `restore` reads the domain from the whole configuration.
    let restore_config = match &cli.command {
        Some(Command::Restore { .. }) => {
            Some(config::load(cli.config.as_deref()).expect("configuration error"))
        }
        _ => None,
    };
    // Every other command works on the database: as root, it reads the key
    // first (a backup needs none), then becomes the database's owner. It
    // holds the database's lock while it runs; `backup` and `restore` take
    // it themselves.
    let mut _lock = None;
    if let Some(command) = &cli.command {
        let db = load_database(cli.config.as_deref());
        let needs_key = !matches!(command, Command::Backup { .. });
        if let Some(file) = &db.file {
            as_owner_of_database(edition, file, needs_key);
        }
        if !matches!(command, Command::Backup { .. } | Command::Restore { .. }) {
            _lock = hold_database(&db);
        }
    }
    match (&cli.command, operator_file, restore_config.as_ref()) {
        (Some(Command::Backup { file }), Some(out), _) => {
            let db = load_database(cli.config.as_deref());
            let database = db.file.as_deref().expect("checked above: a file");
            backup_command(database, out, file).await;
            return;
        }
        (Some(Command::Restore { .. }), Some(source), Some(cfg)) => {
            let db = load_database(cli.config.as_deref());
            let database = db.file.as_deref().expect("checked above: a file");
            restore_command(edition, cfg, database, source).await;
            return;
        }
        _ => {}
    }
    if let Some(Command::Limits { action }) = cli.command {
        let db = load_database(cli.config.as_deref());
        limits_command(edition, nodes, &db, action).await;
        return;
    }
    if let Some(Command::RotateOidcKey) = cli.command {
        let db = load_database(cli.config.as_deref());
        rotate_oidc_key(edition, nodes, &db).await;
        return;
    }
    if let Some(Command::Signup { policy }) = &cli.command {
        let db = load_database(cli.config.as_deref());
        signup_command(edition, nodes, &db, policy.as_deref()).await;
        return;
    }
    if let Some(Command::Admin {
        action: AdminCommand::Link,
    }) = cli.command
    {
        let cfg = config::load(cli.config.as_deref()).expect("configuration error");
        let db = cfg.database.database().unwrap_or_else(|e| fail(&e));
        let store = open_store(nodes, &db, load_master_key(edition)).await;
        let base = public_url(&cfg).as_str().trim_end_matches('/').to_owned();
        // No account yet: a new setup link, which creates the first one.
        // The running server takes it at once; no restart.
        if let Some(link) = brigid_api::setup_link(&store)
            .await
            .expect("failed to make the link")
        {
            println!("{base}/setup/#link={link}");
            eprintln!(
                "✓ No account yet: this address creates the first one, which administers the \
                 server.\n  It works once, for an hour, and replaces any earlier setup link."
            );
            return;
        }
        let link = brigid_api::administrator_link(&store)
            .await
            .expect("failed to make the link");
        println!("{base}/admin/claim/#link={link}");
        eprintln!(
            "✓ Open this address signed in as the account that will administer the server.\n  It works once, for an hour."
        );
        return;
    }
    if let Some(Command::Client { action }) = cli.command {
        let db = load_database(cli.config.as_deref());
        client_command(edition, nodes, &db, action).await;
        return;
    }

    let cfg = config::load(cli.config.as_deref()).expect("configuration error");
    if nodes == Nodes::Several && cfg.server.acme {
        eprintln!(
            "FATAL: server.acme is for a server made of one node: the certificate of {} is held \
             by what stands in front of its nodes",
            edition.name
        );
        std::process::exit(1);
    }

    // -- MASTER_KEY ----------------------------------------------------------
    // Must come from the environment or a Docker-secrets file — never from
    // the config file (see `load_master_key`).
    let master = load_master_key(edition);

    // -- Database ------------------------------------------------------------
    let database = cfg.database.database().unwrap_or_else(|e| {
        eprintln!("FATAL: {e}");
        std::process::exit(1);
    });
    if nodes == Nodes::Several && cfg.database.url.is_none() && cfg.database.url_file.is_none() {
        eprintln!(
            "FATAL: {} serves a database its nodes share: set database.url_file (or database.url) \
             to the address of a PostgreSQL database",
            edition.name
        );
        std::process::exit(1);
    }
    // Held while the server runs: `restore` refuses while it is.
    let _database_lock = hold_database(&database);
    let (store, vsid_salt, oidc_key, retired_oidc_keys) = match nodes {
        Nodes::One => {
            let store = EncryptedStore::new(&database.address, master)
                .await
                .expect("failed to open or migrate database");
            // Stored, so that rotating the master key does not change every
            // VSID.
            let vsid_salt = *store
                .vsid_secret()
                .await
                .expect("failed to read or store the VSID secret");
            let (oidc_key, retired) = load_oidc_keys(&store).await;
            (store, vsid_salt, oidc_key, retired)
        }
        Nodes::Several => {
            // A node creates neither schema, secret nor key: it waits for
            // the ones `init` made.
            let store = nodes::connect(&database, master).await;
            let (vsid_salt, oidc_key, others) = nodes::wait_for_init(edition, &store).await;
            (store, vsid_salt, oidc_key, others)
        }
    };
    tracing::info!(
        kid = oidc_key.kid(),
        published_with_it = retired_oidc_keys.len(),
        "OIDC signing keys loaded"
    );

    // -- Application state --------------------------------------------------
    let base_url = public_url(&cfg);

    let webauthn = WebauthnService::new(cfg.server.domain.as_str(), &base_url)
        .expect("failed to build WebAuthn service (check `domain` in config)");

    let mut state = AppState::new(store, webauthn, oidc_key, base_url, vsid_salt)
        .with_retired_oidc_keys(retired_oidc_keys)
        // Public (`GET /auth/server`); `<server> --version` says the same on
        // the machine.
        .with_edition(edition.name, edition.version)
        .with_session_timeouts(
            Duration::from_secs(cfg.security.session_ttl_seconds),
            Duration::from_secs(cfg.security.session_lifetime_seconds),
        );
    state.trust_forwarded_for = cfg.security.trust_forwarded_for;
    let mut state = state
        .with_admin_log_retention(Duration::from_secs(
            cfg.security
                .admin_log_retention_days
                .saturating_mul(24 * 3600),
        ))
        .with_confirmation_ttl(Duration::from_secs(cfg.security.admin_confirmation_seconds));
    // What lives minutes: in this process's memory, or, for a node of
    // several, in the database they share.
    let stored = (nodes == Nodes::Several)
        .then(|| Arc::new(brigid_api::shared::Stored::new(state.store.clone())));
    if let Some(stored) = &stored {
        state = state.with_several_nodes().with_shared(stored.clone());
    }
    let state = Arc::new(state);
    if let Some(stored) = stored {
        nodes::keep_sweeping(stored);
        nodes::keep_reading_keys(state.clone());
    }
    announce_administration(edition, nodes, &state).await;
    let stopping = state.clone();
    // The certificate obtained with ACME is kept in the database.
    let acme_store = state.store.clone();
    let api_router = build_router(state);

    // The interface. A released build carries it; `server.ui_dist_dir`, the
    // development option, names the directory of another build to serve
    // instead. A directory that cannot be served is fatal, unless the
    // executable has its own interface to fall back on: a setting left over
    // from the time the interface was a directory must not stop a server.
    // Without either, the server is its API alone. API routes always take
    // priority.
    let from_directory = cfg
        .server
        .ui_dist_dir
        .as_deref()
        .map(|dir| (dir, Ui::from_dir(dir)));
    let ui = match (from_directory, Ui::embedded(&edition.ui)) {
        (Some((dir, Ok(ui))), _) => {
            tracing::info!(path = %dir.display(), files = ui.len(), "serving the interface from a directory");
            Some(ui)
        }
        (Some((dir, Err(e))), Some(ui)) => {
            tracing::warn!(
                path = %dir.display(),
                error = %e,
                "server.ui_dist_dir cannot be served: using the interface this executable carries"
            );
            Some(ui)
        }
        (Some((_, Err(e))), None) => {
            eprintln!("FATAL: server.ui_dist_dir: {e}");
            std::process::exit(1);
        }
        (None, Some(ui)) => {
            tracing::info!(files = ui.len(), "serving the embedded interface");
            Some(ui)
        }
        (None, None) => {
            tracing::info!("no interface: this build carries none and no directory is configured");
            None
        }
    };
    let app = apply_ui(api_router, ui.map(Arc::new));

    // -- Metrics -------------------------------------------------------------
    // Counted on the public app, served on a separate internal listener.
    let app = match cfg.server.metrics_port {
        Some(port) => {
            let registry = metrics::Metrics::default();
            let metrics_ip: std::net::IpAddr = cfg
                .server
                .host
                .parse()
                .expect("invalid `server.host` in configuration");
            let metrics_addr = SocketAddr::new(metrics_ip, port);
            let listener = tokio::net::TcpListener::bind(metrics_addr)
                .await
                .unwrap_or_else(|e| panic!("cannot bind metrics listener {metrics_addr}: {e}"));
            let router = metrics::metrics_router(registry.clone());
            tracing::info!(%metrics_addr, "metrics listener (internal only)");
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, router).await {
                    tracing::error!(error = %e, "metrics listener stopped");
                }
            });
            metrics::instrument(app, registry)
        }
        None => app,
    };

    // -- Server --------------------------------------------------------------
    // Parse the host as an IpAddr first so that IPv6 addresses are bracketed
    // correctly in the resulting SocketAddr (e.g. `::1` → `[::1]:8080`).
    let ip: std::net::IpAddr = cfg
        .server
        .host
        .parse()
        .expect("invalid `server.host` in configuration");
    let addr = SocketAddr::new(ip, cfg.server.port);

    let handle = axum_server::Handle::new();

    // Spawn graceful-shutdown task.
    {
        let shutdown_handle = handle.clone();
        let delay = Duration::from_secs(cfg.server.shutdown_delay_seconds.unwrap_or(match nodes {
            Nodes::One => 0,
            Nodes::Several => 5,
        }));
        tokio::spawn(async move {
            shutdown_signal().await;
            // Not ready first, so that what spreads requests sends no new
            // one; then the requests already here are finished.
            stopping.stop();
            if !delay.is_zero() {
                tracing::info!(
                    seconds = delay.as_secs(),
                    "shutdown signal received — no longer ready, still answering"
                );
                tokio::time::sleep(delay).await;
            }
            tracing::info!("draining connections (10 s grace)");
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });
    }

    let tls = tls_mode(&cfg.server);
    tracing::info!(
        %addr,
        domain = %cfg.server.domain,
        tls = tls.name(),
        session_idle_secs = cfg.security.session_ttl_seconds,
        session_lifetime_secs = cfg.security.session_lifetime_seconds,
        edition = edition.name,
        "brig·id server starting"
    );
    let service = app.into_make_service_with_connect_info::<SocketAddr>();
    match tls {
        TlsMode::Off => {
            tracing::warn!(
                "TLS not configured — running plain HTTP (behind a proxy that holds the \
                 certificate, or set `server.acme`, or `tls_cert`/`tls_key`)"
            );
            axum_server::bind(addr)
                .handle(handle)
                .serve(service)
                .await
                .expect("HTTP server error");
        }
        TlsMode::Files { cert, key } => {
            let read = |path: &std::path::Path| {
                std::fs::read(path)
                    .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
            };
            let loaded = acme::load(&read(&cert), &read(&key)).unwrap_or_else(|e| {
                panic!("the certificate in tls_cert/tls_key cannot be used: {e}")
            });
            let certificates = Arc::new(acme::Certificates::fixed(loaded.key));
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
                acme::server_config(certificates),
            ));
            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(service)
                .await
                .expect("TLS server error");
        }
        TlsMode::Acme(settings) => {
            if cfg.server.port != 443 {
                tracing::warn!(
                    port = cfg.server.port,
                    "the certificate authority checks the domain on port 443: forward it to this port"
                );
            }
            let certificates = Arc::new(acme::Certificates::default());
            let manager = acme::Acme::new(settings, acme_store, certificates.clone());
            let listening = handle.clone();
            tokio::spawn(manager.run(async move {
                listening.listening().await;
            }));
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
                acme::server_config(certificates),
            ));
            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(service)
                .await
                .expect("TLS server error");
        }
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown signal handler
// ---------------------------------------------------------------------------

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("CTRL-C handler failed");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler registration failed")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod sealed_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A stand-in for `systemd-creds`: prints the file it is given when the
    /// arguments are the expected ones, fails otherwise.
    fn fake(dir: &Path) -> std::path::PathBuf {
        let program = dir.join("systemd-creds");
        std::fs::write(
            &program,
            "#!/bin/sh\n[ \"$1\" = decrypt ] && [ \"$2\" = --name=master.key ] && [ \"$4\" = - ] \
             && exec cat \"$3\"\necho refused >&2; exit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        program
    }

    #[test]
    fn a_sealed_key_is_unsealed_by_systemd_creds_under_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake(dir.path());
        let sealed = dir.path().join("master.key.cred");
        std::fs::write(&sealed, "ab".repeat(32)).unwrap();
        assert_eq!(
            unseal_with(program.as_os_str(), &sealed).unwrap(),
            "ab".repeat(32)
        );
        let missing = dir.path().join("nothing.cred");
        let err = unseal_with(program.as_os_str(), &missing).unwrap_err();
        assert!(err.contains("could not unseal"), "{err}");
        let err = unseal_with(std::ffi::OsStr::new("/no/such/program"), &sealed).unwrap_err();
        assert!(err.contains("cannot run systemd-creds"), "{err}");
    }
}
