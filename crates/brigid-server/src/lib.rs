//! brig·id server: what every edition (seedling, grove) runs, the same code.
//!
//! An edition is a small executable: its name, its version, the interface it
//! carries and where it looks for things on a machine (`Edition`), its own
//! commands next to the shared ones (`Command`), and a call to `run`. What
//! makes editions differ lives in their own repositories: how they are
//! installed and packaged, never how they behave.
//!
//! # Startup sequence
//!
//! 1. Load and validate configuration (TOML + `BRIGID_*` environment).
//! 2. Load the master key (environment, mounted secret, or the edition's file).
//! 3. Open and migrate the SQLite database.
//! 4. Read the VSID secret and the OIDC signing keys from it.
//! 5. Build the Axum application (router + state + interface + metrics).
//! 6. Start TLS (if cert/key configured) or plain HTTP server.
//! 7. Await graceful shutdown on `SIGTERM` / `CTRL-C`.

pub mod config;
pub mod metrics;
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
    /// tokens for the grace period (tokens live one hour), then is pruned at
    /// a later start. Restart the server afterwards to sign with the new key.
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

    /// Liveness probe for Docker's HEALTHCHECK: GET the local `/health`,
    /// exit 0 on 200, 1 otherwise. Reads only `BRIGID_SERVER__PORT` (default
    /// 8080), so it needs neither the config file nor the master key.
    Healthcheck {
        /// Port of the plain-HTTP listener to probe.
        #[arg(long, env = "BRIGID_SERVER__PORT", default_value_t = 8080)]
        port: u16,
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

/// Builds the sqlx connection URL for a database path.
fn db_url(path: &str) -> String {
    if path == ":memory:" {
        "sqlite::memory:".to_string()
    } else {
        // Use the path-only form `sqlite:{path}` rather than `sqlite://{path}`.
        // The double-slash form is a URL where everything after `://` is
        // host+path; for an absolute path like `/data/brigid.db` that yields
        // `sqlite:///data/brigid.db` (three slashes) which is correct but
        // easy to miscount as `sqlite:////…` in code review and is fragile
        // when the path contains characters that would otherwise need URL
        // encoding. The single-slash form is unambiguously a filename and
        // sqlx parses it the same way for both absolute and relative paths.
        format!("sqlite:{path}?mode=rwc")
    }
}

/// Handles `rotate-key --old <path> --new <path>`.
async fn rotate_key(
    edition: &Edition,
    db: &config::DatabaseConfig,
    old_master: MasterKey,
    new_master: MasterKey,
) {
    let mut store = EncryptedStore::new(&db_url(&db.path), old_master)
        .await
        .expect("failed to open or migrate database");

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
async fn rotate_oidc_key(edition: &Edition, db: &config::DatabaseConfig) {
    let store = EncryptedStore::new(&db_url(&db.path), load_master_key(edition))
        .await
        .expect("failed to open or migrate database");
    let seed = OidcSigningKey::generate().to_raw_bytes();
    let key = OidcSigningKey::from_seed(&seed);
    store
        .add_oidc_signing_key(key.kid(), &seed)
        .await
        .expect("failed to store the new OIDC signing key");
    eprintln!("✓ New OIDC signing key {} is current.", key.kid());
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
fn public_url(cfg: &config::Config) -> Url {
    match cfg.server.public_url {
        Some(ref u) => u
            .parse()
            .expect("invalid `server.public_url` in configuration"),
        None => {
            let scheme = if cfg.server.tls_cert.is_some() && cfg.server.tls_key.is_some() {
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
async fn announce_administration(edition: &Edition, state: &AppState) {
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
async fn signup_command(edition: &Edition, db: &config::DatabaseConfig, policy: Option<&str>) {
    use brigid_store::SignupPolicy;
    let store = EncryptedStore::new(&db_url(&db.path), load_master_key(edition))
        .await
        .expect("failed to open or migrate database");
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

/// Says what is wrong on standard error and ends with the status of a
/// refused command.
fn fail(message: &str) -> ! {
    eprintln!("✗ {message}");
    std::process::exit(2);
}

/// Handles `client …`. Results go to standard output, one `key=value`
/// or one site per line, so that a script can read them; everything meant
/// for a person goes to standard error.
async fn client_command(edition: &Edition, db: &config::DatabaseConfig, action: ClientCommand) {
    let store = EncryptedStore::new(&db_url(&db.path), load_master_key(edition))
        .await
        .expect("failed to open or migrate database");
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
    // `axum-server`'s `tls-rustls` feature and `reqwest`'s TLS backend each
    // pull in a different rustls crypto provider (`aws-lc-rs` and `ring`
    // respectively) — Cargo unifies both onto the one `rustls` crate in the
    // dependency graph, so rustls refuses to auto-select either and panics
    // the first time a TLS handshake is attempted. Installing one explicitly
    // up front resolves the ambiguity; which of the two is picked doesn't
    // matter functionally, so this matches axum-server's own default pairing.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("no CryptoProvider should be installed yet — this runs once at startup");

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
    if cli.command.is_none() && owner::effective_uid() == 0 {
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
    if let Some(Command::RotateKey { old, new }) = cli.command {
        let db = config::load_database(cli.config.as_deref()).expect("configuration error");
        // Read as whoever runs this (root may be the only one who can), then
        // the database is touched as its owner.
        let old_master = MasterKey::from_file(&old)
            .expect("failed to read the old master key file (64 hex chars expected)");
        let new_master = MasterKey::from_file(&new)
            .expect("failed to read the new master key file (64 hex chars expected)");
        as_owner_of_database(edition, Path::new(&db.path), false);
        rotate_key(edition, &db, old_master, new_master).await;
        return;
    }
    // Every other command works on the database: as root, it reads the key
    // first, then becomes the database's owner.
    if cli.command.is_some() {
        let db = config::load_database(cli.config.as_deref()).expect("configuration error");
        as_owner_of_database(edition, Path::new(&db.path), true);
    }
    if let Some(Command::RotateOidcKey) = cli.command {
        let db = config::load_database(cli.config.as_deref()).expect("configuration error");
        rotate_oidc_key(edition, &db).await;
        return;
    }
    if let Some(Command::Signup { policy }) = &cli.command {
        let db = config::load_database(cli.config.as_deref()).expect("configuration error");
        signup_command(edition, &db, policy.as_deref()).await;
        return;
    }
    if let Some(Command::Admin {
        action: AdminCommand::Link,
    }) = cli.command
    {
        let cfg = config::load(cli.config.as_deref()).expect("configuration error");
        let store = EncryptedStore::new(&db_url(&cfg.database.path), load_master_key(edition))
            .await
            .expect("failed to open or migrate database");
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
        let db = config::load_database(cli.config.as_deref()).expect("configuration error");
        client_command(edition, &db, action).await;
        return;
    }

    let cfg = config::load(cli.config.as_deref()).expect("configuration error");

    // -- MASTER_KEY ----------------------------------------------------------
    // Must come from the environment or a Docker-secrets file — never from
    // the config file (see `load_master_key`).
    let master = load_master_key(edition);

    // -- Database ------------------------------------------------------------
    let store = EncryptedStore::new(&db_url(&cfg.database.path), master)
        .await
        .expect("failed to open or migrate database");

    // -- VSID secret ---------------------------------------------------------
    // Stored, so that rotating the master key does not change every VSID.
    let vsid_salt = *store
        .vsid_secret()
        .await
        .expect("failed to read or store the VSID secret");

    // -- OIDC signing keys ---------------------------------------------------
    let (oidc_key, retired_oidc_keys) = load_oidc_keys(&store).await;
    tracing::info!(
        kid = oidc_key.kid(),
        retired = retired_oidc_keys.len(),
        "OIDC signing keys loaded"
    );

    // -- Application state --------------------------------------------------
    let base_url = public_url(&cfg);

    let webauthn = WebauthnService::new(cfg.server.domain.as_str(), &base_url)
        .expect("failed to build WebAuthn service (check `domain` in config)");

    let cors_origins: Vec<Url> = cfg
        .security
        .cors_origins
        .iter()
        .map(|s| {
            s.parse::<Url>()
                .unwrap_or_else(|e| panic!("invalid CORS origin '{s}' in configuration: {e}"))
        })
        .collect();

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
    let state = Arc::new(
        state
            .with_admin_log_retention(Duration::from_secs(
                cfg.security
                    .admin_log_retention_days
                    .saturating_mul(24 * 3600),
            ))
            .with_confirmation_ttl(Duration::from_secs(cfg.security.admin_confirmation_seconds)),
    );
    announce_administration(edition, &state).await;
    let api_router = build_router(state, &cors_origins);

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
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received — draining connections (10 s grace)");
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });
    }

    match (cfg.server.tls_cert, cfg.server.tls_key) {
        (Some(cert), Some(key)) => {
            tracing::info!(
                %addr,
                domain = %cfg.server.domain,
                tls = true,
                session_idle_secs = cfg.security.session_ttl_seconds,
                session_lifetime_secs = cfg.security.session_lifetime_seconds,
                edition = edition.name,
                "brig·id server starting"
            );
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .expect("failed to load TLS certificate/key — check tls_cert/tls_key paths");
            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("TLS server error");
        }
        (None, None) => {
            tracing::warn!(
                %addr,
                domain = %cfg.server.domain,
                tls = false,
                session_idle_secs = cfg.security.session_ttl_seconds,
                session_lifetime_secs = cfg.security.session_lifetime_seconds,
                "TLS not configured — running plain HTTP (use Caddy or configure tls_cert/tls_key)"
            );
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("HTTP server error");
        }
        // Refuse to start when only one of (tls_cert, tls_key) is set: falling
        // back to plain HTTP would silently disable TLS whenever an operator
        // mistypes a single path. A hard failure surfaces the
        // misconfiguration at startup rather than after public exposure.
        (Some(_), None) => {
            panic!(
                "server.tls_cert is set but server.tls_key is missing — \
                 both must be set together (HTTPS) or both omitted (plain HTTP)"
            );
        }
        (None, Some(_)) => {
            panic!(
                "server.tls_key is set but server.tls_cert is missing — \
                 both must be set together (HTTPS) or both omitted (plain HTTP)"
            );
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
