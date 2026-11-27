//! A server made of several nodes on one database (spec `forest.md`).
//!
//! A node holds nothing that another node needs, and creates nothing that
//! two nodes starting together could each create:
//!
//! - `init` prepares the database, once, before the nodes start and before
//!   each update: the schema, the tables of what the nodes share, the secret
//!   of the identifiers, the first signing key, the setup link;
//! - a node that starts waits for what `init` made, then serves; it is ready
//!   only on a schema made for its version (`GET /ready`);
//! - what lives minutes is in the database, swept by every node;
//! - the signing keys are read again every minute: a rotation needs no
//!   restart, and a key is published by every node before any signs with it.
//!
//! `import` fills a server that has no account yet with a backup of a
//! single-node server.

use std::{
    os::unix::fs::DirBuilderExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use brigid_api::AppState;
use brigid_crypto::MasterKey;
use brigid_oidc::OidcSigningKey;
use brigid_store::{EncryptedStore, StoredOidcKey, nodes::Fit};

use crate::{Edition, OIDC_GRACE, config, fail, load_master_key, public_url};

/// How often a node reads the signing keys again.
pub const KEYS_READ_EVERY: Duration = Duration::from_secs(60);

/// How long a key is published before a node signs with it: several times
/// [`KEYS_READ_EVERY`], so that every node, and every application that read
/// the published keys a moment ago, has it by then.
pub const KEY_PUBLISHED_FOR: time::Duration = time::Duration::minutes(5);

/// How often a node removes what expired from the state the nodes share.
const SWEEP_EVERY: Duration = Duration::from_secs(10);

/// How long a node that starts waits for `init` before it gives up.
const WAIT_FOR_INIT: Duration = Duration::from_secs(60);

/// Opens the database as it is.
pub(crate) async fn connect(database: &config::Database, master: MasterKey) -> EncryptedStore {
    match EncryptedStore::connect(&database.address, master, database.connections).await {
        Ok(store) => store,
        Err(e) => {
            eprintln!("FATAL: cannot open the database: {}", e.opening());
            std::process::exit(1);
        }
    }
}

/// Whether the database is one a node of this version serves on, and why
/// not when it is not.
pub(crate) async fn initialised(store: &EncryptedStore) -> Result<(), String> {
    let schema = store
        .schema()
        .await
        .map_err(|e| format!("the database does not answer ({e})"))?;
    let why = match schema.fit() {
        Fit::Serves => {
            return match store.kept_prepared().await {
                Ok(true) => Ok(()),
                _ => Err("The tables of what the nodes share are missing: run `init`".into()),
            };
        }
        Fit::Empty => "The database has no schema: run `init`".to_owned(),
        Fit::NotInitialised => {
            "The schema was not recorded by an initialisation: run `init`".to_owned()
        }
        Fit::Behind => format!(
            "The schema is at step {}, this version needs step {}: run this version's `init`",
            schema.applied, schema.known
        ),
        Fit::LeftBehind => format!(
            "The schema (step {}) was made for a newer version than this one: update",
            schema.applied
        ),
    };
    Err(why)
}

/// The key that signs among `keys` (the current one first, then the retired
/// ones, newest first), at `now`: the newest one published for
/// [`KEY_PUBLISHED_FOR`]. When none is that old (a server just initialised,
/// or two rotations in a row), the oldest: the one published the longest.
/// `None` without keys.
pub(crate) fn signing_key(keys: &[StoredOidcKey], now: time::OffsetDateTime) -> Option<usize> {
    keys.iter()
        .position(|key| key.created_at + KEY_PUBLISHED_FOR <= now)
        .or_else(|| keys.len().checked_sub(1))
}

/// The stored keys as a node uses them: the one that signs, and the others
/// to publish with it. Keys whose grace period is over are deleted on the
/// way. `None` when the database holds no key.
async fn read_keys(
    store: &EncryptedStore,
) -> brigid_store::Result<Option<(OidcSigningKey, Vec<OidcSigningKey>)>> {
    let now = time::OffsetDateTime::now_utc();
    store.prune_oidc_keys(now - OIDC_GRACE).await?;
    let keys = store.oidc_signing_keys().await?;
    let Some(signing) = signing_key(&keys, now) else {
        return Ok(None);
    };
    let mut signs = None;
    let mut others = Vec::with_capacity(keys.len().saturating_sub(1));
    for (n, key) in keys.into_iter().enumerate() {
        let key = OidcSigningKey::from_raw_bytes(key.kid, &key.seed);
        if n == signing {
            signs = Some(key);
        } else {
            others.push(key);
        }
    }
    Ok(signs.map(|signs| (signs, others)))
}

/// What a node needs from `init` before it serves: the secret of the
/// identifiers and the signing keys, on a schema made for it. It creates
/// none of them. Waits [`WAIT_FOR_INIT`] for an `init` still running, then
/// ends the process and says what is missing.
pub(crate) async fn wait_for_init(
    edition: &Edition,
    store: &EncryptedStore,
) -> ([u8; 32], OidcSigningKey, Vec<OidcSigningKey>) {
    let started = tokio::time::Instant::now();
    let mut said = String::new();
    loop {
        let missing = match initialised(store).await {
            Err(why) => why,
            Ok(()) => match (store.stored_vsid_secret().await, read_keys(store).await) {
                (Ok(Some(vsid)), Ok(Some((signs, others)))) => return (*vsid, signs, others),
                (Ok(None), _) => {
                    "The database holds no secret for the identifiers: run `init`".into()
                }
                (_, Ok(None)) => "The database holds no signing key: run `init`".into(),
                (Err(brigid_store::Error::Crypto(_) | brigid_store::Error::InvalidBlob), _)
                | (_, Err(brigid_store::Error::Crypto(_) | brigid_store::Error::InvalidBlob)) => {
                    eprintln!(
                        "FATAL: the master key does not open this database: it is not the key \
                         the server was initialised with"
                    );
                    std::process::exit(1);
                }
                (Err(e), _) | (_, Err(e)) => format!("the database does not answer ({e})"),
            },
        };
        if missing != said {
            // On standard error too: the log says nothing below errors
            // unless RUST_LOG asks.
            eprintln!("Not ready, waiting for `{} init`: {missing}.", edition.name);
            tracing::warn!(reason = %missing, "not ready: waiting for the initialisation");
            said = missing.clone();
        }
        if started.elapsed() >= WAIT_FOR_INIT {
            eprintln!(
                "FATAL: {missing}.\nA node of {name} creates nothing in the database: \
                 `{name} init` does, before the nodes start and before each update.",
                name = edition.name
            );
            std::process::exit(1);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Reads the signing keys again every [`KEYS_READ_EVERY`], for as long as
/// the process lives. A read that fails changes nothing: the node keeps the
/// keys it has.
pub(crate) fn keep_reading_keys(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(KEYS_READ_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        every.tick().await;
        loop {
            every.tick().await;
            match read_keys(&state.store).await {
                Ok(Some((signs, others))) => {
                    let published: Vec<String> = std::iter::once(&signs)
                        .chain(&others)
                        .map(|key| key.kid().to_owned())
                        .collect();
                    let before: Vec<String> = state
                        .oidc_verification_keys()
                        .iter()
                        .map(|key| key.kid().to_owned())
                        .collect();
                    if published != before {
                        tracing::info!(
                            signs = signs.kid(),
                            published = published.len(),
                            "OIDC signing keys read again: they changed"
                        );
                        state.set_oidc_keys(signs, others);
                    }
                }
                Ok(None) => tracing::error!("the database holds no signing key any more"),
                Err(e) => tracing::warn!(error = %e, "the signing keys could not be read again"),
            }
        }
    });
}

/// Removes what expired from the state the nodes share, every
/// [`SWEEP_EVERY`]. Every node does it; two at once is harmless.
pub(crate) fn keep_sweeping(stored: Arc<brigid_api::shared::Stored>) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(SWEEP_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            if let Err(e) = stored.sweep().await {
                tracing::warn!(error = %e, "what expired could not be removed");
            }
        }
    });
}

/// Handles `init`.
pub(crate) async fn init(
    edition: &Edition,
    cfg: &config::Config,
    grant: Option<&str>,
    logged_pending: bool,
) {
    let name = edition.name;
    let database = cfg.database.database().unwrap_or_else(|e| fail(&e));
    // Its own connections, never one only: the lock holds one while the
    // schema is written through another.
    let database = config::Database {
        connections: None,
        ..database
    };
    let store = connect(&database, load_master_key(edition)).await;
    let lock = store
        .begin_initialisation()
        .await
        .expect("failed to take the initialisation lock");

    let before = store.schema().await.expect("failed to read the schema");
    store.migrate().await.unwrap_or_else(|e| {
        fail(&format!(
            "the schema could not be brought up to date ({e}). Is the database role its owner?"
        ))
    });
    store
        .prepare_kept_as(!logged_pending)
        .await
        .expect("failed to create the tables of what the nodes share");
    let after = store.schema().await.expect("failed to read the schema");
    if before.applied == 0 {
        eprintln!("✓ Schema created (step {}).", after.applied);
    } else if before.applied < after.applied {
        eprintln!(
            "✓ Schema brought from step {} to step {}.",
            before.applied, after.applied
        );
    } else {
        eprintln!("✓ Schema up to date (step {}).", after.applied);
    }

    // The secret of the identifiers and the first signing key: made once.
    // A master key that is not the one of an earlier `init` stops here.
    let wrong_key = |e: brigid_store::Error| -> ! {
        match e {
            brigid_store::Error::Crypto(_) | brigid_store::Error::InvalidBlob => fail(
                "the master key does not open this database: it is not the key the server was \
                 initialised with",
            ),
            other => fail(&format!("the database refused: {other}")),
        }
    };
    store.vsid_secret().await.unwrap_or_else(|e| wrong_key(e));
    let keys = store
        .oidc_signing_keys()
        .await
        .unwrap_or_else(|e| wrong_key(e));
    if keys.is_empty() {
        let seed = OidcSigningKey::generate().to_raw_bytes();
        store
            .add_oidc_signing_key(OidcSigningKey::from_seed(&seed).kid(), &seed)
            .await
            .expect("failed to store the first signing key");
        eprintln!("✓ Secret of the identifiers and first signing key created.");
    }

    if let Some(role) = grant {
        match store.grant_to_nodes(role).await {
            Ok(true) => {
                eprintln!("✓ The role {role} reads and writes rows, and cannot change the schema.")
            }
            Ok(false) => eprintln!("  --grant does nothing on a database without roles."),
            Err(e) => fail(&format!("--grant {role}: {e}")),
        }
    }

    // Last: from here nodes of this version serve.
    store
        .record_schema()
        .await
        .expect("failed to record the schema");

    let administrators = store
        .count_administrators()
        .await
        .expect("failed to read the accounts");
    if administrators == 0 {
        match brigid_api::setup_link(&store)
            .await
            .expect("failed to make the setup link")
        {
            Some(link) => {
                let base = public_url(cfg).as_str().trim_end_matches('/').to_owned();
                // The secret is in the fragment of the address: a browser
                // never sends it, so it is in no access log.
                println!("{base}/setup/#link={link}");
                eprintln!(
                    "✓ No administrator yet: the address above creates the first account, which \
                     administers the server.\n  It works once, for an hour; `{name} admin link` \
                     makes a new one."
                );
            }
            None => eprintln!(
                "  This server has accounts and no administrator: run `{name} admin link`, then \
                 open the address it prints, signed in as the account that will administer."
            ),
        }
    }
    lock.done()
        .await
        .expect("failed to release the initialisation lock");
    eprintln!("✓ {name} is initialised: its nodes can start.");
}

/// A directory of this process's own under the system's temporary one,
/// readable by nobody else.
fn private_directory() -> Result<PathBuf, String> {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    let dir = std::env::temp_dir().join(format!("brigid-import-{}-{nanos}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}

/// Handles `import <file>`.
pub(crate) async fn import(edition: &Edition, cfg: &config::Config, file: &Path, any_domain: bool) {
    let name = edition.name;
    if !file.is_file() {
        fail(&format!("{}: not a file", file.display()));
    }
    let database = cfg.database.database().unwrap_or_else(|e| fail(&e));
    let store = connect(&database, load_master_key(edition)).await;
    if let Err(why) = initialised(&store).await {
        fail(&format!("{why}, then import."));
    }

    // Checked before anything is written, and said in the operator's words.
    let master = load_master_key(edition);
    let inspection = match brigid_store::backup::inspect(file, &master).await {
        Ok(inspection) => inspection,
        Err(e) => fail(&format!("{}: {e}", file.display())),
    };
    let base = public_url(cfg);
    let domain = base.host_str().unwrap_or(&cfg.server.domain);
    let foreign: Vec<&str> = inspection
        .domains
        .iter()
        .map(String::as_str)
        .filter(|found| *found != domain)
        .collect();
    if !foreign.is_empty() && !any_domain {
        fail(&format!(
            "{} holds accounts created on {}, and this server is {domain}: their passkeys are \
             bound to that domain and would not work here. Give this server the same domain, or \
             import anyway with --any-domain.",
            file.display(),
            foreign.join(", ")
        ));
    }

    // A backup made by an earlier version is brought to this version's
    // schema first, on a copy: the file itself is never written.
    let mut copy = None;
    let source = if inspection.schema < inspection.known_schema {
        let dir = private_directory().unwrap_or_else(|e| fail(&e));
        let path = dir.join("source.db");
        let migrated = async {
            brigid_store::backup::copy_database(file, &path).await?;
            let opened = EncryptedStore::new(
                &format!("sqlite:{}", path.display()),
                load_master_key(edition),
            )
            .await?;
            opened.close().await;
            Ok::<_, brigid_store::Error>(())
        }
        .await;
        if let Err(e) = migrated {
            let _ = std::fs::remove_dir_all(&dir);
            fail(&format!(
                "{} was made by an earlier version, and could not be brought up to date in {} \
                 ({e})",
                file.display(),
                dir.display()
            ));
        }
        copy = Some(dir);
        path
    } else {
        file.to_owned()
    };

    let imported = store.import(&source).await;
    if let Some(dir) = copy {
        let _ = std::fs::remove_dir_all(dir);
    }
    let imported = match imported {
        Ok(imported) => imported,
        Err(brigid_store::Error::NotEmpty) => fail(
            "this server already has accounts: an import fills a server that has none. \
             Nothing was changed.",
        ),
        Err(e) => fail(&format!("the import failed, nothing was changed: {e}")),
    };

    let rows: u64 = imported.tables.iter().map(|(_, rows)| rows).sum();
    for (table, rows) in &imported.tables {
        println!("{table}\t{rows}");
    }
    eprintln!(
        "✓ Imported: {} accounts, {} identities ({rows} rows).",
        inspection.accounts, inspection.identities
    );
    eprintln!(
        "  The identifiers sites hold and the signing keys came with them: nothing changes for \
         the people and the sites."
    );
    eprintln!(
        "  The nodes of {name} read the keys within a minute. Stop the server the backup came \
         from: two servers must not answer for one domain."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn key(kid: &str, age: time::Duration, retired: bool) -> StoredOidcKey {
        let now = time::OffsetDateTime::now_utc();
        StoredOidcKey {
            kid: kid.to_owned(),
            seed: Zeroizing::new([0; 32]),
            created_at: now - age,
            retired_at: retired.then_some(now),
        }
    }

    #[test]
    fn a_key_signs_once_it_has_been_published_long_enough() {
        let now = time::OffsetDateTime::now_utc();
        let minutes = time::Duration::minutes;
        // A server just initialised: its only key signs at once.
        assert_eq!(signing_key(&[key("a", minutes(0), false)], now), Some(0));
        // A rotation a minute ago: the key before still signs.
        let keys = [key("b", minutes(1), false), key("a", minutes(600), true)];
        assert_eq!(signing_key(&keys, now), Some(1));
        // Five minutes later every node has published the new one.
        let keys = [key("b", minutes(6), false), key("a", minutes(600), true)];
        assert_eq!(signing_key(&keys, now), Some(0));
        // Two rotations in a row: the oldest of the young keys.
        let keys = [
            key("c", minutes(1), false),
            key("b", minutes(2), true),
            key("a", minutes(600), true),
        ];
        assert_eq!(signing_key(&keys, now), Some(2));
        let keys = [key("c", minutes(1), false), key("b", minutes(2), true)];
        assert_eq!(signing_key(&keys, now), Some(1));
        assert_eq!(signing_key(&[], now), None);
    }
}
