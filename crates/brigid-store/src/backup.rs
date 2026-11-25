//! Backups: a consistent copy of a database while the server runs, and the
//! checks a copy passes before it replaces the database of a server.
//!
//! A backup is the database itself, as SQLite writes it: encrypted under the
//! same master key, holding the VSID secret and the signing keys. It moves a
//! server between editions that run the same file (seedling, grove), and
//! brings one back to the moment of the copy.

use std::{collections::BTreeSet, path::Path};

use brigid_crypto::MasterKey;
use sqlx::{
    Row as _, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use crate::{
    error::{Error, Result},
    store::{dec, server_secret_key, user_key},
};

/// One connection to the database file at `path`, which must exist. No
/// migration runs: a copy is taken, or checked, as it is.
async fn open(path: &Path) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .foreign_keys(true);
    Ok(SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?)
}

/// Writes a consistent copy of the database at `database` into `into`, an
/// empty file or one that does not exist (SQLite's `VACUUM INTO`). The copy
/// is one read transaction: a server writing meanwhile waits at most for
/// the copy, and the copy holds every transaction committed before it began.
/// Checked (`PRAGMA quick_check`) once written.
pub async fn copy_database(database: &Path, into: &Path) -> Result<()> {
    let into_name = into
        .to_str()
        .ok_or_else(|| Error::NotABackup(format!("{} is not UTF-8", into.display())))?;
    let pool = open(database).await?;
    let copied = sqlx::query("VACUUM INTO ?")
        .bind(into_name)
        .execute(&pool)
        .await;
    pool.close().await;
    copied?;
    let copy = open(into).await?;
    let check: Result<String> = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_one(&copy)
        .await
        .map_err(Error::from);
    copy.close().await;
    match check? {
        ok if ok == "ok" => Ok(()),
        other => Err(Error::NotABackup(format!(
            "the copy fails its check: {other}"
        ))),
    }
}

/// Brings into the database file what its write-ahead log holds, if it has
/// one, and closes it: a database left by a server that stopped abruptly is
/// then whole in its main file. `Ok(false)` when the log is still there
/// after the close: something else (a server, Litestream, `sqlite3`) still
/// has the database open.
pub async fn settle(database: &Path) -> Result<bool> {
    let pool = open(database).await?;
    let settled = async {
        // A read: a rollback journal left by a crash is rolled back.
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sqlite_master")
            .fetch_one(&pool)
            .await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&pool)
            .await?;
        Ok::<_, Error>(())
    }
    .await;
    pool.close().await;
    settled?;
    Ok(!sidecar(database, "-wal").exists())
}

/// `<database><suffix>`: the files SQLite keeps next to a database.
pub fn sidecar(database: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

/// What a backup holds, as far as it is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// The latest step of its schema.
    pub schema: i64,
    /// The latest step this version knows.
    pub known_schema: i64,
    pub accounts: u64,
    pub identities: u64,
    /// The domains its accounts were created on: passkeys are bound to the
    /// domain. Empty for a backup without account.
    pub domains: BTreeSet<String>,
}

/// Checks that the database file at `path` can serve as this server's
/// database under `master`, writing nothing to it but what SQLite writes
/// when it opens a file:
///
/// - it is a database of a brig·id server ([`Error::NotABackup`]), whose
///   schema steps are this version's or earlier ones ([`Error::NewerSchema`],
///   [`Error::SchemaMismatch`]): an earlier schema is migrated at the next
///   start, a newer one cannot be;
/// - `master` opens its VSID secret and every account's name and domain
///   ([`Error::WrongMasterKey`]).
pub async fn inspect(path: &Path, master: &MasterKey) -> Result<Inspection> {
    let pool = open(path).await?;
    let inspection = inspect_pool(&pool, master).await;
    pool.close().await;
    inspection
}

async fn inspect_pool(pool: &SqlitePool, master: &MasterKey) -> Result<Inspection> {
    let not_brigid = |e: sqlx::Error| Error::NotABackup(e.to_string());
    let steps = sqlx::query("SELECT version, checksum, success FROM _sqlx_migrations")
        .fetch_all(pool)
        .await
        .map_err(not_brigid)?;
    let known_schema = crate::MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0);
    let mut schema = 0;
    for step in &steps {
        let version: i64 = step.try_get("version")?;
        let checksum: Vec<u8> = step.try_get("checksum")?;
        let success: bool = step.try_get("success")?;
        schema = schema.max(version);
        if version > known_schema {
            return Err(Error::NewerSchema {
                found: version,
                known: known_schema,
            });
        }
        match crate::MIGRATOR.iter().find(|m| m.version == version) {
            Some(known) if success && *known.checksum == *checksum => {}
            _ => return Err(Error::SchemaMismatch(version)),
        }
    }
    if steps.is_empty() {
        return Err(Error::NotABackup("its schema is empty".into()));
    }

    let wrong_key = |e: Error| match e {
        Error::Crypto(_) | Error::InvalidBlob => Error::WrongMasterKey,
        other => other,
    };
    let vsid: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM server_secrets WHERE name = 'vsid'")
            .fetch_optional(pool)
            .await
            .map_err(not_brigid)?;
    let Some(vsid) = vsid else {
        return Err(Error::NotABackup(
            "it holds no VSID secret: a server never started on it".into(),
        ));
    };
    dec(&*server_secret_key(master)?, &vsid).map_err(wrong_key)?;

    let mut domains = BTreeSet::new();
    let users = sqlx::query("SELECT id, username, server FROM users")
        .fetch_all(pool)
        .await
        .map_err(not_brigid)?;
    for user in &users {
        let id: uuid::Uuid = user.try_get::<String, _>("id")?.parse()?;
        let key = user_key(master, &id)?;
        dec(&key, &user.try_get::<Vec<u8>, _>("username")?).map_err(wrong_key)?;
        let server = dec(&key, &user.try_get::<Vec<u8>, _>("server")?).map_err(wrong_key)?;
        domains.insert(String::from_utf8(server)?);
    }
    let identities: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identities")
        .fetch_one(pool)
        .await
        .map_err(not_brigid)?;
    Ok(Inspection {
        schema,
        known_schema,
        accounts: users.len() as u64,
        identities: u64::try_from(identities).unwrap_or(0),
        domains,
    })
}
