//! `backup <file>` and `restore <file>`: a copy of the database while the
//! server runs, and that copy put back in place of the database.
//!
//! A backup is the database file itself, encrypted under the same master
//! key. It moves a server between seedling and grove, which run the same
//! file, and brings a server back to the moment it was taken. Keep the
//! master key with it: without the key a backup is unreadable, and with it
//! anyone who has the backup has the server.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use brigid_crypto::MasterKey;
use brigid_store::backup::{Inspection, copy_database, inspect, settle, sidecar};

use crate::lock;

/// Creates the file a backup is written to: mode 0600, and never over an
/// existing file. Called before a command typed as root becomes the owner
/// of the database, so that the file can be anywhere root can write.
pub fn create_output(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => format!(
                "{} exists: a backup is never written over a file. Name another one.",
                path.display()
            ),
            _ => format!("{}: {e}", path.display()),
        })
}

/// A name next to `database` that nothing else uses: `<database><tag>-<pid>-<nanos>`.
fn beside(database: &Path, tag: &str) -> PathBuf {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    sidecar(database, &format!("{tag}-{}-{nanos}", std::process::id()))
}

/// Removes `path` and the files SQLite may have left next to it.
fn remove_with_sidecars(path: &Path) {
    for file in [
        path.to_owned(),
        sidecar(path, "-wal"),
        sidecar(path, "-shm"),
        sidecar(path, "-journal"),
    ] {
        let _ = fs::remove_file(file);
    }
}

fn not_in_memory(database: &Path) -> Result<(), String> {
    if database.as_os_str() == ":memory:" {
        return Err("the database is in memory: there is nothing to back up or restore".into());
    }
    Ok(())
}

/// Writes a consistent copy of `database` into `out`, the file `create_output`
/// made at `out_path`. The server may be running: the copy is one read
/// transaction. On failure, `out_path` is removed.
pub async fn backup(database: &Path, mut out: File, out_path: &Path) -> Result<(), String> {
    let written = async {
        not_in_memory(database)?;
        if !database.exists() {
            return Err(format!(
                "{} does not exist: there is no database to back up",
                database.display()
            ));
        }
        let _lock = lock::shared(database).map_err(|e| format!("{}: {e}", database.display()))?;
        // SQLite writes the copy by name; it is made next to the database,
        // which this process can write to, then copied into `out`, which it
        // may not be able to open any more.
        let copy = beside(database, ".backup");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&copy)
            .map_err(|e| format!("{}: {e}", copy.display()))?;
        let copied = async {
            copy_database(database, &copy)
                .await
                .map_err(|e| format!("the copy failed: {e}"))?;
            let mut from = File::open(&copy).map_err(|e| format!("{}: {e}", copy.display()))?;
            io::copy(&mut from, &mut out).map_err(|e| format!("{}: {e}", out_path.display()))?;
            out.sync_all()
                .map_err(|e| format!("{}: {e}", out_path.display()))
        }
        .await;
        remove_with_sidecars(&copy);
        copied
    }
    .await;
    if written.is_err() {
        let _ = fs::remove_file(out_path);
    }
    written
}

/// Keeps `database` as `<database>.before-restore-<stamp>` (then `-2`, `-3`…
/// when a restore of the same second kept one already): a second link to
/// the same file, or a copy where links cannot be made. Never over a file.
fn keep_aside(database: &Path, stamp: &str, mode: u32) -> Result<PathBuf, String> {
    for n in 1..100 {
        let name = match n {
            1 => format!(".before-restore-{stamp}"),
            n => format!(".before-restore-{stamp}-{n}"),
        };
        let aside = sidecar(database, &name);
        match fs::hard_link(database, &aside) {
            Ok(()) => return Ok(aside),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => {}
        }
        let mut to = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&aside)
        {
            Ok(to) => to,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", aside.display())),
        };
        let copied = File::open(database)
            .and_then(|mut from| io::copy(&mut from, &mut to))
            .and_then(|_| to.sync_all());
        if let Err(e) = copied {
            let _ = fs::remove_file(&aside);
            return Err(format!("{}: {e}", aside.display()));
        }
        return Ok(aside);
    }
    Err(format!(
        "{}: too many databases kept aside this second",
        database.display()
    ))
}

/// What `restore` did.
#[derive(Debug)]
pub struct Restored {
    /// Where the database it replaced is kept: `<database>.before-restore-<time>`.
    /// `None` when there was none.
    pub aside: Option<PathBuf>,
    pub inspection: Inspection,
}

/// Puts the backup read from `source` in place of `database`, for a server
/// at `domain` whose master key is `master`.
///
/// Refused, with nothing changed:
/// - while anything uses the database: a server or a command of this
///   version (they hold `<database>.lock`), or any process that has it open
///   in WAL mode (an older server, Litestream, `sqlite3`), seen by the
///   write-ahead log that stays after this closes the database. A process
///   of an older version, with the database in rollback mode and between
///   two transactions, cannot be seen: stop the server before a restore;
/// - when the backup is not a database of a brig·id server, has a schema
///   newer than this version's, or does not open with `master`;
/// - when its accounts belong to another domain than `domain`: their
///   passkeys work on no other. A backup without account cannot be checked.
///
/// The database replaced is kept aside, and the backup replaces it in one
/// rename, with the owner and permissions the database had.
pub async fn restore(
    database: &Path,
    mut source: File,
    master: &MasterKey,
    domain: &str,
) -> Result<Restored, String> {
    not_in_memory(database)?;
    let _lock = lock::exclusive(database)
        .map_err(|e| format!("{}: {e}", lock::path(database).display()))?
        .ok_or_else(|| {
            format!(
                "the server, or another command, is using {}: stop it, then restore",
                database.display()
            )
        })?;

    // The database in place: whole in its own file before it is set aside,
    // and used by nothing else.
    let existing = database.exists();
    let (mode, owner) = if existing {
        if !settle(database)
            .await
            .map_err(|e| format!("{}: {e}", database.display()))?
        {
            return Err(format!(
                "something still has {} open (the server, Litestream, sqlite3): stop it, then \
                 restore",
                database.display()
            ));
        }
        if sidecar(database, "-journal").exists() {
            return Err(format!(
                "{} has a journal SQLite did not resolve: something still uses it",
                database.display()
            ));
        }
        // No connection is left, and its log is folded in: a stale index of
        // the log must not meet the restored file.
        let _ = fs::remove_file(sidecar(database, "-shm"));
        let meta = fs::metadata(database).map_err(|e| format!("{}: {e}", database.display()))?;
        (
            meta.permissions().mode() & 0o777,
            Some((meta.uid(), meta.gid())),
        )
    } else {
        (0o600, None)
    };
    let me = crate::owner::effective_uid();
    if let Some((uid, _)) = owner
        && uid != me
        && me != 0
    {
        return Err(format!(
            "{} belongs to uid {uid}: restore as that user, or as root",
            database.display()
        ));
    }

    let incoming = beside(database, ".restore");
    let placed = async {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&incoming)
            .map_err(|e| format!("{}: {e}", incoming.display()))?;
        io::copy(&mut source, &mut file).map_err(|e| format!("reading the backup: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("{}: {e}", incoming.display()))?;
        drop(file);

        let inspection = inspect(&incoming, master)
            .await
            .map_err(|e| format!("this backup cannot be restored: {e}"))?;
        // Opening it may have left SQLite's files next to the copy.
        let _ = fs::remove_file(sidecar(&incoming, "-wal"));
        let _ = fs::remove_file(sidecar(&incoming, "-shm"));
        let expected = BTreeSet::from([domain.to_owned()]);
        if !inspection.domains.is_empty() && inspection.domains != expected {
            let theirs: Vec<&str> = inspection.domains.iter().map(String::as_str).collect();
            return Err(format!(
                "this backup holds the accounts of {}, and this server is {domain}: a passkey \
                 works only on the domain that created it",
                theirs.join(", ")
            ));
        }

        fs::set_permissions(&incoming, fs::Permissions::from_mode(mode))
            .map_err(|e| format!("{}: {e}", incoming.display()))?;
        // The owner the database had. Root can give it; its owner keeps
        // it, in a group of its own if it is not in the database's.
        if let Some((uid, gid)) = owner
            && let Err(e) = std::os::unix::fs::chown(&incoming, Some(uid), Some(gid))
            && me == 0
        {
            return Err(format!("{}: {e}", incoming.display()));
        }

        // The database in place stays, under another name (a second link
        // to the same file, or a copy where links cannot be made), and the
        // backup takes its name in one step.
        let aside = if existing {
            let now = time::OffsetDateTime::now_utc();
            let stamp = format!(
                "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
                now.year(),
                u8::from(now.month()),
                now.day(),
                now.hour(),
                now.minute(),
                now.second()
            );
            Some(keep_aside(database, &stamp, mode)?)
        } else {
            None
        };
        fs::rename(&incoming, database).map_err(|e| format!("{}: {e}", database.display()))?;
        if let Some(dir) = database.parent().filter(|d| !d.as_os_str().is_empty())
            && let Ok(dir) = File::open(dir)
        {
            let _ = dir.sync_all();
        }
        Ok(Restored { aside, inspection })
    }
    .await;
    if placed.is_err() {
        remove_with_sidecars(&incoming);
    }
    placed
}

#[cfg(test)]
mod tests {
    use brigid_identity::{Attribute, Attributes, identity_vsid};
    use brigid_store::{Credential, EncryptedStore, Identity, User};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;

    const DOMAIN: &str = "id.example.org";

    fn master() -> MasterKey {
        MasterKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn other_master() -> MasterKey {
        MasterKey::from_hex(&"cd".repeat(32)).unwrap()
    }

    async fn open(path: &Path, master: MasterKey) -> EncryptedStore {
        EncryptedStore::new(&format!("sqlite:{}?mode=rwc", path.display()), master)
            .await
            .unwrap()
    }

    /// A server as it runs: its VSID secret, two accounts on `domain` with a
    /// passkey and identities each, a site, and the identity each account
    /// chose for it.
    async fn populated(path: &Path, domain: &str) -> (EncryptedStore, String) {
        let store = open(path, master()).await;
        store.vsid_secret().await.unwrap();
        let (site, _) = store
            .create_client("Shop", &["https://shop.example/cb".to_owned()], true)
            .await
            .unwrap();
        for (n, name) in ["swift-otter-1", "calm-heron-2"].into_iter().enumerate() {
            let user = User {
                id: Uuid::new_v4(),
                username: name.to_owned(),
                server: domain.to_owned(),
                created_at: OffsetDateTime::now_utc(),
            };
            let passkey = Credential {
                id: Uuid::new_v4(),
                user_id: user.id,
                data: vec![n as u8; 40],
            };
            store
                .register_user_with_credential(&user, &passkey, None)
                .await
                .unwrap();
            for persona in ["Work", "Games"] {
                let now = OffsetDateTime::now_utc();
                store
                    .store_identity(&Identity {
                        id: Uuid::new_v4(),
                        account_id: user.id,
                        name: format!("{persona} {n}"),
                        logo: "icon:ph:rocket-launch".to_owned(),
                        description: Some("only mine".to_owned()),
                        attributes: Attributes::from([(
                            Attribute::Email,
                            format!("{n}@x.example"),
                        )]),
                        created_at: now,
                        updated_at: now,
                    })
                    .await
                    .unwrap();
            }
            let chosen = store.fetch_identities(user.id).await.unwrap()[1].id;
            store
                .set_chosen_identity(user.id, &site.client_id, chosen)
                .await
                .unwrap();
        }
        (store, site.client_id)
    }

    /// Everything a person and a site see of a server: per account, its
    /// name, its identities and the VSID the site receives for the chosen
    /// one.
    async fn seen(store: &EncryptedStore, site: &str) -> Vec<(String, Vec<String>, String)> {
        let secret = store.vsid_secret().await.unwrap();
        let mut seen = Vec::new();
        for account in store.list_accounts().await.unwrap() {
            let identities: Vec<String> = store
                .fetch_identities(account.id)
                .await
                .unwrap()
                .into_iter()
                .map(|i| format!("{} {} {:?} {:?}", i.id, i.name, i.description, i.attributes))
                .collect();
            let chosen = store
                .chosen_identity(account.id, site)
                .await
                .unwrap()
                .expect("an identity is chosen");
            let vsid = identity_vsid(chosen, site, &*secret).to_string();
            seen.push((account.username, identities, vsid));
        }
        seen
    }

    async fn back_up(database: &Path, to: &Path) {
        let out = create_output(to).unwrap();
        backup(database, out, to).await.unwrap();
    }

    #[tokio::test]
    async fn a_backup_restored_elsewhere_is_the_same_server() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.db");
        // Taken while the server has the database open.
        let (store, site) = populated(&live, DOMAIN).await;
        let before = seen(&store, &site).await;
        let copy = dir.path().join("brigid.backup");
        back_up(&live, &copy).await;
        assert_eq!(
            fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Another server, with a database of its own, takes it.
        let target = dir.path().join("target.db");
        let (other, other_site) = populated(&target, DOMAIN).await;
        let replaced = seen(&other, &other_site).await;
        other.close().await;
        let restored = restore(&target, File::open(&copy).unwrap(), &master(), DOMAIN)
            .await
            .unwrap();
        assert_eq!(restored.inspection.accounts, 2);
        assert_eq!(restored.inspection.identities, 4);
        assert_eq!(
            restored.inspection.domains,
            BTreeSet::from([DOMAIN.to_owned()])
        );

        let after = open(&target, master()).await;
        assert_eq!(seen(&after, &site).await, before);
        for account in after.list_accounts().await.unwrap() {
            assert_eq!(after.fetch_credentials(account.id).await.unwrap().len(), 1);
        }
        // What it replaced is kept, whole.
        let aside = restored.aside.expect("the target had a database");
        assert!(
            aside
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("target.db.before-restore-")
        );
        let kept = open(&aside, master()).await;
        assert_eq!(seen(&kept, &other_site).await, replaced);
        // Nothing of the restore is left next to the database.
        let mut left: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains(".restore-") || n.contains(".backup-"))
            .collect();
        left.sort();
        assert!(left.is_empty(), "{left:?}");
        drop(store);
    }

    #[tokio::test]
    async fn a_backup_never_writes_over_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.db");
        populated(&live, DOMAIN).await;
        let copy = dir.path().join("brigid.backup");
        fs::write(&copy, b"something kept").unwrap();
        let err = create_output(&copy).unwrap_err();
        assert!(err.contains("never written over"), "{err}");
        assert_eq!(fs::read(&copy).unwrap(), b"something kept");
    }

    /// A restore that is refused changes nothing: the database in place is
    /// the file that was there (a restore puts another in its place).
    async fn refused(target: &Path, copy: &Path, master: &MasterKey, domain: &str) -> String {
        let before = fs::metadata(target).unwrap().ino();
        let err = restore(target, File::open(copy).unwrap(), master, domain)
            .await
            .unwrap_err();
        assert_eq!(fs::metadata(target).unwrap().ino(), before, "{err}");
        let names: Vec<String> = fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains("before-restore") || n.contains(".restore-"))
            .collect();
        assert!(names.is_empty(), "{names:?}");
        err
    }

    #[tokio::test]
    async fn a_backup_under_another_key_or_domain_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.db");
        let (store, _) = populated(&live, DOMAIN).await;
        store.close().await;
        let copy = dir.path().join("brigid.backup");
        back_up(&live, &copy).await;
        let target = dir.path().join("target.db");
        open(&target, master()).await.close().await;

        let err = refused(&target, &copy, &other_master(), DOMAIN).await;
        assert!(err.contains("another master key"), "{err}");
        let err = refused(&target, &copy, &master(), "id.other.example").await;
        assert!(err.contains("id.example.org"), "{err}");
        assert!(err.contains("only on the domain"), "{err}");
        let not_a_database = dir.path().join("notes.txt");
        fs::write(&not_a_database, b"hello").unwrap();
        let err = refused(&target, &not_a_database, &master(), DOMAIN).await;
        assert!(err.contains("cannot be restored"), "{err}");
    }

    #[tokio::test]
    async fn a_backup_of_a_newer_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.db");
        let (store, _) = populated(&live, DOMAIN).await;
        store.close().await;
        let copy = dir.path().join("brigid.backup");
        back_up(&live, &copy).await;
        // A step of the schema this version does not know.
        let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", copy.display()))
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
             VALUES (9999, 'from the future', 1, x'00', 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
        let target = dir.path().join("target.db");
        open(&target, master()).await.close().await;

        let err = refused(&target, &copy, &master(), DOMAIN).await;
        assert!(err.contains("newer version"), "{err}");
        assert!(err.contains("9999"), "{err}");
    }

    #[tokio::test]
    async fn a_restore_waits_for_the_server_to_stop() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("live.db");
        let (store, _) = populated(&live, DOMAIN).await;
        store.close().await;
        let copy = dir.path().join("brigid.backup");
        back_up(&live, &copy).await;
        let target = dir.path().join("target.db");

        // A server of this version holds the lock.
        let server = open(&target, master()).await;
        let held = lock::shared(&target).unwrap();
        let err = refused(&target, &copy, &master(), DOMAIN).await;
        assert!(err.contains("stop it"), "{err}");
        drop(held);

        // One that holds no lock, with the database in WAL mode (as with
        // Litestream), still has it open: seen by its log.
        let switch = sqlx::SqlitePool::connect(&format!("sqlite:{}", target.display()))
            .await
            .unwrap();
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&switch)
            .await
            .unwrap();
        switch.close().await;
        server.vsid_secret().await.unwrap();
        let err = refused(&target, &copy, &master(), DOMAIN).await;
        assert!(err.contains("still has"), "{err}");

        // Stopped, it is restored. Twice in the same second, each database
        // replaced is kept.
        server.close().await;
        let first = restore(&target, File::open(&copy).unwrap(), &master(), DOMAIN)
            .await
            .unwrap()
            .aside
            .unwrap();
        let second = restore(&target, File::open(&copy).unwrap(), &master(), DOMAIN)
            .await
            .unwrap()
            .aside
            .unwrap();
        assert_ne!(first, second);
        assert!(first.exists() && second.exists());
    }
}
