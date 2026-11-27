//! Import: a server's SQLite database copied into another database, row by
//! row. It is how a seedling or a grove becomes a forest (spec `forest.md`
//! §9): a SQLite backup cannot be restored into PostgreSQL.
//!
//! The tables have the same shapes in both databases, and what is encrypted
//! is encrypted the same way: a row is copied as it is, under the same
//! master key. Nothing is decrypted on the way. The VSID secret and the
//! signing keys come with the rest, so every identifier an application
//! holds and every token issued stay valid; the domain cannot change,
//! passkeys are bound to it.
//!
//! What a single node keeps in its memory (ceremonies in progress, codes)
//! is not in its database and is not copied: sign-ins in progress during
//! the move start again. Sessions are copied.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use sqlx::{
    Row as _, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use crate::{
    backup::{Inspection, inspect},
    error::{Error, Result},
    store::EncryptedStore,
};

/// How many rows are read from the source at a time.
const PAGE: i64 = 500;

/// The types a column of the schema has ([`crate::for_postgres`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    Integer,
    Blob,
}

struct Column {
    name: String,
    kind: Kind,
}

struct Table {
    name: String,
    columns: Vec<Column>,
    /// The tables its rows point to: filled before it.
    parents: BTreeSet<String>,
}

/// What an import copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    /// What the source held, as checked before anything was written.
    pub inspection: Inspection,
    /// The rows copied, per table, in the order they were written.
    pub tables: Vec<(String, u64)>,
}

/// Tables that are no part of what a server is: the record of the schema's
/// steps, SQLite's own, and what lives minutes (never in a single node's
/// database, except in tests).
fn skipped(table: &str) -> bool {
    table == "_sqlx_migrations"
        || table.starts_with("sqlite_")
        || table == "pending"
        || table == "used_assertions"
}

/// A name of the schema: lowercase letters, digits and `_`. Names are read
/// from the source file and written into statements: anything else is
/// refused, whatever the file claims to be.
fn plain(name: &str) -> Result<&str> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok {
        Ok(name)
    } else {
        Err(Error::NotABackup(format!(
            "{name:?} is not a name of the schema"
        )))
    }
}

/// The tables of the source, each after the ones its rows point to.
async fn tables(source: &SqlitePool) -> Result<Vec<Table>> {
    let named = sqlx::query("SELECT name, sql FROM sqlite_master WHERE type = 'table'")
        .fetch_all(source)
        .await?;
    let mut found = BTreeMap::new();
    for row in &named {
        let name: String = row.try_get("name")?;
        if skipped(&name) {
            continue;
        }
        let name = plain(&name)?.to_owned();
        let definition: String = row.try_get("sql")?;
        let counter = definition.contains("AUTOINCREMENT");

        let mut columns = Vec::new();
        // The name was checked above: PRAGMA takes no parameter.
        let described = sqlx::query(sqlx::AssertSqlSafe(format!("PRAGMA table_info({name})")))
            .fetch_all(source)
            .await?;
        for column in &described {
            let column_name: String = column.try_get("name")?;
            let declared: String = column.try_get("type")?;
            let key: i64 = column.try_get("pk")?;
            let kind = match declared.as_str() {
                "TEXT" => Kind::Text,
                "INTEGER" => Kind::Integer,
                "BLOB" => Kind::Blob,
                other => {
                    return Err(Error::NotABackup(format!(
                        "{name}.{column_name} has the type {other}, which the schema never uses"
                    )));
                }
            };
            // A counter is drawn again by the target, in the same order.
            if counter && key > 0 && kind == Kind::Integer {
                continue;
            }
            columns.push(Column {
                name: plain(&column_name)?.to_owned(),
                kind,
            });
        }

        let mut parents = BTreeSet::new();
        let pointed = sqlx::query(sqlx::AssertSqlSafe(format!(
            "PRAGMA foreign_key_list({name})"
        )))
        .fetch_all(source)
        .await?;
        for pointer in &pointed {
            let parent: String = pointer.try_get("table")?;
            if parent != name {
                parents.insert(plain(&parent)?.to_owned());
            }
        }
        found.insert(
            name.clone(),
            Table {
                name,
                columns,
                parents,
            },
        );
    }

    let mut ordered: Vec<Table> = Vec::with_capacity(found.len());
    while !found.is_empty() {
        let ready: Vec<String> = found
            .values()
            .filter(|table| {
                table
                    .parents
                    .iter()
                    .all(|parent| !found.contains_key(parent))
            })
            .map(|table| table.name.clone())
            .collect();
        if ready.is_empty() {
            return Err(Error::NotABackup(
                "its tables point to one another in a circle".into(),
            ));
        }
        for name in ready {
            if let Some(table) = found.remove(&name) {
                ordered.push(table);
            }
        }
    }
    Ok(ordered)
}

impl EncryptedStore {
    /// Copies every row of the SQLite database at `source` into this one,
    /// which must have its schema and no account. What this database held
    /// (the VSID secret and the signing key an initialisation made, its
    /// settings) is replaced by the source's: no account exists yet, so no
    /// identifier was ever given out under them.
    ///
    /// The source is checked first ([`inspect`]): a database of a brig·id
    /// server, at the schema this version knows, that this store's master
    /// key opens. It is read and never written. One transaction: an import
    /// that fails leaves this database as it was.
    pub async fn import(&self, source: &Path) -> Result<Imported> {
        let inspection = inspect(source, &self.master).await?;
        if inspection.schema != inspection.known_schema {
            return Err(Error::SchemaNotReady {
                applied: inspection.schema,
                known: inspection.known_schema,
            });
        }
        let target = self.schema().await?;
        if target.applied != target.known {
            return Err(Error::SchemaNotReady {
                applied: target.applied,
                known: target.known,
            });
        }

        let options = SqliteConnectOptions::new()
            .filename(source)
            .create_if_missing(false)
            .read_only(true);
        let from = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        let copied = self.copy_from(&from).await;
        from.close().await;
        Ok(Imported {
            inspection,
            tables: copied?,
        })
    }

    async fn copy_from(&self, from: &SqlitePool) -> Result<Vec<(String, u64)>> {
        let tables = tables(from).await?;
        let mut tx = self.pool.begin().await?;

        // Checked inside the transaction that writes.
        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await?;
        if accounts > 0 {
            return Err(Error::NotEmpty);
        }
        // What the initialisation recorded about the schema belongs to this
        // database, not to the source.
        let kept_settings =
            sqlx::query("SELECT name, value FROM settings WHERE name LIKE 'schema.%'")
                .fetch_all(&mut *tx)
                .await?
                .iter()
                .map(|row| Ok((row.try_get("name")?, row.try_get("value")?)))
                .collect::<Result<Vec<(String, String)>>>()?;

        for table in tables.iter().rev() {
            sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {}", table.name)))
                .execute(&mut *tx)
                .await?;
        }

        let mut copied = Vec::with_capacity(tables.len());
        for table in &tables {
            let names: Vec<&str> = table.columns.iter().map(|c| c.name.as_str()).collect();
            let read = format!(
                "SELECT rowid AS source_row, {} FROM {} WHERE rowid > ? ORDER BY rowid LIMIT {PAGE}",
                names.join(", "),
                table.name
            );
            let places: Vec<String> = (1..=names.len()).map(|n| format!("${n}")).collect();
            let write = format!(
                "INSERT INTO {} ({}) VALUES ({})",
                table.name,
                names.join(", "),
                places.join(", ")
            );
            let mut after = i64::MIN;
            let mut rows = 0u64;
            loop {
                // Names checked by `plain`; the rest is written here.
                let page = sqlx::query(sqlx::AssertSqlSafe(read.clone()))
                    .bind(after)
                    .fetch_all(from)
                    .await?;
                if page.is_empty() {
                    break;
                }
                for row in &page {
                    after = row.try_get("source_row")?;
                    let mut insert = sqlx::query(sqlx::AssertSqlSafe(write.clone()));
                    for column in &table.columns {
                        let name = column.name.as_str();
                        insert = match column.kind {
                            Kind::Text => insert.bind(row.try_get::<Option<String>, _>(name)?),
                            Kind::Integer => insert.bind(row.try_get::<Option<i64>, _>(name)?),
                            Kind::Blob => insert.bind(row.try_get::<Option<Vec<u8>>, _>(name)?),
                        };
                    }
                    insert.execute(&mut *tx).await?;
                    rows += 1;
                }
            }
            copied.push((table.name.clone(), rows));
        }

        // The certificate a single node obtained for itself is its own: a
        // server behind an ingress has no listener to use it on.
        sqlx::query("DELETE FROM server_secrets WHERE name LIKE 'acme%'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM settings WHERE name LIKE 'schema.%'")
            .execute(&mut *tx)
            .await?;
        for (name, value) in kept_settings {
            sqlx::query("INSERT INTO settings (name, value) VALUES ($1, $2)")
                .bind(name)
                .bind(value)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(copied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brigid_crypto::MasterKey;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::model::{AcmeSecret, AdminAction, Identity, User};

    fn master() -> MasterKey {
        MasterKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    /// A single node's database, in a file, with a little of everything.
    async fn source(dir: &Path) -> (std::path::PathBuf, Uuid, Uuid, [u8; 32]) {
        let path = dir.join("source.db");
        let store = EncryptedStore::new(&format!("sqlite:{}", path.display()), master())
            .await
            .unwrap();
        let vsid = *store.vsid_secret().await.unwrap();
        store.add_oidc_signing_key("kid-1", &[7; 32]).await.unwrap();
        store
            .set_acme_secret(AcmeSecret::Certificate, b"a certificate")
            .await
            .unwrap();
        let user = User {
            id: Uuid::new_v4(),
            username: "alice".into(),
            server: "example.org".into(),
            created_at: OffsetDateTime::now_utc(),
        };
        store.store_user(&user).await.unwrap();
        let identity = Identity {
            id: Uuid::new_v4(),
            account_id: user.id,
            name: "Work".into(),
            logo: "icon:ph:user".into(),
            description: None,
            attributes: brigid_identity::Attributes::new(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        store.add_identity(&identity).await.unwrap();
        let (client, _) = store
            .create_client("A site", &["https://site.example/cb".to_owned()], true)
            .await
            .unwrap();
        store
            .set_chosen_identity(user.id, &client.client_id, identity.id)
            .await
            .unwrap();
        for action in ["one", "two", "three"] {
            store
                .log_admin_action(&AdminAction {
                    action: action.into(),
                    actor: None,
                    account: None,
                    detail: None,
                })
                .await
                .unwrap();
        }
        store
            .set_limit(crate::Limit::PasskeysPerAccount, 7)
            .await
            .unwrap();
        store.close().await;
        (path, user.id, identity.id, vsid)
    }

    /// A server as its initialisation leaves it: a schema, a VSID secret
    /// and a signing key of its own, no account.
    async fn initialised() -> EncryptedStore {
        let store = EncryptedStore::new(&crate::testing::url().await, master())
            .await
            .unwrap();
        store.record_schema().await.unwrap();
        store.vsid_secret().await.unwrap();
        store
            .add_oidc_signing_key("made-here", &[9; 32])
            .await
            .unwrap();
        store
    }

    #[tokio::test]
    async fn every_row_arrives_and_the_identifiers_keep_their_secret() {
        let dir = tempfile::tempdir().unwrap();
        let (path, account, identity, vsid) = source(dir.path()).await;
        let target = initialised().await;

        let imported = target.import(&path).await.unwrap();
        assert_eq!(imported.inspection.accounts, 1);
        let rows = |table: &str| {
            imported
                .tables
                .iter()
                .find(|(name, _)| name == table)
                .map(|(_, rows)| *rows)
        };
        assert_eq!(rows("users"), Some(1));
        assert_eq!(rows("identities"), Some(1));
        assert_eq!(rows("admin_log"), Some(3));
        assert_eq!(rows("_sqlx_migrations"), None);

        // The source's secret and key replaced the ones made here.
        assert_eq!(*target.vsid_secret().await.unwrap(), vsid);
        let keys = target.oidc_signing_keys().await.unwrap();
        assert_eq!(
            keys.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>(),
            ["kid-1"]
        );
        // What was encrypted opens under the same master key.
        let user = target.fetch_user(account).await.unwrap().unwrap();
        assert_eq!(user.username, "alice");
        let identities = target.fetch_identities(account).await.unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].id, identity);
        let clients = target.list_clients().await.unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(
            target
                .chosen_identity(account, &clients[0].client_id)
                .await
                .unwrap(),
            Some(identity)
        );
        assert_eq!(
            target
                .limit(crate::Limit::PasskeysPerAccount)
                .await
                .unwrap(),
            7
        );
        // The log keeps its order, and the next entry follows.
        target
            .log_admin_action(&AdminAction {
                action: "four".into(),
                actor: None,
                account: None,
                detail: None,
            })
            .await
            .unwrap();
        let log = target.admin_log(10).await.unwrap();
        let actions: Vec<&str> = log.iter().map(|e| e.action.action.as_str()).collect();
        assert_eq!(actions, ["four", "three", "two", "one"]);
        // The certificate of the single node stays behind; what the
        // initialisation recorded about this schema stays.
        assert!(
            target
                .acme_secret(AcmeSecret::Certificate)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            target.schema().await.unwrap().fit(),
            crate::nodes::Fit::Serves
        );
    }

    #[tokio::test]
    async fn a_server_with_an_account_takes_no_import() {
        let dir = tempfile::tempdir().unwrap();
        let (path, ..) = source(dir.path()).await;
        let target = initialised().await;
        let user = User {
            id: Uuid::new_v4(),
            username: "bob".into(),
            server: "example.org".into(),
            created_at: OffsetDateTime::now_utc(),
        };
        target.store_user(&user).await.unwrap();
        assert!(matches!(target.import(&path).await, Err(Error::NotEmpty)));
        assert!(target.fetch_user(user.id).await.unwrap().is_some());
        let keys = target.oidc_signing_keys().await.unwrap();
        assert_eq!(keys[0].kid, "made-here");
    }

    #[tokio::test]
    async fn a_source_under_another_key_or_of_another_kind_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, ..) = source(dir.path()).await;
        let other = EncryptedStore::new(
            &crate::testing::url().await,
            MasterKey::from_hex(&"cd".repeat(32)).unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            other.import(&path).await,
            Err(Error::WrongMasterKey)
        ));

        let not_one = dir.path().join("notes.db");
        std::fs::write(&not_one, b"not a database").unwrap();
        let target = initialised().await;
        assert!(target.import(&not_one).await.is_err());
        let keys = target.oidc_signing_keys().await.unwrap();
        assert_eq!(keys[0].kid, "made-here");
    }

    #[test]
    fn only_names_of_the_schema_reach_a_statement() {
        assert!(plain("users").is_ok());
        assert!(plain("client_identities").is_ok());
        for bad in ["", "users; DROP TABLE users", "Users", "a b", "a\"b", "a-b"] {
            assert!(plain(bad).is_err(), "{bad}");
        }
    }
}
