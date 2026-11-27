//! What a server made of several nodes asks of its database, beyond the
//! store every edition uses (spec `forest.md` §5, §6).
//!
//! A server made of one node brings its schema up to date when it starts.
//! Several nodes must not: they start together, and an update replaces them
//! one by one, so that for a while nodes of two versions answer on one
//! database. One command initialises the server, before the nodes start
//! ([`EncryptedStore::begin_initialisation`], then [`EncryptedStore::migrate`]
//! and [`EncryptedStore::record_schema`]); a node only reads where the schema
//! is ([`EncryptedStore::schema`]) and serves or not ([`Schema::fit`]).

use sqlx::Row as _;

use crate::{
    error::{Error, Result},
    store::EncryptedStore,
};

/// The oldest schema step a node may have been built for and still work on
/// today's schema.
///
/// The rule of a rolling update: **a migration leaves the previous release
/// working.** A column is added in one release and relied on in the next; it
/// is removed one release after the code stopped reading it. A new step that
/// keeps to the rule leaves this constant alone. One that does not (the
/// nodes of an earlier release would write wrongly, or fail) raises it to
/// the first step whose nodes still work: when the server is initialised by
/// the new version, older nodes stop being ready instead of answering, and
/// the release's notes say that the update interrupts.
pub const SERVES_NODES_FROM: i64 = 5;

/// The setting that holds [`SERVES_NODES_FROM`] as the last initialisation
/// wrote it.
const SERVES_FROM_SETTING: &str = "schema.serves_nodes_from";

/// The key of the advisory lock an initialisation holds: "brigid" in ASCII.
const INITIALISATION_LOCK: i64 = 0x6272_6967_6964;

/// The latest schema step this build knows.
pub fn known_schema() -> i64 {
    crate::MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0)
}

/// Where the schema of a database is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schema {
    /// The latest step applied; 0 for a database without schema.
    pub applied: i64,
    /// The latest step this build knows.
    pub known: i64,
    /// The oldest step a node may know and still serve, as the last
    /// initialisation recorded it. `None`: never initialised for nodes.
    pub serves_from: Option<i64>,
}

/// Whether a node of this build can serve on a schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    /// It can.
    Serves,
    /// The database has no schema: the server was never initialised.
    Empty,
    /// The schema is older than this build: its initialisation has not run
    /// yet. The node waits.
    Behind,
    /// The schema was made for nodes newer than this one: it was left
    /// behind by an update, and must not write.
    LeftBehind,
    /// The schema has every step, and nothing recorded for nodes: it was
    /// brought up to date by something else than the initialisation.
    NotInitialised,
}

impl Schema {
    /// Whether a node of this build can serve on this schema.
    pub fn fit(&self) -> Fit {
        if self.applied == 0 {
            return Fit::Empty;
        }
        if self.applied < self.known {
            return Fit::Behind;
        }
        match self.serves_from {
            None => Fit::NotInitialised,
            Some(from) if self.known < from => Fit::LeftBehind,
            Some(_) => Fit::Serves,
        }
    }
}

/// An initialisation in progress: while it lives, no other runs on the
/// same PostgreSQL database.
pub struct Initialising {
    lock: Option<sqlx::Transaction<'static, sqlx::Any>>,
}

impl Initialising {
    /// Lets the next initialisation in.
    pub async fn done(self) -> Result<()> {
        if let Some(lock) = self.lock {
            lock.commit().await?;
        }
        Ok(())
    }
}

/// Whether a statement failed because a table is not there.
fn no_such_table(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(e) => {
            // PostgreSQL: undefined_table. SQLite has no code for it.
            e.code().as_deref() == Some("42P01") || e.message().contains("no such table")
        }
        _ => false,
    }
}

impl EncryptedStore {
    /// Waits for any initialisation running on this database to end, and
    /// keeps the next ones out until [`Initialising::done`]. On PostgreSQL
    /// an advisory lock held by a transaction of its own, which a process
    /// that dies gives back. SQLite has one writer and no nodes: nothing is
    /// held.
    pub async fn begin_initialisation(&self) -> Result<Initialising> {
        if !self.postgres().await? {
            return Ok(Initialising { lock: None });
        }
        let mut lock = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(INITIALISATION_LOCK)
            .execute(&mut *lock)
            .await?;
        Ok(Initialising { lock: Some(lock) })
    }

    /// Where the schema of this database is. Reads, and changes nothing.
    pub async fn schema(&self) -> Result<Schema> {
        let known = known_schema();
        let applied = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success",
        )
        .fetch_one(&self.pool)
        .await;
        let applied = match applied {
            Ok(applied) => applied,
            Err(e) if no_such_table(&e) => 0,
            Err(e) => return Err(e.into()),
        };
        // The settings came with step 3.
        let serves_from = if applied >= 3 {
            sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE name = $1")
                .bind(SERVES_FROM_SETTING)
                .fetch_optional(&self.pool)
                .await?
                .and_then(|value| value.parse().ok())
        } else {
            None
        };
        Ok(Schema {
            applied,
            known,
            serves_from,
        })
    }

    /// Records, once the schema is up to date, which nodes may serve on it:
    /// those built for [`SERVES_NODES_FROM`] or later. The last act of an
    /// initialisation.
    pub async fn record_schema(&self) -> Result<()> {
        let schema = self.schema().await?;
        if schema.applied != schema.known {
            return Err(Error::SchemaNotReady {
                applied: schema.applied,
                known: schema.known,
            });
        }
        sqlx::query(
            "INSERT INTO settings (name, value) VALUES ($1, $2) \
             ON CONFLICT (name) DO UPDATE SET value = excluded.value",
        )
        .bind(SERVES_FROM_SETTING)
        .bind(SERVES_NODES_FROM.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lets the PostgreSQL role `role` read and write the rows of every
    /// table of this schema, and nothing else: the role of the nodes, which
    /// cannot change the schema (spec `forest.md` §3). Run by the
    /// initialisation, as the role that owns the tables, each time: a table
    /// added by an update is then covered before a node needs it.
    /// `Ok(false)` on SQLite, which has no roles.
    pub async fn grant_to_nodes(&self, role: &str) -> Result<bool> {
        let named = !role.is_empty()
            && role.len() <= 63
            && role
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !named {
            return Err(Error::InvalidRole(role.to_owned()));
        }
        if !self.postgres().await? {
            return Ok(false);
        }
        let schema = sqlx::query("SELECT CAST(current_schema() AS TEXT) AS name")
            .fetch_one(&self.pool)
            .await?
            .try_get::<String, _>("name")?;
        // A schema's name can hold anything; quoted, with its quotes doubled.
        let schema = format!("\"{}\"", schema.replace('"', "\"\""));
        let role = format!("\"{role}\"");
        for statement in [
            format!("GRANT USAGE ON SCHEMA {schema} TO {role}"),
            format!(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role}"
            ),
            format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role}"),
            // Where the schema is: read by the nodes, written by the
            // initialisation alone.
            format!("REVOKE INSERT, UPDATE, DELETE ON {schema}._sqlx_migrations FROM {role}"),
        ] {
            // The role's name was checked above; the rest is written here.
            sqlx::query(sqlx::AssertSqlSafe(statement))
                .execute(&self.pool)
                .await?;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brigid_crypto::MasterKey;

    fn master() -> MasterKey {
        MasterKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    /// Adding a schema step is a decision about the nodes of the release
    /// before: they keep serving on it (the rule, leave
    /// `SERVES_NODES_FROM`), or they do not (raise it, and say in the
    /// release's notes that the update interrupts). Then change this pair.
    #[test]
    fn a_new_schema_step_says_which_nodes_still_serve() {
        assert_eq!((known_schema(), SERVES_NODES_FROM), (5, 5));
    }

    #[tokio::test]
    async fn a_database_without_schema_is_empty_and_nothing_is_created_by_reading() {
        let store = EncryptedStore::connect(&crate::testing::url().await, master(), None)
            .await
            .unwrap();
        let schema = store.schema().await.unwrap();
        assert_eq!(schema.applied, 0);
        assert_eq!(schema.fit(), Fit::Empty);
        assert_eq!(store.schema().await.unwrap().applied, 0);
        assert!(!store.kept_prepared().await.unwrap());
    }

    #[tokio::test]
    async fn a_schema_serves_once_its_initialisation_recorded_it() {
        let store = EncryptedStore::connect(&crate::testing::url().await, master(), None)
            .await
            .unwrap();
        let lock = store.begin_initialisation().await.unwrap();
        store.migrate().await.unwrap();
        assert_eq!(store.schema().await.unwrap().fit(), Fit::NotInitialised);
        store.record_schema().await.unwrap();
        store.prepare_kept().await.unwrap();
        lock.done().await.unwrap();

        let schema = store.schema().await.unwrap();
        assert_eq!(schema.applied, known_schema());
        assert_eq!(schema.serves_from, Some(SERVES_NODES_FROM));
        assert_eq!(schema.fit(), Fit::Serves);
        assert!(store.kept_prepared().await.unwrap());
        // A second initialisation changes nothing.
        let lock = store.begin_initialisation().await.unwrap();
        store.migrate().await.unwrap();
        store.record_schema().await.unwrap();
        lock.done().await.unwrap();
        assert_eq!(store.schema().await.unwrap(), schema);
    }

    #[test]
    fn a_node_serves_on_the_schemas_made_for_it() {
        let schema = |applied, known, serves_from| Schema {
            applied,
            known,
            serves_from,
        };
        // The update's initialisation has not run yet: the new node waits.
        assert_eq!(schema(5, 6, Some(5)).fit(), Fit::Behind);
        // It ran, and keeps to the rule: the old node still serves.
        assert_eq!(schema(6, 5, Some(5)).fit(), Fit::Serves);
        assert_eq!(schema(6, 6, Some(5)).fit(), Fit::Serves);
        // It ran, and breaks the nodes before step 6: the old one stops.
        assert_eq!(schema(7, 5, Some(6)).fit(), Fit::LeftBehind);
        assert_eq!(schema(7, 6, Some(6)).fit(), Fit::Serves);
    }

    /// Two initialisations at once on PostgreSQL: the second waits for the
    /// first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn of_two_initialisations_one_waits_for_the_other() {
        let url = crate::testing::url().await;
        let first = EncryptedStore::connect(&url, master(), None).await.unwrap();
        if !first.postgres().await.unwrap() {
            return;
        }
        let second = EncryptedStore::connect(&url, master(), None).await.unwrap();
        let held = first.begin_initialisation().await.unwrap();
        let waiting = tokio::spawn(async move {
            let lock = second.begin_initialisation().await.unwrap();
            lock.done().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!waiting.is_finished(), "the second did not wait");
        held.done().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), waiting)
            .await
            .expect("the second never got the lock")
            .unwrap();
    }

    #[tokio::test]
    async fn a_role_is_named_with_letters_digits_and_two_signs() {
        let store = EncryptedStore::new(&crate::testing::url().await, master())
            .await
            .unwrap();
        for bad in ["", "a\"b", "a b", "a;b", &"a".repeat(64)] {
            assert!(matches!(
                store.grant_to_nodes(bad).await,
                Err(Error::InvalidRole(_))
            ));
        }
    }

    /// The role of the nodes reads and writes rows, and changes neither the
    /// schema nor the record of its steps.
    #[tokio::test]
    async fn the_role_of_the_nodes_writes_rows_and_not_the_schema() {
        let Ok(base) = std::env::var("BRIGID_TEST_POSTGRES") else {
            return;
        };
        let url = crate::testing::url().await;
        let owner = EncryptedStore::new(&url, master()).await.unwrap();
        owner.prepare_kept().await.unwrap();
        let role = format!("node_{}", uuid::Uuid::new_v4().simple());
        // The role's name is drawn here.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {role} LOGIN PASSWORD 'node'"
        )))
        .execute(&owner.pool)
        .await
        .unwrap();
        assert!(owner.grant_to_nodes(&role).await.unwrap());

        // The same database and schema, as the role.
        let (scheme, rest) = url.split_once("://").unwrap();
        let (_, host) = rest.split_once('@').unwrap();
        let as_node = format!("{scheme}://{role}:node@{host}");
        assert!(as_node.contains("search_path"), "{base}");
        let node = EncryptedStore::connect(&as_node, master(), None)
            .await
            .unwrap();
        assert_eq!(node.schema().await.unwrap().applied, known_schema());
        node.vsid_secret().await.unwrap();
        node.keep("code", "codes", "a", b"v", i64::MAX)
            .await
            .unwrap();
        for forbidden in [
            "CREATE TABLE more (id TEXT)",
            "ALTER TABLE users ADD COLUMN more TEXT",
            "DROP TABLE pending",
            "DELETE FROM _sqlx_migrations",
        ] {
            assert!(
                sqlx::query(forbidden).execute(&node.pool).await.is_err(),
                "{forbidden}"
            );
        }
    }
}
