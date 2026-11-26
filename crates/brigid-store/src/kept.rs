//! What the nodes of one server share and that lives minutes: passkey
//! ceremonies in progress, sign-in requests of applications waiting for the
//! person, authorization codes, and the assertions of clients already
//! presented (spec `forest.md` §3).
//!
//! A server made of one node keeps all of it in its memory and never comes
//! here. A server made of several keeps it in the database they share, in
//! two tables of their own:
//!
//! - `pending`: a value under a kind and an identifier, until a date. On
//!   PostgreSQL it is an **unlogged** table: not written to the database's
//!   log, and empty again after a crash or a failover. The failure is
//!   closed: ceremonies in progress start again, and nothing already taken
//!   can come back.
//! - `used_assertions`: an ordinary table. Its purpose is to be remembered.
//!
//! Neither is part of the numbered schema: nothing in them is data, and a
//! value whose shape changes gets a new kind instead of a migration.
//!
//! What a reader of the database learns from `pending`: how many values of
//! each kind are waiting, and until when. The identifier stored is a hash of
//! the one the browser or the application holds, so no row can be presented;
//! the value is encrypted, and bound to its row, so none can be read or
//! moved under another identifier.

use brigid_crypto::MasterKey;
use sha3::{Digest, Sha3_256};
use sqlx::Row as _;
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    store::{EncryptedStore, dec, enc},
};

/// The two tables, as SQLite holds them; PostgreSQL gets the same with the
/// type names of its schema ([`crate::for_postgres`]) and `{TABLE}` unlogged.
const TABLES: [&str; 4] = [
    "CREATE {TABLE} IF NOT EXISTS pending (\
         kind       TEXT    NOT NULL, \
         id         TEXT    NOT NULL, \
         family     TEXT    NOT NULL, \
         value      BLOB    NOT NULL, \
         expires_at INTEGER NOT NULL, \
         PRIMARY KEY (kind, id))",
    "CREATE INDEX IF NOT EXISTS idx_pending_expires_at ON pending(expires_at)",
    "CREATE TABLE IF NOT EXISTS used_assertions (\
         client_id  TEXT    NOT NULL, \
         jti        TEXT    NOT NULL, \
         expires_at INTEGER NOT NULL, \
         PRIMARY KEY (client_id, jti))",
    "CREATE INDEX IF NOT EXISTS idx_used_assertions_expires_at ON used_assertions(expires_at)",
];

/// The key that encrypts the values of `pending`. Its own derivation: after
/// a rotation of the master key the values kept under the old one cannot be
/// read, and are as absent.
fn kept_key(master: &MasterKey) -> Result<Zeroizing<[u8; 32]>> {
    brigid_crypto::hkdf::derive_user_key(master, b"shared-state", b"store-fields")
        .map_err(Error::from)
}

/// What names a row: SHA3-256 of the kind and the identifier. The
/// identifier itself (a code, a request id) is never stored.
fn row_id(kind: &str, id: &str) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update((kind.len() as u32).to_be_bytes());
    hash.update(kind.as_bytes());
    hash.update(id.as_bytes());
    hash.finalize().into()
}

impl EncryptedStore {
    /// Creates the two tables if they are not there. Run once, by what
    /// initialises a server made of several nodes; nodes never do it.
    pub async fn prepare_kept(&self) -> Result<()> {
        let postgres = self.pool.acquire().await?.backend_name() == "PostgreSQL";
        for table in TABLES {
            let statement = if postgres {
                crate::for_postgres(table).replace("{TABLE}", "UNLOGGED TABLE")
            } else {
                table.replace("{TABLE}", "TABLE")
            };
            // The statements above, never input.
            sqlx::query(sqlx::AssertSqlSafe(statement))
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Keeps `value` under `kind` and `id` until `expires_at` (Unix
    /// seconds). `family` is what the kind is counted with
    /// ([`Self::count_kept`]).
    pub async fn keep(
        &self,
        kind: &str,
        family: &str,
        id: &str,
        value: &[u8],
        expires_at: i64,
    ) -> Result<()> {
        let row = row_id(kind, id);
        // The row's name goes inside what is encrypted: a value moved under
        // another identifier is refused when read.
        let mut bound = Zeroizing::new(Vec::with_capacity(row.len() + value.len()));
        bound.extend_from_slice(&row);
        bound.extend_from_slice(value);
        sqlx::query(
            "INSERT INTO pending (kind, id, family, value, expires_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(kind)
        .bind(helpers4::hex::encode(&row))
        .bind(family)
        .bind(enc(&*kept_key(&self.master)?, &bound)?)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The value kept under `kind` and `id`, left in place. `None` when
    /// there is none, or it expired before `now`.
    pub async fn kept(&self, kind: &str, id: &str, now: i64) -> Result<Option<Vec<u8>>> {
        let row = row_id(kind, id);
        let found: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT value FROM pending WHERE kind = $1 AND id = $2 AND expires_at > $3",
        )
        .bind(kind)
        .bind(helpers4::hex::encode(&row))
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        found.map(|raw| self.unbind(&row, &raw)).transpose()
    }

    /// Takes the value kept under `kind` and `id` out. One statement removes
    /// the row and returns it: of any number of nodes that present the same
    /// identifier at the same instant, the database gives the row to one.
    pub async fn take_kept(&self, kind: &str, id: &str, now: i64) -> Result<Option<Vec<u8>>> {
        let row = row_id(kind, id);
        let taken = sqlx::query(
            "DELETE FROM pending WHERE kind = $1 AND id = $2 AND expires_at > $3 \
             RETURNING value",
        )
        .bind(kind)
        .bind(helpers4::hex::encode(&row))
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        taken
            .map(|taken| self.unbind(&row, &taken.try_get::<Vec<u8>, _>("value")?))
            .transpose()
    }

    /// How many values of `family` are kept and not expired.
    pub async fn count_kept(&self, family: &str, now: i64) -> Result<i64> {
        Ok(
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM pending WHERE family = $1 AND expires_at > $2",
            )
            .bind(family)
            .bind(now)
            .fetch_one(&self.pool)
            .await?,
        )
    }

    /// Whether the assertion `jti` of `client_id` is presented for the first
    /// time; it is remembered until `expires_at`. An assertion remembered
    /// and expired before `now` counts as never presented: its own date
    /// refuses it.
    pub async fn first_use_of_assertion(
        &self,
        client_id: &str,
        jti: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<bool> {
        let written = sqlx::query(
            "INSERT INTO used_assertions (client_id, jti, expires_at) VALUES ($1, $2, $3) \
             ON CONFLICT (client_id, jti) DO UPDATE SET expires_at = excluded.expires_at \
             WHERE used_assertions.expires_at < $4",
        )
        .bind(client_id)
        // A fixed size whatever the client sent, and nothing to read.
        .bind(helpers4::hex::encode(&row_id(client_id, jti)))
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(written.rows_affected() == 1)
    }

    /// How many assertions are remembered and not expired.
    pub async fn count_assertions(&self, now: i64) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM used_assertions WHERE expires_at >= $1")
                .bind(now)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    /// Removes what expired before `now` from both tables; returns how many
    /// rows went. Every node does it every few seconds: two at once is
    /// harmless.
    pub async fn sweep_kept(&self, now: i64) -> Result<u64> {
        let pending = sqlx::query("DELETE FROM pending WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        let assertions = sqlx::query("DELETE FROM used_assertions WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(pending.rows_affected() + assertions.rows_affected())
    }

    /// The value inside `raw`, if it was kept under the row `row`.
    fn unbind(&self, row: &[u8; 32], raw: &[u8]) -> Result<Vec<u8>> {
        let bound = Zeroizing::new(dec(&*kept_key(&self.master)?, raw)?);
        match bound.split_at_checked(row.len()) {
            Some((name, value)) if name == row => Ok(value.to_vec()),
            _ => Err(Error::InvalidBlob),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn master() -> MasterKey {
        MasterKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    async fn store() -> EncryptedStore {
        let store = EncryptedStore::new(&crate::testing::url().await, master())
            .await
            .unwrap();
        store.prepare_kept().await.unwrap();
        store
    }

    #[tokio::test]
    async fn preparing_twice_changes_nothing() {
        let store = store().await;
        store.keep("code", "codes", "a", b"v", 100).await.unwrap();
        store.prepare_kept().await.unwrap();
        assert_eq!(
            store.kept("code", "a", 50).await.unwrap(),
            Some(b"v".to_vec())
        );
    }

    /// What makes a crash fail closed: on PostgreSQL the values are in a
    /// table that comes back empty, and the assertions in one that lasts.
    #[tokio::test]
    async fn on_postgresql_pending_is_unlogged_and_assertions_are_not() {
        let store = store().await;
        if store.pool.acquire().await.unwrap().backend_name() != "PostgreSQL" {
            return;
        }
        for (table, persistence) in [("pending", "u"), ("used_assertions", "p")] {
            let found: String = sqlx::query_scalar(
                "SELECT c.relpersistence::text FROM pg_class c \
                 JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE c.relname = $1 AND n.nspname = current_schema()",
            )
            .bind(table)
            .fetch_one(&store.pool)
            .await
            .unwrap();
            assert_eq!(found, persistence, "{table}");
        }
    }

    #[tokio::test]
    async fn a_value_is_read_as_often_as_asked_and_taken_once() {
        let store = store().await;
        store
            .keep("authorization", "authorizations", "a", b"value", 100)
            .await
            .unwrap();
        for _ in 0..3 {
            assert_eq!(
                store.kept("authorization", "a", 50).await.unwrap(),
                Some(b"value".to_vec())
            );
        }
        assert_eq!(
            store.take_kept("authorization", "a", 50).await.unwrap(),
            Some(b"value".to_vec())
        );
        assert_eq!(
            store.take_kept("authorization", "a", 50).await.unwrap(),
            None
        );
        assert_eq!(store.kept("authorization", "a", 50).await.unwrap(), None);
    }

    /// What several nodes rely on: whoever presents an identifier at the
    /// same instant, one caller gets the value. On PostgreSQL the callers
    /// are as many connections; on SQLite in memory they wait in line.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn of_many_callers_at_once_one_takes_the_value() {
        let store = Arc::new(store().await);
        for round in 0..20 {
            let id = format!("code-{round}");
            store.keep("code", "codes", &id, b"v", 100).await.unwrap();
            let start = Arc::new(tokio::sync::Barrier::new(16));
            let mut callers = tokio::task::JoinSet::new();
            for _ in 0..16 {
                let (store, start, id) = (store.clone(), start.clone(), id.clone());
                callers.spawn(async move {
                    start.wait().await;
                    store.take_kept("code", &id, 50).await.unwrap().is_some()
                });
            }
            let mut taken = 0;
            while let Some(got) = callers.join_next().await {
                taken += usize::from(got.unwrap());
            }
            assert_eq!(taken, 1, "round {round}");
        }
    }

    #[tokio::test]
    async fn a_value_is_found_under_its_own_kind_only() {
        let store = store().await;
        store
            .keep("sign-in", "authentications", "s", b"v", 100)
            .await
            .unwrap();
        assert_eq!(
            store.take_kept("delete-account", "s", 50).await.unwrap(),
            None
        );
        assert_eq!(store.kept("confirm", "s", 50).await.unwrap(), None);
        assert_eq!(
            store.take_kept("sign-in", "s", 50).await.unwrap(),
            Some(b"v".to_vec())
        );
    }

    #[tokio::test]
    async fn an_expired_value_is_as_if_never_kept_and_is_swept() {
        let store = store().await;
        store.keep("code", "codes", "old", b"v", 100).await.unwrap();
        store.keep("code", "codes", "new", b"v", 200).await.unwrap();
        // At its date a value is gone.
        assert_eq!(store.kept("code", "old", 100).await.unwrap(), None);
        assert_eq!(store.take_kept("code", "old", 100).await.unwrap(), None);
        assert_eq!(store.count_kept("codes", 100).await.unwrap(), 1);
        assert_eq!(store.sweep_kept(100).await.unwrap(), 1);
        assert_eq!(
            store.kept("code", "new", 100).await.unwrap(),
            Some(b"v".to_vec())
        );
    }

    #[tokio::test]
    async fn values_are_counted_by_family() {
        let store = store().await;
        store
            .keep("signup", "registrations", "a", b"", 100)
            .await
            .unwrap();
        store
            .keep("add-passkey", "registrations", "b", b"", 100)
            .await
            .unwrap();
        store.keep("code", "codes", "c", b"", 100).await.unwrap();
        assert_eq!(store.count_kept("registrations", 50).await.unwrap(), 2);
        assert_eq!(store.count_kept("codes", 50).await.unwrap(), 1);
        assert_eq!(store.count_kept("authentications", 50).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn an_assertion_is_a_first_use_once() {
        let store = store().await;
        assert!(
            store
                .first_use_of_assertion("c", "j1", 100, 50)
                .await
                .unwrap()
        );
        assert!(
            !store
                .first_use_of_assertion("c", "j1", 100, 60)
                .await
                .unwrap()
        );
        assert!(
            store
                .first_use_of_assertion("other", "j1", 100, 60)
                .await
                .unwrap()
        );
        assert_eq!(store.count_assertions(60).await.unwrap(), 2);
        // Past its expiry it counts as never presented, swept or not.
        assert!(
            store
                .first_use_of_assertion("c", "j1", 300, 200)
                .await
                .unwrap()
        );
        assert!(
            !store
                .first_use_of_assertion("c", "j1", 300, 210)
                .await
                .unwrap()
        );
        assert_eq!(store.sweep_kept(200).await.unwrap(), 1);
        assert_eq!(store.count_assertions(200).await.unwrap(), 1);
    }

    /// Reading the table gives nothing to present and nothing to read.
    #[tokio::test]
    async fn the_table_holds_no_identifier_and_no_readable_value() {
        let store = store().await;
        store
            .keep(
                "code",
                "codes",
                "the-code-itself",
                b"what the person accepted",
                100,
            )
            .await
            .unwrap();
        let row = sqlx::query("SELECT id, value FROM pending")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        let id: String = row.try_get("id").unwrap();
        let value: Vec<u8> = row.try_get("value").unwrap();
        assert!(!id.contains("the-code-itself"));
        assert_eq!(id.len(), 64);
        assert!(
            !value
                .windows(b"accepted".len())
                .any(|window| window == b"accepted")
        );
        // The stored identifier is not one that can be presented.
        assert_eq!(store.kept("code", &id, 50).await.unwrap(), None);
    }

    /// Whoever can write to the database cannot give one person's value to
    /// another: a value moved under another identifier is refused.
    #[tokio::test]
    async fn a_value_moved_under_another_identifier_is_refused() {
        let store = store().await;
        store
            .keep("code", "codes", "victim", b"hers", 100)
            .await
            .unwrap();
        store
            .keep("code", "codes", "attacker", b"his", 100)
            .await
            .unwrap();
        let hers: Vec<u8> = sqlx::query_scalar("SELECT value FROM pending WHERE id = $1")
            .bind(helpers4::hex::encode(&row_id("code", "victim")))
            .fetch_one(&store.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE pending SET value = $1 WHERE id = $2")
            .bind(hers)
            .bind(helpers4::hex::encode(&row_id("code", "attacker")))
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(matches!(
            store.take_kept("code", "attacker", 50).await,
            Err(Error::InvalidBlob)
        ));
    }

    #[tokio::test]
    async fn a_value_kept_under_another_master_key_cannot_be_read() {
        let url = crate::testing::url().await;
        let store = EncryptedStore::new(&url, master()).await.unwrap();
        store.prepare_kept().await.unwrap();
        store.keep("code", "codes", "a", b"v", 100).await.unwrap();
        let other = EncryptedStore {
            pool: store.pool.clone(),
            master: MasterKey::from_hex(&"cd".repeat(32)).unwrap(),
        };
        assert!(other.kept("code", "a", 50).await.is_err());
    }
}
