//! Zero-trust storage operations and the [`EncryptedStore`] wrapper.
//!
//! Every sensitive field is encrypted with a per-user HKDF-derived key
//! before writing to SQLite. A raw DB dump must never expose readable secrets.

use brigid_crypto::{EncryptedBlob, MasterKey};
use sqlx::{
    Row as _, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    model::{Credential, User},
};

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte per-user encryption key (HKDF-SHA3-256).
///
/// HKDF-SHA3-256 with a 32-byte output is unconditionally infallible; the
/// `Result` is an artefact of the RustCrypto API surface.
fn user_key(master: &MasterKey, user_id: &Uuid) -> Result<Zeroizing<[u8; 32]>> {
    brigid_crypto::hkdf::derive_user_key(master, user_id.as_bytes(), b"store-fields")
        .map_err(crate::Error::from)
}

/// Compute a stable, deterministic lookup index for `username@server`.
///
/// Because `username` and `server` are stored encrypted, we cannot do a SQL
/// `WHERE` on those columns. Instead we store an HKDF-derived index that is
/// consistent across calls for the same master key and `username@server` pair,
/// enabling an indexed lookup without leaking the plaintext values.
///
/// Both fields are length-prefixed (u32 BE) before being fed into HKDF to
/// prevent ambiguous collisions between inputs such as
/// `(username="a@b", server="c")` and `(username="a", server="b@c")`.
///
/// Index = hex(HKDF-SHA3-256(master, len||username||len||server, b"username-lookup"))
fn username_index(master: &MasterKey, username: &str, server: &str) -> Result<String> {
    let ulen = (username.len() as u32).to_be_bytes();
    let slen = (server.len() as u32).to_be_bytes();
    let mut input = Vec::with_capacity(8 + username.len() + server.len());
    input.extend_from_slice(&ulen);
    input.extend_from_slice(username.as_bytes());
    input.extend_from_slice(&slen);
    input.extend_from_slice(server.as_bytes());
    let key = brigid_crypto::hkdf::derive_user_key(master, &input, b"username-lookup")
        .map_err(crate::Error::from)?;
    Ok(hex::encode(*key))
}

/// Encrypt `plaintext` with `key`; returns the serialised nonce+ciphertext blob.
///
/// AES-256-GCM encryption with a valid 32-byte key is unconditionally
/// infallible; `map_err` propagates the (unreachable) error without creating a
/// dead closure region.
fn enc(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    brigid_crypto::aes::encrypt(key, plaintext)
        .map(|blob| blob.to_bytes())
        .map_err(crate::Error::from)
}

/// Decrypt a raw blob (nonce+ciphertext) with `key`; returns plaintext bytes.
fn dec(key: &[u8; 32], raw: &[u8]) -> Result<Vec<u8>> {
    let blob = EncryptedBlob::from_bytes(raw).map_err(|_| Error::InvalidBlob)?;
    let plaintext = brigid_crypto::aes::decrypt(key, &blob)?;
    let bytes: &[u8] = &plaintext;
    Ok(bytes.to_vec())
}

// ---------------------------------------------------------------------------
// Standalone public functions
// ---------------------------------------------------------------------------

/// Encrypt and INSERT a [`User`] into the database.
///
/// `username`, `server`, and `did_web` are encrypted with a per-user
/// HKDF-derived key before storage. A deterministic `username_index` is
/// computed and stored to enable lookups without exposing plaintext.
pub async fn store_user(pool: &SqlitePool, master: &MasterKey, user: &User) -> Result<()> {
    let key = user_key(master, &user.id)?;
    let username_enc = enc(&key, user.username.as_bytes())?;
    let server_enc = enc(&key, user.server.as_bytes())?;
    let did_web_enc = enc(&key, user.did_web.as_bytes())?;
    let created_at = user
        .created_at
        .format(&Rfc3339)
        .map_err(|e| Error::Time(e.to_string()))?;
    let idx = username_index(master, &user.username, &user.server)?;

    sqlx::query(
        "INSERT INTO users (id, username, server, did_web, created_at, username_index) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user.id.to_string())
    .bind(username_enc)
    .bind(server_enc)
    .bind(did_web_enc)
    .bind(created_at)
    .bind(idx)
    .execute(pool)
    .await
    .map_err(map_sqlx_unique)?;

    Ok(())
}

/// Map a `sqlx::Error` to [`Error::Duplicate`] when the underlying database
/// reports a UNIQUE constraint violation (e.g. concurrent registration of the
/// same username). Other errors are propagated as `Error::Database`.
fn map_sqlx_unique(e: sqlx::Error) -> Error {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.is_unique_violation() {
            return Error::Duplicate;
        }
    }
    Error::Database(e)
}

/// Look up a [`User`] by `username` and `server`, using the deterministic
/// `username_index` for the WHERE clause.
///
/// Returns `None` if no matching user exists.
pub async fn fetch_user_by_username(
    pool: &SqlitePool,
    master: &MasterKey,
    username: &str,
    server: &str,
) -> Result<Option<User>> {
    let idx = username_index(master, username, server)?;

    let row = sqlx::query(
        "SELECT id, username, server, did_web, created_at FROM users WHERE username_index = ?",
    )
    .bind(&idx)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };

    let id_str: String = row.try_get("id")?;
    let id: Uuid = id_str.parse()?;
    let key = user_key(master, &id)?;

    let username_raw: Vec<u8> = row.try_get("username")?;
    let server_raw: Vec<u8> = row.try_get("server")?;
    let did_web_raw: Vec<u8> = row.try_get("did_web")?;
    let created_at_str: String = row.try_get("created_at")?;

    let username = String::from_utf8(dec(&key, &username_raw)?)?;
    let server = String::from_utf8(dec(&key, &server_raw)?)?;
    let did_web = String::from_utf8(dec(&key, &did_web_raw)?)?;
    let created_at =
        OffsetDateTime::parse(&created_at_str, &Rfc3339).map_err(|e| Error::Time(e.to_string()))?;

    Ok(Some(User {
        id,
        username,
        server,
        did_web,
        created_at,
    }))
}

/// Fetch a [`User`] by ID, decrypting sensitive fields on read.
pub async fn fetch_user(
    pool: &SqlitePool,
    master: &MasterKey,
    user_id: Uuid,
) -> Result<Option<User>> {
    let row =
        sqlx::query("SELECT id, username, server, did_web, created_at FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .fetch_optional(pool)
            .await?;

    let Some(row) = row else { return Ok(None) };

    let id_str: String = row.try_get("id")?;
    let id: Uuid = id_str.parse()?;
    let key = user_key(master, &id)?;

    let username_raw: Vec<u8> = row.try_get("username")?;
    let server_raw: Vec<u8> = row.try_get("server")?;
    let did_web_raw: Vec<u8> = row.try_get("did_web")?;
    let created_at_str: String = row.try_get("created_at")?;

    let username = String::from_utf8(dec(&key, &username_raw)?)?;
    let server = String::from_utf8(dec(&key, &server_raw)?)?;
    let did_web = String::from_utf8(dec(&key, &did_web_raw)?)?;
    let created_at =
        OffsetDateTime::parse(&created_at_str, &Rfc3339).map_err(|e| Error::Time(e.to_string()))?;

    Ok(Some(User {
        id,
        username,
        server,
        did_web,
        created_at,
    }))
}

/// Encrypt and INSERT a [`Credential`] into the database.
pub async fn store_credential(
    pool: &SqlitePool,
    master: &MasterKey,
    cred: &Credential,
) -> Result<()> {
    let key = user_key(master, &cred.user_id)?;
    let data_enc = enc(&key, &cred.data)?;

    sqlx::query("INSERT INTO webauthn_credentials (id, user_id, data) VALUES (?, ?, ?)")
        .bind(cred.id.to_string())
        .bind(cred.user_id.to_string())
        .bind(data_enc)
        .execute(pool)
        .await?;

    Ok(())
}

/// UPDATE the encrypted `data` blob for an existing [`Credential`] row.
///
/// Used when WebAuthn advances the signature counter after a successful
/// authentication — the credential's serialised `Passkey` state is updated
/// in-place rather than inserting a duplicate row.
pub async fn update_credential(
    pool: &SqlitePool,
    master: &MasterKey,
    cred: &Credential,
) -> Result<()> {
    let key = user_key(master, &cred.user_id)?;
    let data_enc = enc(&key, &cred.data)?;

    // Match on (id, user_id) — not id alone. The encrypted `data` blob is
    // wrapped under the caller-supplied `cred.user_id`'s per-user key, so an
    // UPDATE that matched only on `id` and was called with a mismatched
    // `user_id` would overwrite an existing row with ciphertext readable only
    // under a different user's key, corrupting that credential beyond
    // recovery. The extra predicate makes the mismatch a clean `NotFound`.
    let result =
        sqlx::query("UPDATE webauthn_credentials SET data = ? WHERE id = ? AND user_id = ?")
            .bind(data_enc)
            .bind(cred.id.to_string())
            .bind(cred.user_id.to_string())
            .execute(pool)
            .await?;

    // Guard against silent counter desync: a concurrent credential deletion
    // (or a (id, user_id) mismatch — see WHERE clause above) would otherwise
    // make a no-op UPDATE look successful.
    if result.rows_affected() == 0 {
        return Err(Error::NotFound);
    }

    Ok(())
}

/// Fetch all [`Credential`]s for a user, decrypting `data` on read.
pub async fn fetch_credentials(
    pool: &SqlitePool,
    master: &MasterKey,
    user_id: Uuid,
) -> Result<Vec<Credential>> {
    let rows = sqlx::query("SELECT id, user_id, data FROM webauthn_credentials WHERE user_id = ?")
        .bind(user_id.to_string())
        .fetch_all(pool)
        .await?;

    let key = user_key(master, &user_id)?;
    let mut creds = Vec::with_capacity(rows.len());

    for row in rows {
        let id_str: String = row.try_get("id")?;
        let id: Uuid = id_str.parse()?;
        let data_raw: Vec<u8> = row.try_get("data")?;
        let data = dec(&key, &data_raw)?;
        creds.push(Credential { id, user_id, data });
    }

    Ok(creds)
}

// ---------------------------------------------------------------------------
// EncryptedStore wrapper
// ---------------------------------------------------------------------------

/// Owns a connection pool and a master key; enforces zero-trust storage on all
/// operations.
pub struct EncryptedStore {
    pool: SqlitePool,
    master: MasterKey,
}

impl EncryptedStore {
    /// Open (or create) the SQLite database at `database_url`, run migrations,
    /// and return an `EncryptedStore`.
    pub async fn new(database_url: &str, master: MasterKey) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(database_url)?
            .foreign_keys(true)
            .create_if_missing(true);
        // For in-memory SQLite each connection gets its own empty database.
        // Restrict the pool to a single connection so all operations share the
        // same in-memory database (used in tests; does not affect file-backed DBs).
        let pool = if database_url.contains(":memory:") {
            SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(opts)
                .await?
        } else {
            SqlitePool::connect_with(opts).await?
        };
        crate::MIGRATOR.run(&pool).await?;
        Ok(Self { pool, master })
    }

    pub async fn store_user(&self, user: &User) -> Result<()> {
        store_user(&self.pool, &self.master, user).await
    }

    pub async fn fetch_user(&self, user_id: Uuid) -> Result<Option<User>> {
        fetch_user(&self.pool, &self.master, user_id).await
    }

    pub async fn store_credential(&self, cred: &Credential) -> Result<()> {
        store_credential(&self.pool, &self.master, cred).await
    }

    pub async fn update_credential(&self, cred: &Credential) -> Result<()> {
        update_credential(&self.pool, &self.master, cred).await
    }

    pub async fn fetch_credentials(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        fetch_credentials(&self.pool, &self.master, user_id).await
    }

    pub async fn fetch_user_by_username(
        &self,
        username: &str,
        server: &str,
    ) -> Result<Option<User>> {
        fetch_user_by_username(&self.pool, &self.master, username, server).await
    }

    /// Atomically INSERT a user **and** their first credential in a single
    /// transaction.
    ///
    /// This is the only correct entry point for the WebAuthn registration
    /// finish flow: if the credential write fails after the user write
    /// succeeds, the account would otherwise remain registered with no
    /// credentials — locking the user out (every login then fails with no
    /// credentials, every re-registration attempt collides on the unique
    /// username index). The transaction guarantees the two rows either both
    /// commit or both roll back.
    pub async fn register_user_with_credential(
        &self,
        user: &User,
        cred: &Credential,
    ) -> Result<()> {
        // Defend against a mismatched credential reaching the transaction:
        // the credential's `data` is encrypted under `cred.user_id`'s per-user
        // key, so committing a `Credential` whose `user_id` differs from the
        // user being created would either (a) attach a credential decryptable
        // only under a third party's key to the new user, or (b) cause the
        // newly created user to have no credential at all while a different
        // existing user silently receives one — either outcome defeats the
        // atomicity this method exists to provide.
        if cred.user_id != user.id {
            return Err(Error::CredentialUserMismatch);
        }

        let u_key = user_key(&self.master, &user.id)?;
        let username_enc = enc(&u_key, user.username.as_bytes())?;
        let server_enc = enc(&u_key, user.server.as_bytes())?;
        let did_web_enc = enc(&u_key, user.did_web.as_bytes())?;
        let created_at = user
            .created_at
            .format(&Rfc3339)
            .map_err(|e| Error::Time(e.to_string()))?;
        let idx = username_index(&self.master, &user.username, &user.server)?;

        let cred_key = user_key(&self.master, &cred.user_id)?;
        let cred_data_enc = enc(&cred_key, &cred.data)?;

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO users (id, username, server, did_web, created_at, username_index) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(user.id.to_string())
        .bind(username_enc)
        .bind(server_enc)
        .bind(did_web_enc)
        .bind(created_at)
        .bind(idx)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_unique)?;

        sqlx::query("INSERT INTO webauthn_credentials (id, user_id, data) VALUES (?, ?, ?)")
            .bind(cred.id.to_string())
            .bind(cred.user_id.to_string())
            .bind(cred_data_enc)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Persist a revoked JTI in the database so it remains blacklisted across
    /// server restarts for the duration of its token lifetime.
    ///
    /// Expired entries (exp < now) are pruned on each insert to keep the table
    /// bounded.
    pub async fn blacklist_jti(&self, jti: &str, exp: i64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        // Prune expired entries to keep the table bounded.
        sqlx::query("DELETE FROM jti_blacklist WHERE exp <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        sqlx::query("INSERT OR REPLACE INTO jti_blacklist (jti, exp) VALUES (?, ?)")
            .bind(jti)
            .bind(exp)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Returns `true` if the JTI is in the persistent blacklist and has not
    /// yet expired.
    pub async fn is_jti_blacklisted(&self, jti: &str) -> Result<bool> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let row: Option<(String,)> =
            sqlx::query_as("SELECT jti FROM jti_blacklist WHERE jti = ? AND exp > ?")
                .bind(jti)
                .bind(now)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use brigid_crypto::MasterKey;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn master() -> MasterKey {
        MasterKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn sample_user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "alice".to_string(),
            server: "example.com".to_string(),
            did_web: "did:web:example.com:u:alice".to_string(),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn store_and_fetch_user(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        let id = user.id;

        store_user(&pool, &master, &user).await.unwrap();
        let fetched = fetch_user(&pool, &master, id).await.unwrap().unwrap();

        assert_eq!(fetched.id, id);
        assert_eq!(fetched.username, "alice");
        assert_eq!(fetched.server, "example.com");
        assert_eq!(fetched.did_web, "did:web:example.com:u:alice");
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn fetch_missing_user_returns_none(pool: SqlitePool) -> sqlx::Result<()> {
        let result = fetch_user(&pool, &master(), Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn store_and_fetch_credential(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        let user_id = user.id;
        store_user(&pool, &master, &user).await.unwrap();

        let cred = Credential {
            id: Uuid::new_v4(),
            user_id,
            data: b"webauthn-credential-bytes".to_vec(),
        };
        store_credential(&pool, &master, &cred).await.unwrap();

        let fetched = fetch_credentials(&pool, &master, user_id).await.unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].data, b"webauthn-credential-bytes");
        Ok(())
    }

    /// A raw SQLite dump must not expose readable secrets.
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn dump_contains_no_plaintext(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        store_user(&pool, &master, &user).await.unwrap();

        let rows = sqlx::query("SELECT username, server, did_web FROM users")
            .fetch_all(&pool)
            .await?;
        assert!(!rows.is_empty());

        let row = &rows[0];
        let username_raw: Vec<u8> = row.try_get(0)?;
        let server_raw: Vec<u8> = row.try_get(1)?;
        let did_web_raw: Vec<u8> = row.try_get(2)?;

        // Stored bytes must differ from the plaintext UTF-8 representation.
        assert_ne!(username_raw, b"alice", "username stored in plaintext");
        assert_ne!(server_raw, b"example.com", "server stored in plaintext");
        // And must not contain the plaintext as a readable substring.
        assert!(
            !String::from_utf8_lossy(&username_raw).contains("alice"),
            "username readable in dump"
        );
        assert!(
            !String::from_utf8_lossy(&did_web_raw).contains("alice"),
            "DID readable in dump"
        );
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn wrong_master_key_fails_decryption(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        let id = user.id;
        store_user(&pool, &master, &user).await.unwrap();

        let wrong_master = MasterKey::from_hex(&"ff".repeat(32)).unwrap();
        let result = fetch_user(&pool, &wrong_master, id).await;
        assert!(result.is_err(), "decryption with wrong key should fail");
        Ok(())
    }

    /// Inject a malformed (too-short) blob directly into the DB and verify that
    /// `fetch_user` returns `Error::InvalidBlob`, exercising the
    /// `EncryptedBlob::from_bytes` error path inside `dec`.
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn fetch_user_with_malformed_blob_returns_error(pool: SqlitePool) -> sqlx::Result<()> {
        use time::format_description::well_known::Rfc3339;

        let id = Uuid::new_v4();
        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("format is valid");

        // 3 bytes is far too short for a valid AES-GCM blob (nonce alone is 12 bytes).
        let garbage: Vec<u8> = vec![0xde, 0xad, 0xbe];
        // A dummy index value (64 zeros) satisfies the NOT NULL constraint.
        let dummy_index = "0".repeat(64);
        sqlx::query(
            "INSERT INTO users (id, username, server, did_web, created_at, username_index) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(&garbage)
        .bind(&garbage)
        .bind(&garbage)
        .bind(created_at)
        .bind(dummy_index)
        .execute(&pool)
        .await?;

        let result = fetch_user(&pool, &master(), id).await;
        assert!(
            matches!(result, Err(Error::InvalidBlob)),
            "expected InvalidBlob, got {result:?}"
        );
        Ok(())
    }

    /// Exercise all `EncryptedStore` wrapper methods using an in-memory SQLite
    /// database so that every delegate method is covered.
    #[tokio::test]
    async fn encrypted_store_wrapper_methods() {
        use sqlx::sqlite::SqlitePoolOptions;

        // Single-connection pool keeps the :memory: database alive for the
        // duration of the test.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        crate::MIGRATOR.run(&pool).await.unwrap();
        drop(pool); // EncryptedStore::new will create its own pool

        let store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();

        let user = sample_user();
        let user_id = user.id;
        store.store_user(&user).await.unwrap();

        let fetched = store.fetch_user(user_id).await.unwrap().unwrap();
        assert_eq!(fetched.username, "alice");

        let none = store.fetch_user(Uuid::new_v4()).await.unwrap();
        assert!(none.is_none());

        let cred = Credential {
            id: Uuid::new_v4(),
            user_id,
            data: b"passkey-data".to_vec(),
        };
        store.store_credential(&cred).await.unwrap();

        let creds = store.fetch_credentials(user_id).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].data, b"passkey-data");

        // fetch_user_by_username via the wrapper
        let found = store
            .fetch_user_by_username("alice", "example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, user_id);
        assert_eq!(found.username, "alice");

        let missing = store
            .fetch_user_by_username("bob", "example.com")
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    /// `OffsetDateTime::format(&Rfc3339)` returns `Err` for years outside
    /// 0..=9999. Year -1 is valid for `time::Date` but RFC 3339 requires a
    /// 4-digit year, so the call fails with `Format::InvalidComponent("year")`.
    /// This exercises the `|e| Error::Time(e.to_string())` closure on the
    /// `format(&Rfc3339)?` line inside `store_user`.
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn store_user_with_bc_date_returns_time_error(pool: SqlitePool) -> sqlx::Result<()> {
        use time::{Date, Month, Time};

        let date = Date::from_calendar_date(-1, Month::June, 15)
            .expect("year -1 is within time::Date range");
        let dt = OffsetDateTime::new_utc(date, Time::MIDNIGHT);
        let user = User {
            id: Uuid::new_v4(),
            username: "alice".to_string(),
            server: "example.com".to_string(),
            did_web: "did:web:example.com:u:alice".to_string(),
            created_at: dt,
        };

        let result = store_user(&pool, &master(), &user).await;
        assert!(
            matches!(result, Err(Error::Time(_))),
            "expected Time error for year -1, got {result:?}"
        );
        Ok(())
    }

    /// Insert a row with a malformed `created_at` string to exercise the
    /// `OffsetDateTime::parse` error path in `fetch_user` (the
    /// `|e| Error::Time(e.to_string())` closure on the `parse(&Rfc3339)?` line).
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn fetch_user_with_malformed_date_returns_time_error(
        pool: SqlitePool,
    ) -> sqlx::Result<()> {
        // Store a valid user so the encrypted fields are correct.
        let user = sample_user();
        let id = user.id;
        store_user(&pool, &master(), &user).await.unwrap();

        // Corrupt the created_at column so that parsing it as RFC 3339 fails.
        sqlx::query("UPDATE users SET created_at = 'not-a-valid-date' WHERE id = ?")
            .bind(id.to_string())
            .execute(&pool)
            .await?;

        let result = fetch_user(&pool, &master(), id).await;
        assert!(
            matches!(result, Err(Error::Time(_))),
            "expected Time error for malformed date, got {result:?}"
        );
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn fetch_user_by_username_found(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user(); // username="alice", server="example.com"
        let id = user.id;
        store_user(&pool, &master, &user).await.unwrap();

        let found = fetch_user_by_username(&pool, &master, "alice", "example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, id);
        assert_eq!(found.username, "alice");
        assert_eq!(found.server, "example.com");
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn fetch_user_by_username_not_found(pool: SqlitePool) -> sqlx::Result<()> {
        let result = fetch_user_by_username(&pool, &master(), "nobody", "example.com")
            .await
            .unwrap();
        assert!(result.is_none());
        Ok(())
    }

    /// Verify that different master keys produce different username indexes,
    /// so a lookup with the wrong key returns None instead of the wrong user.
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn wrong_master_returns_none_for_username_lookup(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        store_user(&pool, &master, &user).await.unwrap();

        let wrong_master = MasterKey::from_hex(&"ff".repeat(32)).unwrap();
        let result = fetch_user_by_username(&pool, &wrong_master, "alice", "example.com")
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "wrong master key should not find the user"
        );
        Ok(())
    }
}
