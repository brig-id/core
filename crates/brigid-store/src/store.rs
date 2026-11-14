//! Zero-trust storage operations and the [`EncryptedStore`] wrapper.
//!
//! Every sensitive field is encrypted with a per-user HKDF-derived key
//! before writing to SQLite. A raw DB dump must never expose readable secrets.

use brigid_crypto::{EncryptedBlob, MasterKey};
use sqlx::{
    Row as _, SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::str::FromStr;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    model::{Client, Credential, Identity, RecoveryStatus, StoredOidcKey, User},
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

/// The key that encrypts OIDC signing seeds: derived from the master key with
/// a fixed context, so it changes (and the seeds are re-encrypted) on rotation.
fn oidc_seed_key(master: &MasterKey) -> Result<Zeroizing<[u8; 32]>> {
    brigid_crypto::hkdf::derive_user_key(master, b"oidc-signing-keys", b"store-fields")
        .map_err(crate::Error::from)
}

/// Unix time in seconds, as the `sessions` table stores it. A clock set
/// before 1970 reads as 0.
fn now_unix() -> i64 {
    helpers4::time::unix_now().map_or(0, |secs| secs as i64)
}

/// The key that encrypts the rows of `server_secrets`.
fn server_secret_key(master: &MasterKey) -> Result<Zeroizing<[u8; 32]>> {
    brigid_crypto::hkdf::derive_user_key(master, b"server-secrets", b"store-fields")
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
    Ok(helpers4::hex::encode(&*key))
}

/// Keyed lookup index of a recovery code's recovery id (ADR-004), the same
/// construction as [`username_index`] with its own context.
fn recovery_index(master: &MasterKey, recovery_id: &[u8]) -> Result<String> {
    let key = brigid_crypto::hkdf::derive_user_key(master, recovery_id, b"recovery-lookup")
        .map_err(crate::Error::from)?;
    Ok(helpers4::hex::encode(&*key))
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
/// `username` and `server` are encrypted with a per-user
/// HKDF-derived key before storage. A deterministic `username_index` is
/// computed and stored to enable lookups without exposing plaintext.
pub async fn store_user(pool: &SqlitePool, master: &MasterKey, user: &User) -> Result<()> {
    let key = user_key(master, &user.id)?;
    let username_enc = enc(&key, user.username.as_bytes())?;
    let server_enc = enc(&key, user.server.as_bytes())?;
    let created_at = user
        .created_at
        .format(&Rfc3339)
        .map_err(|e| Error::Time(e.to_string()))?;
    let idx = username_index(master, &user.username, &user.server)?;

    sqlx::query(
        "INSERT INTO users (id, username, server, created_at, username_index) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user.id.to_string())
    .bind(username_enc)
    .bind(server_enc)
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
    if let sqlx::Error::Database(ref db_err) = e
        && db_err.is_unique_violation()
    {
        return Error::Duplicate;
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

    let row =
        sqlx::query("SELECT id, username, server, created_at FROM users WHERE username_index = ?")
            .bind(&idx)
            .fetch_optional(pool)
            .await?;

    let Some(row) = row else { return Ok(None) };

    let id_str: String = row.try_get("id")?;
    let id: Uuid = id_str.parse()?;
    let key = user_key(master, &id)?;

    let username_raw: Vec<u8> = row.try_get("username")?;
    let server_raw: Vec<u8> = row.try_get("server")?;
    let created_at_str: String = row.try_get("created_at")?;

    let username = String::from_utf8(dec(&key, &username_raw)?)?;
    let server = String::from_utf8(dec(&key, &server_raw)?)?;
    let created_at =
        OffsetDateTime::parse(&created_at_str, &Rfc3339).map_err(|e| Error::Time(e.to_string()))?;

    Ok(Some(User {
        id,
        username,
        server,
        created_at,
    }))
}

/// Fetch a [`User`] by ID, decrypting sensitive fields on read.
pub async fn fetch_user(
    pool: &SqlitePool,
    master: &MasterKey,
    user_id: Uuid,
) -> Result<Option<User>> {
    let row = sqlx::query("SELECT id, username, server, created_at FROM users WHERE id = ?")
        .bind(user_id.to_string())
        .fetch_optional(pool)
        .await?;

    let Some(row) = row else { return Ok(None) };

    let id_str: String = row.try_get("id")?;
    let id: Uuid = id_str.parse()?;
    let key = user_key(master, &id)?;

    let username_raw: Vec<u8> = row.try_get("username")?;
    let server_raw: Vec<u8> = row.try_get("server")?;
    let created_at_str: String = row.try_get("created_at")?;

    let username = String::from_utf8(dec(&key, &username_raw)?)?;
    let server = String::from_utf8(dec(&key, &server_raw)?)?;
    let created_at =
        OffsetDateTime::parse(&created_at_str, &Rfc3339).map_err(|e| Error::Time(e.to_string()))?;

    Ok(Some(User {
        id,
        username,
        server,
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

/// DELETE a [`Credential`] by `(user_id, cred_id)`.
///
/// The double-column predicate prevents cross-user deletion: a caller who
/// knows `cred_id` but not the matching `user_id` cannot remove it. Returns
/// [`Error::NotFound`] when zero rows are affected (credential absent or
/// `user_id` mismatch), letting callers distinguish a legitimate 404 from an
/// authorisation failure without leaking whether the ID exists at all.
pub async fn delete_credential(pool: &SqlitePool, user_id: Uuid, cred_id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?")
        .bind(cred_id.to_string())
        .bind(user_id.to_string())
        .execute(pool)
        .await?;

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

/// Longest passkey label, in characters.
pub const CREDENTIAL_LABEL_MAX_CHARS: usize = 64;

/// Name a passkey of `user_id` (trimmed; empty clears the label).
/// [`Error::NotFound`] when the passkey is not the user's.
pub async fn set_credential_label(
    pool: &SqlitePool,
    master: &MasterKey,
    user_id: Uuid,
    cred_id: Uuid,
    label: &str,
) -> Result<()> {
    let label = label.trim();
    if label.chars().count() > CREDENTIAL_LABEL_MAX_CHARS || label.chars().any(char::is_control) {
        return Err(Error::InvalidLabel);
    }
    let key = user_key(master, &user_id)?;
    let label_enc = if label.is_empty() {
        None
    } else {
        Some(enc(&key, label.as_bytes())?)
    };
    let result =
        sqlx::query("UPDATE webauthn_credentials SET label = ? WHERE id = ? AND user_id = ?")
            .bind(label_enc)
            .bind(cred_id.to_string())
            .bind(user_id.to_string())
            .execute(pool)
            .await?;
    if result.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// The labels of `user_id`'s named passkeys, by credential id.
pub async fn fetch_credential_labels(
    pool: &SqlitePool,
    master: &MasterKey,
    user_id: Uuid,
) -> Result<std::collections::HashMap<Uuid, String>> {
    let rows = sqlx::query(
        "SELECT id, label FROM webauthn_credentials WHERE user_id = ? AND label IS NOT NULL",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    let key = user_key(master, &user_id)?;
    rows.iter()
        .map(|row| {
            let id: Uuid = row.try_get::<String, _>("id")?.parse()?;
            let label = String::from_utf8(dec(&key, &row.try_get::<Vec<u8>, _>("label")?)?)?;
            Ok((id, label))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

fn fmt_time(t: OffsetDateTime) -> Result<String> {
    t.format(&Rfc3339).map_err(|e| Error::Time(e.to_string()))
}

/// Validate and INSERT an [`Identity`]; `name` and `description` are
/// encrypted with the owning account's key. The account must exist.
///
/// The name is trimmed and the fields validated (`brigid_identity::profile`);
/// the stored values are the validated ones.
pub async fn store_identity(
    pool: &SqlitePool,
    master: &MasterKey,
    identity: &Identity,
) -> Result<()> {
    insert_identity(pool, master, identity).await
}

async fn insert_identity<'e, E>(executor: E, master: &MasterKey, identity: &Identity) -> Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let name = brigid_identity::validate_name(&identity.name)?;
    brigid_identity::validate_logo(&identity.logo)?;
    let description = match &identity.description {
        Some(d) => brigid_identity::validate_description(d)?,
        None => None,
    };

    let key = user_key(master, &identity.account_id)?;
    sqlx::query(
        "INSERT INTO identities \
         (id, account_id, name, logo, description, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(identity.id.to_string())
    .bind(identity.account_id.to_string())
    .bind(enc(&key, name.as_bytes())?)
    .bind(&identity.logo)
    .bind(description.map(|d| enc(&key, d.as_bytes())).transpose()?)
    .bind(fmt_time(identity.created_at)?)
    .bind(fmt_time(identity.updated_at)?)
    .execute(executor)
    .await
    .map_err(map_sqlx_unique)?;
    Ok(())
}

fn identity_from_row(master: &MasterKey, row: &sqlx::sqlite::SqliteRow) -> Result<Identity> {
    let id: Uuid = row.try_get::<String, _>("id")?.parse()?;
    let account_id: Uuid = row.try_get::<String, _>("account_id")?.parse()?;
    let key = user_key(master, &account_id)?;

    let name = String::from_utf8(dec(&key, &row.try_get::<Vec<u8>, _>("name")?)?)?;
    let description = row
        .try_get::<Option<Vec<u8>>, _>("description")?
        .map(|raw| dec(&key, &raw).and_then(|b| Ok(String::from_utf8(b)?)))
        .transpose()?;
    let parse = |col: &str| -> Result<OffsetDateTime> {
        OffsetDateTime::parse(&row.try_get::<String, _>(col)?, &Rfc3339)
            .map_err(|e| Error::Time(e.to_string()))
    };

    Ok(Identity {
        id,
        account_id,
        name,
        logo: row.try_get("logo")?,
        description,
        created_at: parse("created_at")?,
        updated_at: parse("updated_at")?,
    })
}

const IDENTITY_COLUMNS: &str = "id, account_id, name, logo, description, created_at, updated_at";

/// Fetch one identity, only if it belongs to `account_id`.
pub async fn fetch_identity(
    pool: &SqlitePool,
    master: &MasterKey,
    account_id: Uuid,
    identity_id: Uuid,
) -> Result<Option<Identity>> {
    let row = sqlx::query(&format!(
        "SELECT {IDENTITY_COLUMNS} FROM identities WHERE id = ? AND account_id = ?"
    ))
    .bind(identity_id.to_string())
    .bind(account_id.to_string())
    .fetch_optional(pool)
    .await?;
    row.map(|r| identity_from_row(master, &r)).transpose()
}

/// All identities of an account, oldest first.
pub async fn fetch_identities(
    pool: &SqlitePool,
    master: &MasterKey,
    account_id: Uuid,
) -> Result<Vec<Identity>> {
    let rows = sqlx::query(&format!(
        "SELECT {IDENTITY_COLUMNS} FROM identities WHERE account_id = ? \
         ORDER BY created_at, id"
    ))
    .bind(account_id.to_string())
    .fetch_all(pool)
    .await?;
    rows.iter().map(|r| identity_from_row(master, r)).collect()
}

/// Change an identity's display fields (name, logo, description) and bump
/// `updated_at`. [`Error::NotFound`] when the identity
/// does not exist or belongs to another account.
pub async fn update_identity(
    pool: &SqlitePool,
    master: &MasterKey,
    identity: &Identity,
) -> Result<()> {
    let name = brigid_identity::validate_name(&identity.name)?;
    brigid_identity::validate_logo(&identity.logo)?;
    let description = match &identity.description {
        Some(d) => brigid_identity::validate_description(d)?,
        None => None,
    };

    let key = user_key(master, &identity.account_id)?;
    let result = sqlx::query(
        "UPDATE identities SET name = ?, logo = ?, description = ?, updated_at = ? \
         WHERE id = ? AND account_id = ?",
    )
    .bind(enc(&key, name.as_bytes())?)
    .bind(&identity.logo)
    .bind(description.map(|d| enc(&key, d.as_bytes())).transpose()?)
    .bind(fmt_time(OffsetDateTime::now_utc())?)
    .bind(identity.id.to_string())
    .bind(identity.account_id.to_string())
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Delete an identity of `account_id`. [`Error::NotFound`] when absent.
pub async fn delete_identity(pool: &SqlitePool, account_id: Uuid, identity_id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM identities WHERE id = ? AND account_id = ?")
        .bind(identity_id.to_string())
        .bind(account_id.to_string())
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
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

    pub async fn delete_credential(&self, user_id: Uuid, cred_id: Uuid) -> Result<()> {
        delete_credential(&self.pool, user_id, cred_id).await
    }

    pub async fn set_credential_label(
        &self,
        user_id: Uuid,
        cred_id: Uuid,
        label: &str,
    ) -> Result<()> {
        set_credential_label(&self.pool, &self.master, user_id, cred_id, label).await
    }

    pub async fn fetch_credential_labels(
        &self,
        user_id: Uuid,
    ) -> Result<std::collections::HashMap<Uuid, String>> {
        fetch_credential_labels(&self.pool, &self.master, user_id).await
    }

    // -- OIDC signing keys (core#22) ------------------------------------------

    /// Every stored signing key, the current one first, then retired ones,
    /// newest first.
    pub async fn oidc_signing_keys(&self) -> Result<Vec<StoredOidcKey>> {
        let rows = sqlx::query(
            "SELECT kid, seed, created_at, retired_at FROM oidc_keys \
             ORDER BY retired_at IS NOT NULL, created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        let key = oidc_seed_key(&self.master)?;
        let parse =
            |s: String| OffsetDateTime::parse(&s, &Rfc3339).map_err(|e| Error::Time(e.to_string()));
        rows.into_iter()
            .map(|row| {
                let plain = Zeroizing::new(dec(&key, &row.try_get::<Vec<u8>, _>("seed")?)?);
                let seed: [u8; 32] = plain
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidBlob)?;
                Ok(StoredOidcKey {
                    kid: row.try_get("kid")?,
                    seed: Zeroizing::new(seed),
                    created_at: parse(row.try_get("created_at")?)?,
                    retired_at: row
                        .try_get::<Option<String>, _>("retired_at")?
                        .map(parse)
                        .transpose()?,
                })
            })
            .collect()
    }

    /// Store `seed` as the new current signing key and retire the previous
    /// current one (it keeps verifying until [`Self::prune_oidc_keys`]).
    pub async fn add_oidc_signing_key(&self, kid: &str, seed: &[u8; 32]) -> Result<()> {
        let key = oidc_seed_key(&self.master)?;
        let now = fmt_time(OffsetDateTime::now_utc())?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE oidc_keys SET retired_at = ? WHERE retired_at IS NULL")
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO oidc_keys (kid, seed, created_at) VALUES (?, ?, ?)")
            .bind(kid)
            .bind(enc(&key, seed)?)
            .bind(&now)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_unique)?;
        tx.commit().await?;
        Ok(())
    }

    // -- VSID secret -----------------------------------------------------------

    /// The VSID secret: the keying material of every VSID.
    ///
    /// 32 random bytes, drawn at the first call on a database and stored. A
    /// master key rotation re-encrypts it, so VSIDs survive the rotation.
    pub async fn vsid_secret(&self) -> Result<Zeroizing<[u8; 32]>> {
        let key = server_secret_key(&self.master)?;
        let mut tx = self.pool.begin().await?;
        let stored: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT value FROM server_secrets WHERE name = 'vsid'")
                .fetch_optional(&mut *tx)
                .await?;
        let secret = match stored {
            Some(raw) => Zeroizing::new(dec(&key, &raw)?),
            None => {
                let secret = Zeroizing::new(helpers4::random::random_bytes(32)?);
                sqlx::query("INSERT INTO server_secrets (name, value) VALUES ('vsid', ?)")
                    .bind(enc(&key, &secret)?)
                    .execute(&mut *tx)
                    .await?;
                secret
            }
        };
        tx.commit().await?;
        let secret: [u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidBlob)?;
        Ok(Zeroizing::new(secret))
    }

    /// Delete keys retired before `before` (their grace period is over: every
    /// token they signed has expired). Returns how many were deleted.
    pub async fn prune_oidc_keys(&self, before: OffsetDateTime) -> Result<u64> {
        // RFC 3339 UTC timestamps written by this store compare correctly as
        // text: same format, same offset.
        let result =
            sqlx::query("DELETE FROM oidc_keys WHERE retired_at IS NOT NULL AND retired_at < ?")
                .bind(fmt_time(before)?)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected())
    }

    pub async fn store_identity(&self, identity: &Identity) -> Result<()> {
        store_identity(&self.pool, &self.master, identity).await
    }

    pub async fn fetch_identity(
        &self,
        account_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Option<Identity>> {
        fetch_identity(&self.pool, &self.master, account_id, identity_id).await
    }

    pub async fn fetch_identities(&self, account_id: Uuid) -> Result<Vec<Identity>> {
        fetch_identities(&self.pool, &self.master, account_id).await
    }

    pub async fn update_identity(&self, identity: &Identity) -> Result<()> {
        update_identity(&self.pool, &self.master, identity).await
    }

    pub async fn delete_identity(&self, account_id: Uuid, identity_id: Uuid) -> Result<()> {
        delete_identity(&self.pool, account_id, identity_id).await
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
    ///
    /// `identities` (the account's starter identities) are inserted in the
    /// same transaction; each must belong to `user`.
    pub async fn register_user_with_credential(
        &self,
        user: &User,
        cred: &Credential,
        identities: &[Identity],
    ) -> Result<()> {
        if identities.iter().any(|i| i.account_id != user.id) {
            return Err(Error::CredentialUserMismatch);
        }
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
        let created_at = user
            .created_at
            .format(&Rfc3339)
            .map_err(|e| Error::Time(e.to_string()))?;
        let idx = username_index(&self.master, &user.username, &user.server)?;

        let cred_key = user_key(&self.master, &cred.user_id)?;
        let cred_data_enc = enc(&cred_key, &cred.data)?;

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO users (id, username, server, created_at, username_index) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user.id.to_string())
        .bind(username_enc)
        .bind(server_enc)
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

        for identity in identities {
            insert_identity(&mut *tx, &self.master, identity).await?;
        }

        tx.commit().await?;
        Ok(())
    }

    // -- Account recovery (ADR-004) -------------------------------------------

    /// Make `recovery_id`/`verifier` the account's recovery code, replacing
    /// any previous one. `last_used_at` is kept.
    pub async fn set_recovery_code(
        &self,
        user_id: Uuid,
        recovery_id: &[u8],
        verifier: &[u8],
    ) -> Result<()> {
        let key = user_key(&self.master, &user_id)?;
        sqlx::query(
            "INSERT INTO account_recovery (user_id, recovery_index, recovery_id, verifier, created_at) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(user_id) DO UPDATE SET recovery_index = excluded.recovery_index, \
             recovery_id = excluded.recovery_id, verifier = excluded.verifier, \
             created_at = excluded.created_at",
        )
        .bind(user_id.to_string())
        .bind(recovery_index(&self.master, recovery_id)?)
        .bind(enc(&key, recovery_id)?)
        .bind(enc(&key, verifier)?)
        .bind(fmt_time(OffsetDateTime::now_utc())?)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_unique)?;
        Ok(())
    }

    /// Whether the account has a usable code, and when one was last used.
    pub async fn recovery_status(&self, user_id: Uuid) -> Result<RecoveryStatus> {
        let row = sqlx::query(
            "SELECT created_at, used_at, recovery_index IS NOT NULL AS usable \
             FROM account_recovery WHERE user_id = ?",
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(RecoveryStatus::default());
        };
        let parse = |s: Option<String>| {
            s.map(|s| OffsetDateTime::parse(&s, &Rfc3339).map_err(|e| Error::Time(e.to_string())))
                .transpose()
        };
        let usable: bool = row.try_get("usable")?;
        Ok(RecoveryStatus {
            code_created_at: if usable {
                parse(row.try_get("created_at")?)?
            } else {
                None
            },
            last_used_at: parse(row.try_get("used_at")?)?,
        })
    }

    /// The account and stored verifier of a usable code with `recovery_id`.
    pub async fn find_recovery(&self, recovery_id: &[u8]) -> Result<Option<(Uuid, Vec<u8>)>> {
        let row =
            sqlx::query("SELECT user_id, verifier FROM account_recovery WHERE recovery_index = ?")
                .bind(recovery_index(&self.master, recovery_id)?)
                .fetch_optional(&self.pool)
                .await?;
        let Some(row) = row else { return Ok(None) };
        let user_id: Uuid = row.try_get::<String, _>("user_id")?.parse()?;
        let key = user_key(&self.master, &user_id)?;
        let verifier = dec(&key, &row.try_get::<Vec<u8>, _>("verifier")?)?;
        Ok(Some((user_id, verifier)))
    }

    /// Recover the account: store its new passkey and consume the code, in one
    /// transaction. `Ok(false)` (nothing written) when the code with
    /// `recovery_id` is no longer the account's usable code: used meanwhile,
    /// or replaced.
    pub async fn recover_with_credential(
        &self,
        recovery_id: &[u8],
        cred: &Credential,
    ) -> Result<bool> {
        let key = user_key(&self.master, &cred.user_id)?;
        let mut tx = self.pool.begin().await?;
        let consumed = sqlx::query(
            "UPDATE account_recovery SET recovery_index = NULL, recovery_id = NULL, \
             verifier = NULL, used_at = ? WHERE user_id = ? AND recovery_index = ?",
        )
        .bind(fmt_time(OffsetDateTime::now_utc())?)
        .bind(cred.user_id.to_string())
        .bind(recovery_index(&self.master, recovery_id)?)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if consumed != 1 {
            return Ok(false);
        }
        sqlx::query("INSERT INTO webauthn_credentials (id, user_id, data) VALUES (?, ?, ?)")
            .bind(cred.id.to_string())
            .bind(cred.user_id.to_string())
            .bind(enc(&key, &cred.data)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Re-encrypts everything stored under the master key with `new_master`,
    /// which then replaces this store's key.
    ///
    /// Covers the encrypted columns of `users` (and `username_index`, which is
    /// derived from the master key: an index computed under the old key would
    /// never match a lookup computed under the new one), `webauthn_credentials`,
    /// `identities`, `oidc_keys`, `server_secrets` and `account_recovery`
    /// (whose index, like `username_index`, is recomputed). `sessions` holds
    /// nothing encrypted.
    ///
    /// One transaction: any failure rolls the whole rotation back and leaves
    /// every row as it was under the old key.
    ///
    /// Nothing visible from outside changes: OIDC signing keys and the VSID
    /// secret are stored, so issued tokens stay valid and every VSID keeps its
    /// value.
    pub async fn rotate_master_key(&mut self, new_master: MasterKey) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let user_rows = sqlx::query("SELECT id, username, server FROM users")
            .fetch_all(&mut *tx)
            .await?;
        for row in user_rows {
            let id_str: String = row.try_get("id")?;
            let id: Uuid = id_str.parse()?;
            let username_raw: Vec<u8> = row.try_get("username")?;
            let server_raw: Vec<u8> = row.try_get("server")?;

            let old_key = user_key(&self.master, &id)?;
            let username = dec(&old_key, &username_raw)?;
            let server = dec(&old_key, &server_raw)?;

            let new_key = user_key(&new_master, &id)?;
            let username_enc = enc(&new_key, &username)?;
            let server_enc = enc(&new_key, &server)?;

            let username_str = String::from_utf8(username)?;
            let server_str = String::from_utf8(server)?;
            let new_idx = username_index(&new_master, &username_str, &server_str)?;

            sqlx::query(
                "UPDATE users SET username = ?, server = ?, username_index = ? WHERE id = ?",
            )
            .bind(username_enc)
            .bind(server_enc)
            .bind(new_idx)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        }

        let cred_rows = sqlx::query("SELECT id, user_id, data, label FROM webauthn_credentials")
            .fetch_all(&mut *tx)
            .await?;
        for row in cred_rows {
            let cred_id: String = row.try_get("id")?;
            let user_id_str: String = row.try_get("user_id")?;
            let user_id: Uuid = user_id_str.parse()?;
            let data_raw: Vec<u8> = row.try_get("data")?;

            let old_key = user_key(&self.master, &user_id)?;
            let data = dec(&old_key, &data_raw)?;

            let new_key = user_key(&new_master, &user_id)?;
            let data_enc = enc(&new_key, &data)?;
            let label_enc = row
                .try_get::<Option<Vec<u8>>, _>("label")?
                .map(|raw| dec(&old_key, &raw).and_then(|plain| enc(&new_key, &plain)))
                .transpose()?;

            sqlx::query("UPDATE webauthn_credentials SET data = ?, label = ? WHERE id = ?")
                .bind(data_enc)
                .bind(label_enc)
                .bind(cred_id)
                .execute(&mut *tx)
                .await?;
        }

        let identity_rows = sqlx::query("SELECT id, account_id, name, description FROM identities")
            .fetch_all(&mut *tx)
            .await?;
        for row in identity_rows {
            let id: String = row.try_get("id")?;
            let account_id: Uuid = row.try_get::<String, _>("account_id")?.parse()?;
            let old_key = user_key(&self.master, &account_id)?;
            let new_key = user_key(&new_master, &account_id)?;

            let name = enc(
                &new_key,
                &dec(&old_key, &row.try_get::<Vec<u8>, _>("name")?)?,
            )?;
            let description = row
                .try_get::<Option<Vec<u8>>, _>("description")?
                .map(|raw| dec(&old_key, &raw).and_then(|plain| enc(&new_key, &plain)))
                .transpose()?;

            sqlx::query("UPDATE identities SET name = ?, description = ? WHERE id = ?")
                .bind(name)
                .bind(description)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }

        let oidc_rows = sqlx::query("SELECT kid, seed FROM oidc_keys")
            .fetch_all(&mut *tx)
            .await?;
        let old_oidc = oidc_seed_key(&self.master)?;
        let new_oidc = oidc_seed_key(&new_master)?;
        for row in oidc_rows {
            let kid: String = row.try_get("kid")?;
            let seed = Zeroizing::new(dec(&old_oidc, &row.try_get::<Vec<u8>, _>("seed")?)?);
            sqlx::query("UPDATE oidc_keys SET seed = ? WHERE kid = ?")
                .bind(enc(&new_oidc, &seed)?)
                .bind(kid)
                .execute(&mut *tx)
                .await?;
        }

        let secret_rows = sqlx::query("SELECT name, value FROM server_secrets")
            .fetch_all(&mut *tx)
            .await?;
        let old_secrets = server_secret_key(&self.master)?;
        let new_secrets = server_secret_key(&new_master)?;
        for row in secret_rows {
            let name: String = row.try_get("name")?;
            let value = Zeroizing::new(dec(&old_secrets, &row.try_get::<Vec<u8>, _>("value")?)?);
            sqlx::query("UPDATE server_secrets SET value = ? WHERE name = ?")
                .bind(enc(&new_secrets, &value)?)
                .bind(name)
                .execute(&mut *tx)
                .await?;
        }

        let recovery_rows = sqlx::query(
            "SELECT user_id, recovery_id, verifier FROM account_recovery \
             WHERE recovery_index IS NOT NULL",
        )
        .fetch_all(&mut *tx)
        .await?;
        for row in recovery_rows {
            let user_id_str: String = row.try_get("user_id")?;
            let user_id: Uuid = user_id_str.parse()?;
            let old_key = user_key(&self.master, &user_id)?;
            let new_key = user_key(&new_master, &user_id)?;
            let recovery_id = dec(&old_key, &row.try_get::<Vec<u8>, _>("recovery_id")?)?;
            let verifier = dec(&old_key, &row.try_get::<Vec<u8>, _>("verifier")?)?;
            sqlx::query(
                "UPDATE account_recovery SET recovery_index = ?, recovery_id = ?, verifier = ? \
                 WHERE user_id = ?",
            )
            .bind(recovery_index(&new_master, &recovery_id)?)
            .bind(enc(&new_key, &recovery_id)?)
            .bind(enc(&new_key, &verifier)?)
            .bind(user_id_str)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        self.master = new_master;
        Ok(())
    }

    // -- Account sessions (ADR-005 §1) -----------------------------------------

    /// Open a session for `account_id`: returns the token for the cookie
    /// (base64url of 32 random bytes). Only its hash is stored. The session
    /// ends after `idle` without use, and after `lifetime` in any case.
    /// Expired sessions are pruned on the way.
    pub async fn create_session(
        &self,
        account_id: Uuid,
        idle: std::time::Duration,
        lifetime: std::time::Duration,
    ) -> Result<Zeroizing<String>> {
        let raw = Zeroizing::new(helpers4::random::random_bytes(32)?);
        let token = Zeroizing::new(base64_url(&raw));
        let now = now_unix();
        let expires_at = now + lifetime.as_secs() as i64;
        let idle_expires_at = (now + idle.as_secs() as i64).min(expires_at);
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?1 OR idle_expires_at <= ?1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO sessions (token_hash, account_id, created_at, idle_expires_at, expires_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(session_hash(&token))
        .bind(account_id.to_string())
        .bind(now)
        .bind(idle_expires_at)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    /// The live session behind `token`, its idle deadline pushed back by
    /// `idle` (never past its absolute end). `None` when unknown or expired.
    pub async fn use_session(
        &self,
        token: &str,
        idle: std::time::Duration,
    ) -> Result<Option<SessionInfo>> {
        let now = now_unix();
        let row = sqlx::query(
            "UPDATE sessions SET idle_expires_at = MIN(?1 + ?2, expires_at) \
             WHERE token_hash = ?3 AND idle_expires_at > ?1 AND expires_at > ?1 \
             RETURNING account_id, created_at, idle_expires_at, expires_at",
        )
        .bind(now)
        .bind(idle.as_secs() as i64)
        .bind(session_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(SessionInfo {
            account_id: row.try_get::<String, _>("account_id")?.parse()?,
            created_at: row.try_get("created_at")?,
            idle_expires_at: row.try_get("idle_expires_at")?,
            expires_at: row.try_get("expires_at")?,
        }))
    }

    /// End the session behind `token` (sign out). Unknown tokens are ignored.
    pub async fn delete_session(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(session_hash(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // -- Relying parties (ADR-005 §2) ------------------------------------------

    /// Register a relying party. Returns it with its secret when
    /// `confidential`: 32 random bytes in base64url, of which only the hash is
    /// stored, so this is the one time the secret can be read.
    pub async fn create_client(
        &self,
        name: &str,
        redirect_uris: &[String],
        confidential: bool,
    ) -> Result<(Client, Option<Zeroizing<String>>)> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
            return Err(Error::InvalidClient(
                "the name must have 1 to 100 characters, none of them a control character",
            ));
        }
        if redirect_uris.is_empty() {
            return Err(Error::InvalidClient(
                "at least one redirect URI is required",
            ));
        }
        for uri in redirect_uris {
            validate_redirect_uri(uri)?;
        }
        let secret = if confidential {
            let raw = Zeroizing::new(helpers4::random::random_bytes(32)?);
            Some(Zeroizing::new(base64_url(&raw)))
        } else {
            None
        };
        let client = Client {
            client_id: Uuid::new_v4().to_string(),
            name: name.to_owned(),
            redirect_uris: redirect_uris.to_vec(),
            confidential,
            created_at: now_unix(),
        };
        sqlx::query(
            "INSERT INTO clients (client_id, name, redirect_uris, secret_hash, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&client.client_id)
        .bind(&client.name)
        .bind(serde_json::to_string(&client.redirect_uris).map_err(|_| Error::InvalidBlob)?)
        .bind(secret.as_ref().map(|s| session_hash(s)))
        .bind(client.created_at)
        .execute(&self.pool)
        .await?;
        Ok((client, secret))
    }

    /// The relying party registered as `client_id`, if any.
    pub async fn fetch_client(&self, client_id: &str) -> Result<Option<Client>> {
        let row = sqlx::query(
            "SELECT client_id, name, redirect_uris, secret_hash IS NOT NULL AS confidential, \
             created_at FROM clients WHERE client_id = ?",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| client_from_row(&r)).transpose()
    }

    /// Every registered relying party, oldest first.
    pub async fn list_clients(&self) -> Result<Vec<Client>> {
        sqlx::query(
            "SELECT client_id, name, redirect_uris, secret_hash IS NOT NULL AS confidential, \
             created_at FROM clients ORDER BY created_at, client_id",
        )
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(client_from_row)
        .collect()
    }

    /// Remove a relying party and the identity choices made for it. Returns
    /// whether it existed.
    pub async fn delete_client(&self, client_id: &str) -> Result<bool> {
        let done = sqlx::query("DELETE FROM clients WHERE client_id = ?")
            .bind(client_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Whether `secret` is the secret of confidential client `client_id`.
    /// `false` for an unknown client and for a public one.
    pub async fn verify_client_secret(&self, client_id: &str, secret: &str) -> Result<bool> {
        let stored: Option<Option<String>> =
            sqlx::query_scalar("SELECT secret_hash FROM clients WHERE client_id = ?")
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some(Some(stored)) = stored else {
            return Ok(false);
        };
        Ok(helpers4::bytes::constant_time_eq(
            stored.as_bytes(),
            session_hash(secret).as_bytes(),
        ))
    }

    /// The identity `account_id` last presented to `client_id`, if it still
    /// exists.
    pub async fn chosen_identity(&self, account_id: Uuid, client_id: &str) -> Result<Option<Uuid>> {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT identity_id FROM client_identities WHERE account_id = ? AND client_id = ?",
        )
        .bind(account_id.to_string())
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        id.map(|s| s.parse().map_err(Error::from)).transpose()
    }

    /// Remember that `account_id` presents `identity_id` to `client_id`.
    /// [`Error::NotFound`] when the identity is not one of this account's.
    pub async fn set_chosen_identity(
        &self,
        account_id: Uuid,
        client_id: &str,
        identity_id: Uuid,
    ) -> Result<()> {
        let done = sqlx::query(
            "INSERT INTO client_identities (account_id, client_id, identity_id, updated_at) \
             SELECT ?1, ?2, ?3, ?4 WHERE EXISTS \
               (SELECT 1 FROM identities WHERE id = ?3 AND account_id = ?1) \
             ON CONFLICT (account_id, client_id) DO UPDATE SET \
               identity_id = excluded.identity_id, updated_at = excluded.updated_at",
        )
        .bind(account_id.to_string())
        .bind(client_id)
        .bind(identity_id.to_string())
        .bind(now_unix())
        .execute(&self.pool)
        .await?;
        if done.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }
}

fn client_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Client> {
    let uris: String = row.try_get("redirect_uris")?;
    Ok(Client {
        client_id: row.try_get("client_id")?,
        name: row.try_get("name")?,
        redirect_uris: serde_json::from_str(&uris).map_err(|_| Error::InvalidBlob)?,
        confidential: row.try_get("confidential")?,
        created_at: row.try_get("created_at")?,
    })
}

/// A redirect URI is an absolute `https` URL without fragment. Plain `http`
/// is accepted for the loopback host only, where a development site runs.
fn validate_redirect_uri(uri: &str) -> Result<()> {
    let url = url::Url::parse(uri)
        .map_err(|_| Error::InvalidClient("a redirect URI must be an absolute URL"))?;
    if url.fragment().is_some() {
        return Err(Error::InvalidClient(
            "a redirect URI must not have a fragment",
        ));
    }
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => Err(Error::InvalidClient(
            "a redirect URI must use https (http is accepted for localhost only)",
        )),
    }
}

/// A live account session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub account_id: Uuid,
    /// Unix time of the passkey ceremony that opened the session.
    pub created_at: i64,
    /// Unix time the session ends if unused.
    pub idle_expires_at: i64,
    /// Unix time the session ends in any case.
    pub expires_at: i64,
}

/// SHA3-256 of a session token, hex. The token has 256 random bits: a plain
/// hash is enough, a database dump gives no usable session.
fn session_hash(token: &str) -> String {
    use sha3::{Digest, Sha3_256};
    helpers4::hex::encode(&Sha3_256::digest(token.as_bytes()))
}

fn base64_url(bytes: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(bytes)
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

        let rows = sqlx::query("SELECT username, server FROM users")
            .fetch_all(&pool)
            .await?;
        assert!(!rows.is_empty());

        let row = &rows[0];
        let username_raw: Vec<u8> = row.try_get(0)?;
        let server_raw: Vec<u8> = row.try_get(1)?;

        // Stored bytes must differ from the plaintext UTF-8 representation.
        assert_ne!(username_raw, b"alice", "username stored in plaintext");
        assert_ne!(server_raw, b"example.com", "server stored in plaintext");
        // And must not contain the plaintext as a readable substring.
        assert!(
            !String::from_utf8_lossy(&username_raw).contains("alice"),
            "username readable in dump"
        );
        Ok(())
    }

    fn sample_identity(account_id: Uuid) -> Identity {
        let id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        Identity {
            id,
            account_id,
            name: "Secret Persona".to_string(),
            logo: "icon:ph:rocket-launch".to_string(),
            description: Some("only my friends know".to_string()),
            created_at: now,
            updated_at: now,
        }
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn identity_roundtrip_and_listing(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        store_user(&pool, &master, &user).await.unwrap();

        let a = sample_identity(user.id);
        let mut b = sample_identity(user.id);
        b.description = None;
        store_identity(&pool, &master, &a).await.unwrap();
        store_identity(&pool, &master, &b).await.unwrap();

        let got = fetch_identity(&pool, &master, user.id, a.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.name, "Secret Persona");
        assert_eq!(got.logo, "icon:ph:rocket-launch");
        assert_eq!(got.description.as_deref(), Some("only my friends know"));
        assert!(
            fetch_identity(&pool, &master, user.id, b.id)
                .await
                .unwrap()
                .unwrap()
                .description
                .is_none()
        );
        assert_eq!(
            fetch_identities(&pool, &master, user.id)
                .await
                .unwrap()
                .len(),
            2
        );
        Ok(())
    }

    /// An identity is only reachable through its own account.
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn identity_is_scoped_to_its_account(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let owner = sample_user();
        let mut other = sample_user();
        other.username = "bob".to_string();
        store_user(&pool, &master, &owner).await.unwrap();
        store_user(&pool, &master, &other).await.unwrap();

        let ident = sample_identity(owner.id);
        store_identity(&pool, &master, &ident).await.unwrap();

        assert!(
            fetch_identity(&pool, &master, other.id, ident.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fetch_identities(&pool, &master, other.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            delete_identity(&pool, other.id, ident.id).await,
            Err(Error::NotFound)
        ));
        let mut hijack = ident.clone();
        hijack.account_id = other.id;
        assert!(matches!(
            update_identity(&pool, &master, &hijack).await,
            Err(Error::NotFound)
        ));
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn update_changes_display_fields(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        store_user(&pool, &master, &user).await.unwrap();
        let mut ident = sample_identity(user.id);
        store_identity(&pool, &master, &ident).await.unwrap();

        ident.name = "  Renamed ".to_string();
        ident.logo = "icon:ph:github-logo".to_string();
        ident.description = None;
        update_identity(&pool, &master, &ident).await.unwrap();

        let got = fetch_identity(&pool, &master, user.id, ident.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.name, "Renamed");
        assert_eq!(got.logo, "icon:ph:github-logo");
        assert!(got.description.is_none());
        assert!(got.updated_at >= got.created_at);
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn invalid_identity_is_rejected_before_any_write(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        store_user(&pool, &master, &user).await.unwrap();

        let mut no_name = sample_identity(user.id);
        no_name.name = "  ".to_string();
        let mut bad_logo = sample_identity(user.id);
        bad_logo.logo = "https://example.com/x.png".to_string();
        for bad in [no_name, bad_logo] {
            assert!(matches!(
                store_identity(&pool, &master, &bad).await,
                Err(Error::InvalidIdentity(_))
            ));
        }
        assert!(
            fetch_identities(&pool, &master, user.id)
                .await
                .unwrap()
                .is_empty()
        );
        Ok(())
    }

    /// A raw dump must not expose the name, the DID or the description.
    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn identity_dump_contains_no_plaintext(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        store_user(&pool, &master, &user).await.unwrap();
        store_identity(&pool, &master, &sample_identity(user.id))
            .await
            .unwrap();

        let row = sqlx::query("SELECT name, description FROM identities")
            .fetch_one(&pool)
            .await?;
        for (col, needle) in [(0, "Persona"), (1, "friends")] {
            let raw: Vec<u8> = row.try_get(col)?;
            assert!(
                !String::from_utf8_lossy(&raw).contains(needle),
                "column {col} readable in dump"
            );
        }
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn identities_follow_their_account_on_delete(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        store_user(&pool, &master, &user).await.unwrap();
        store_identity(&pool, &master, &sample_identity(user.id))
            .await
            .unwrap();

        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user.id.to_string())
            .execute(&pool)
            .await?;
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identities")
            .fetch_one(&pool)
            .await?;
        assert_eq!(left, 0);
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn credential_labels_are_encrypted_and_scoped(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        store_user(&pool, &master, &user).await.unwrap();
        let cred = Credential {
            id: Uuid::new_v4(),
            user_id: user.id,
            data: b"x".to_vec(),
        };
        store_credential(&pool, &master, &cred).await.unwrap();

        assert!(
            fetch_credential_labels(&pool, &master, user.id)
                .await
                .unwrap()
                .is_empty()
        );
        set_credential_label(&pool, &master, user.id, cred.id, "  Pixel 9 ")
            .await
            .unwrap();
        let labels = fetch_credential_labels(&pool, &master, user.id)
            .await
            .unwrap();
        assert_eq!(labels.get(&cred.id).map(String::as_str), Some("Pixel 9"));

        let raw: Vec<u8> = sqlx::query_scalar("SELECT label FROM webauthn_credentials")
            .fetch_one(&pool)
            .await?;
        assert!(!String::from_utf8_lossy(&raw).contains("Pixel"));

        assert!(matches!(
            set_credential_label(&pool, &master, Uuid::new_v4(), cred.id, "x").await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            set_credential_label(&pool, &master, user.id, cred.id, &"x".repeat(65)).await,
            Err(Error::InvalidLabel)
        ));
        set_credential_label(&pool, &master, user.id, cred.id, "  ")
            .await
            .unwrap();
        assert!(
            fetch_credential_labels(&pool, &master, user.id)
                .await
                .unwrap()
                .is_empty()
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
            "INSERT INTO users (id, username, server, created_at, username_index) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
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

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn delete_credential_removes_row(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        let user_id = user.id;
        store_user(&pool, &master, &user).await.unwrap();

        let cred = Credential {
            id: Uuid::new_v4(),
            user_id,
            data: b"webauthn-cred".to_vec(),
        };
        store_credential(&pool, &master, &cred).await.unwrap();

        delete_credential(&pool, user_id, cred.id).await.unwrap();

        let remaining = fetch_credentials(&pool, &master, user_id).await.unwrap();
        assert!(remaining.is_empty(), "credential should be deleted");
        Ok(())
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn delete_credential_wrong_user_returns_not_found(pool: SqlitePool) -> sqlx::Result<()> {
        let master = master();
        let user = sample_user();
        let user_id = user.id;
        store_user(&pool, &master, &user).await.unwrap();

        let cred = Credential {
            id: Uuid::new_v4(),
            user_id,
            data: b"webauthn-cred".to_vec(),
        };
        store_credential(&pool, &master, &cred).await.unwrap();

        let other_user_id = Uuid::new_v4();
        let result = delete_credential(&pool, other_user_id, cred.id).await;
        assert!(
            matches!(result, Err(Error::NotFound)),
            "wrong user_id should return NotFound, got {result:?}"
        );

        // Credential must still be present
        let remaining = fetch_credentials(&pool, &master, user_id).await.unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "credential must survive a failed delete"
        );
        Ok(())
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

    fn new_master() -> MasterKey {
        MasterKey::from_hex(&"cd".repeat(32)).unwrap()
    }

    #[tokio::test]
    async fn oidc_keys_rotate_retire_prune_and_survive_master_rotation() {
        let mut store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();
        assert!(store.oidc_signing_keys().await.unwrap().is_empty());

        store.add_oidc_signing_key("k1", &[1u8; 32]).await.unwrap();
        store.add_oidc_signing_key("k2", &[2u8; 32]).await.unwrap();
        let keys = store.oidc_signing_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].kid, "k2", "current key first");
        assert!(keys[0].retired_at.is_none());
        assert_eq!(*keys[1].seed, [1u8; 32]);
        assert!(keys[1].retired_at.is_some(), "the previous key is retired");

        // The seed is not stored in clear.
        let raw: Vec<Vec<u8>> = sqlx::query_scalar("SELECT seed FROM oidc_keys")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        assert!(
            raw.iter()
                .all(|r| r.as_slice() != [1u8; 32] && r.as_slice() != [2u8; 32])
        );

        store.rotate_master_key(new_master()).await.unwrap();
        let keys = store.oidc_signing_keys().await.unwrap();
        assert_eq!(
            *keys[0].seed, [2u8; 32],
            "seeds re-encrypted under the new key"
        );

        // Pruning only drops retired keys older than the cut-off.
        let past = OffsetDateTime::now_utc() - time::Duration::hours(1);
        assert_eq!(store.prune_oidc_keys(past).await.unwrap(), 0);
        let future = OffsetDateTime::now_utc() + time::Duration::hours(1);
        assert_eq!(store.prune_oidc_keys(future).await.unwrap(), 1);
        let keys = store.oidc_signing_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, "k2");
    }

    #[tokio::test]
    async fn vsid_secret_is_random_and_stable() {
        let store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();

        let first = store.vsid_secret().await.unwrap();
        assert_ne!(*first, [0u8; 32]);
        let again = store.vsid_secret().await.unwrap();
        assert_eq!(*first, *again, "stored once, then only read");

        let other = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();
        assert_ne!(
            *first,
            *other.vsid_secret().await.unwrap(),
            "two databases under one master key do not share it"
        );

        // Not stored in clear.
        let raw: Vec<u8> =
            sqlx::query_scalar("SELECT value FROM server_secrets WHERE name = 'vsid'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(!raw.windows(32).any(|w| w == first.as_slice()));
    }

    #[tokio::test]
    async fn vsid_secret_survives_a_master_key_rotation() {
        let mut store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();
        let before = store.vsid_secret().await.unwrap();

        store.rotate_master_key(new_master()).await.unwrap();

        let after = store.vsid_secret().await.unwrap();
        assert_eq!(*before, *after);
    }

    #[tokio::test]
    async fn recovery_code_lifecycle_and_master_rotation() {
        let mut store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();
        let user = sample_user();
        store.store_user(&user).await.unwrap();
        assert_eq!(
            store.recovery_status(user.id).await.unwrap(),
            RecoveryStatus::default()
        );

        store
            .set_recovery_code(user.id, b"id-one!!", &[7u8; 32])
            .await
            .unwrap();
        // Replacing the code makes the previous one unknown.
        store
            .set_recovery_code(user.id, b"id-two!!", &[9u8; 32])
            .await
            .unwrap();
        assert!(store.find_recovery(b"id-one!!").await.unwrap().is_none());
        assert!(
            store
                .recovery_status(user.id)
                .await
                .unwrap()
                .code_created_at
                .is_some()
        );

        // Nothing readable in the table.
        let raw: Vec<Vec<u8>> = sqlx::query_scalar("SELECT verifier FROM account_recovery")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        assert!(raw.iter().all(|v| v.as_slice() != [9u8; 32]));

        store.rotate_master_key(new_master()).await.unwrap();
        let (found_user, verifier) = store.find_recovery(b"id-two!!").await.unwrap().unwrap();
        assert_eq!(found_user, user.id);
        assert_eq!(
            verifier,
            vec![9u8; 32],
            "readable and findable after rotation"
        );

        let cred = Credential {
            id: Uuid::new_v4(),
            user_id: user.id,
            data: b"new passkey".to_vec(),
        };
        assert!(
            store
                .recover_with_credential(b"id-two!!", &cred)
                .await
                .unwrap()
        );
        assert_eq!(store.fetch_credentials(user.id).await.unwrap().len(), 1);
        // Consumed: a second use writes nothing.
        let again = Credential {
            id: Uuid::new_v4(),
            ..cred.clone()
        };
        assert!(
            !store
                .recover_with_credential(b"id-two!!", &again)
                .await
                .unwrap()
        );
        assert_eq!(store.fetch_credentials(user.id).await.unwrap().len(), 1);
        let status = store.recovery_status(user.id).await.unwrap();
        assert!(status.code_created_at.is_none());
        assert!(status.last_used_at.is_some());
    }

    #[tokio::test]
    async fn sessions_expire_idle_and_absolute_and_end_on_sign_out() {
        use std::time::Duration;
        let store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();
        let user = sample_user();
        store.store_user(&user).await.unwrap();

        let token = store
            .create_session(
                user.id,
                Duration::from_secs(3600),
                Duration::from_secs(43200),
            )
            .await
            .unwrap();
        assert_eq!(token.len(), 43, "base64url of 32 bytes");
        let info = store
            .use_session(&token, Duration::from_secs(3600))
            .await
            .unwrap()
            .expect("live session");
        assert_eq!(info.account_id, user.id);
        assert!(info.idle_expires_at <= info.expires_at);

        // Only the hash is stored.
        let stored: Vec<String> = sqlx::query_scalar("SELECT token_hash FROM sessions")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        assert!(stored.iter().all(|h| h.as_str() != token.as_str()));

        assert!(
            store
                .use_session("unknown", Duration::from_secs(3600))
                .await
                .unwrap()
                .is_none()
        );

        // Idle expiry: a session whose idle deadline passed is dead.
        sqlx::query("UPDATE sessions SET idle_expires_at = 1")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(
            store
                .use_session(&token, Duration::from_secs(3600))
                .await
                .unwrap()
                .is_none()
        );

        // Absolute expiry wins over use.
        let token = store
            .create_session(
                user.id,
                Duration::from_secs(3600),
                Duration::from_secs(43200),
            )
            .await
            .unwrap();
        sqlx::query("UPDATE sessions SET expires_at = 1 WHERE idle_expires_at > 1")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(
            store
                .use_session(&token, Duration::from_secs(3600))
                .await
                .unwrap()
                .is_none()
        );

        // Use never extends past the absolute end.
        let token = store
            .create_session(user.id, Duration::from_secs(3600), Duration::from_secs(60))
            .await
            .unwrap();
        let info = store
            .use_session(&token, Duration::from_secs(3600))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.idle_expires_at, info.expires_at);

        store.delete_session(&token).await.unwrap();
        assert!(
            store
                .use_session(&token, Duration::from_secs(3600))
                .await
                .unwrap()
                .is_none()
        );

        // Deleting the account ends its sessions.
        let token = store
            .create_session(
                user.id,
                Duration::from_secs(3600),
                Duration::from_secs(43200),
            )
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user.id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(
            store
                .use_session(&token, Duration::from_secs(3600))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rotate_master_key_round_trip() {
        let mut store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();

        let user = sample_user();
        let user_id = user.id;
        store.store_user(&user).await.unwrap();
        let cred = Credential {
            id: Uuid::new_v4(),
            user_id,
            data: b"webauthn-credential-bytes".to_vec(),
        };
        store.store_credential(&cred).await.unwrap();
        store
            .set_credential_label(user_id, cred.id, "YubiKey")
            .await
            .unwrap();
        let ident = sample_identity(user_id);
        let ident_id = ident.id;
        store.store_identity(&ident).await.unwrap();
        let mut bare = sample_identity(user_id);
        bare.description = None;
        store.store_identity(&bare).await.unwrap();

        store.rotate_master_key(new_master()).await.unwrap();

        // Identities were re-encrypted too, with and without a description.
        let got = store
            .fetch_identity(user_id, ident_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.name, "Secret Persona");
        assert_eq!(got.description.as_deref(), Some("only my friends know"));
        assert_eq!(store.fetch_identities(user_id).await.unwrap().len(), 2);
        assert_eq!(
            store.fetch_credential_labels(user_id).await.unwrap()[&cred.id],
            "YubiKey"
        );

        // The store's own key was updated — every existing accessor keeps
        // working transparently against what rotation just wrote.
        let fetched = store.fetch_user(user_id).await.unwrap().unwrap();
        assert_eq!(fetched.username, "alice");
        assert_eq!(fetched.server, "example.com");

        let creds = store.fetch_credentials(user_id).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].data, b"webauthn-credential-bytes");

        // The username_index was recomputed under the new key too — lookup
        // by username must still resolve, not just lookup by id.
        let found = store
            .fetch_user_by_username("alice", "example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, user_id);
    }

    #[tokio::test]
    async fn rotate_master_key_old_key_can_no_longer_decrypt() {
        let old_master = master();
        let mut store = EncryptedStore::new("sqlite::memory:", old_master)
            .await
            .unwrap();

        let user = sample_user();
        let user_id = user.id;
        store.store_user(&user).await.unwrap();

        store.rotate_master_key(new_master()).await.unwrap();

        // Read the now-rotated rows back out with the *old* key, standalone
        // (not through `store`, which already moved on to the new key).
        let result = fetch_user(&store.pool, &master(), user_id).await;
        assert!(
            result.is_err(),
            "the old master key should no longer decrypt rotated data"
        );
    }

    /// A failure partway through rotation (a malformed blob it can't decrypt)
    /// must roll back the *entire* transaction, not leave some rows rotated
    /// and others not.
    #[tokio::test]
    async fn rotate_master_key_rolls_back_entirely_on_partial_failure() {
        let old_master = master();
        let mut store = EncryptedStore::new("sqlite::memory:", old_master)
            .await
            .unwrap();

        // A normal, validly-encrypted user — processed successfully by the
        // `users` half of the rotation before the credential below is ever
        // reached.
        let user = sample_user();
        let user_id = user.id;
        store.store_user(&user).await.unwrap();

        // A credential with a deliberately malformed blob — too short to be
        // a valid AES-GCM blob (nonce alone is 12 bytes) — inserted directly
        // via raw SQL, bypassing `store_credential`'s normal encryption, so
        // rotation's `dec()` call on it fails.
        let cred_id = Uuid::new_v4();
        sqlx::query("INSERT INTO webauthn_credentials (id, user_id, data) VALUES (?, ?, ?)")
            .bind(cred_id.to_string())
            .bind(user_id.to_string())
            .bind(vec![0xde, 0xad, 0xbe])
            .execute(&store.pool)
            .await
            .unwrap();

        let result = store.rotate_master_key(new_master()).await;
        assert!(
            result.is_err(),
            "rotation should fail on the malformed credential blob"
        );

        // The store itself only swaps to the new key on success — after a
        // failed rotation it must still be usable with the *old* key.
        let fetched = store.fetch_user(user_id).await.unwrap().unwrap();
        assert_eq!(fetched.username, "alice", "user row must not be rotated");

        // Prove it at the SQL level too: the username_index computed under
        // the old key must still be the one on disk — if the `users` UPDATE
        // had actually committed before the credential failure, it wouldn't.
        let old_idx = username_index(&master(), "alice", "example.com").unwrap();
        let row = sqlx::query("SELECT username_index FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        let stored_idx: String = row.try_get("username_index").unwrap();
        assert_eq!(stored_idx, old_idx, "username_index must not be rotated");
    }

    #[tokio::test]
    async fn clients_are_registered_listed_authenticated_and_removed() {
        let store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();
        let uris = vec!["https://shop.example/callback".to_string()];

        let (site, secret) = store.create_client(" Shop ", &uris, true).await.unwrap();
        let secret = secret.expect("a confidential client gets a secret");
        assert_eq!(site.name, "Shop");
        assert!(site.confidential);
        assert_eq!(secret.len(), 43, "32 bytes in unpadded base64url");

        let (app, none) = store
            .create_client("App", &["http://localhost:3000/cb".to_string()], false)
            .await
            .unwrap();
        assert!(none.is_none() && !app.confidential);

        assert_eq!(
            store.fetch_client(&site.client_id).await.unwrap().as_ref(),
            Some(&site)
        );
        assert_eq!(store.list_clients().await.unwrap().len(), 2);
        assert!(store.fetch_client("unknown").await.unwrap().is_none());

        // The secret is checked against its hash; a public client has none.
        assert!(
            store
                .verify_client_secret(&site.client_id, &secret)
                .await
                .unwrap()
        );
        assert!(
            !store
                .verify_client_secret(&site.client_id, "wrong")
                .await
                .unwrap()
        );
        assert!(
            !store
                .verify_client_secret(&app.client_id, "")
                .await
                .unwrap()
        );
        assert!(
            !store
                .verify_client_secret("unknown", &secret)
                .await
                .unwrap()
        );

        // The secret itself is nowhere in the database.
        let stored: String =
            sqlx::query_scalar("SELECT secret_hash FROM clients WHERE client_id = ?")
                .bind(&site.client_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_ne!(stored, *secret);

        assert!(store.delete_client(&site.client_id).await.unwrap());
        assert!(!store.delete_client(&site.client_id).await.unwrap());
        assert!(store.fetch_client(&site.client_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn clients_need_a_name_and_safe_redirect_uris() {
        let store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();
        let ok = vec!["https://shop.example/cb".to_string()];
        for name in ["", "  ", "a\nb"] {
            assert!(matches!(
                store.create_client(name, &ok, false).await,
                Err(Error::InvalidClient(_))
            ));
        }
        for uri in [
            "",
            "/callback",
            "http://shop.example/cb",
            "https://shop.example/cb#fragment",
            "javascript:alert(1)",
        ] {
            assert!(
                matches!(
                    store.create_client("Shop", &[uri.to_string()], false).await,
                    Err(Error::InvalidClient(_))
                ),
                "{uri}"
            );
        }
        assert!(matches!(
            store.create_client("Shop", &[], false).await,
            Err(Error::InvalidClient(_))
        ));
    }

    #[tokio::test]
    async fn the_identity_chosen_for_a_client_is_remembered_per_account() {
        let store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();
        let user = sample_user();
        store.store_user(&user).await.unwrap();
        let mut other = sample_user();
        other.id = Uuid::new_v4();
        other.username = "other".into();
        store.store_user(&other).await.unwrap();
        let (site, _) = store
            .create_client("Shop", &["https://shop.example/cb".to_string()], false)
            .await
            .unwrap();
        let identity = |account_id: Uuid, name: &str| Identity {
            id: Uuid::new_v4(),
            account_id,
            name: name.into(),
            logo: "icon:ph:user".into(),
            description: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let (a, b, theirs) = (
            identity(user.id, "A"),
            identity(user.id, "B"),
            identity(other.id, "T"),
        );
        for i in [&a, &b, &theirs] {
            store.store_identity(i).await.unwrap();
        }

        assert_eq!(
            store
                .chosen_identity(user.id, &site.client_id)
                .await
                .unwrap(),
            None
        );
        store
            .set_chosen_identity(user.id, &site.client_id, a.id)
            .await
            .unwrap();
        store
            .set_chosen_identity(user.id, &site.client_id, b.id)
            .await
            .unwrap();
        assert_eq!(
            store
                .chosen_identity(user.id, &site.client_id)
                .await
                .unwrap(),
            Some(b.id)
        );
        assert_eq!(
            store
                .chosen_identity(other.id, &site.client_id)
                .await
                .unwrap(),
            None
        );

        // Another account's identity cannot be chosen.
        assert!(matches!(
            store
                .set_chosen_identity(user.id, &site.client_id, theirs.id)
                .await,
            Err(Error::NotFound)
        ));

        // Deleting the identity forgets the choice.
        store.delete_identity(user.id, b.id).await.unwrap();
        assert_eq!(
            store
                .chosen_identity(user.id, &site.client_id)
                .await
                .unwrap(),
            None
        );
    }
}
