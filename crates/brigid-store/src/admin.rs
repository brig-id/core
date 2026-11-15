//! Administration: the role, suspension, the links that create accounts or
//! grant the role, the sign-up policy, and the log of administrative actions.
//!
//! What an administrator can reach stops at the account: its generated
//! username, its dates, how many passkeys it has. Nothing here reads an
//! identity, a label, an attribute or a grant.

use sqlx::Row as _;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    model::{
        AccountStanding, AccountSummary, AdminAction, AdminLogEntry, Link, LinkKind, SignupPolicy,
    },
    store::{
        EncryptedStore, base64_url, dec, dec_json, enc_json, now_unix, server_secret_key,
        session_hash, user_key,
    },
};

/// Spends one use of the link `token`, whatever its kind, inside the
/// caller's transaction. `None` when the link is unknown, expired or used
/// up: nothing is spent then.
pub(crate) async fn spend_link(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token: &str,
) -> Result<Option<LinkKind>> {
    let kind: Option<String> = sqlx::query_scalar(
        "UPDATE links SET uses_left = uses_left - 1 \
         WHERE token_hash = ? AND uses_left > 0 AND expires_at > ? RETURNING kind",
    )
    .bind(session_hash(token))
    .bind(now_unix())
    .fetch_optional(&mut **tx)
    .await?;
    Ok(kind.as_deref().and_then(LinkKind::parse))
}

impl EncryptedStore {
    // -- The role and suspension -------------------------------------------------

    /// The role of an account and whether it is suspended. `None` when the
    /// account does not exist.
    pub async fn account_standing(&self, account_id: Uuid) -> Result<Option<AccountStanding>> {
        let row = sqlx::query("SELECT admin, suspended_at FROM users WHERE id = ?")
            .bind(account_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(AccountStanding {
                admin: row.try_get::<i64, _>("admin")? != 0,
                suspended: row.try_get::<Option<i64>, _>("suspended_at")?.is_some(),
            })
        })
        .transpose()
    }

    /// How many accounts exist.
    pub async fn count_accounts(&self) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?)
    }

    /// How many administrators can sign in: suspended ones do not count.
    pub async fn count_administrators(&self) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE admin = 1 AND suspended_at IS NULL",
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Grant or withdraw the administrator role. [`Error::NotFound`] for an
    /// unknown account; [`Error::LastAdministrator`] when withdrawing it
    /// would leave nobody to administer the server.
    pub async fn set_administrator(&self, account_id: Uuid, admin: bool) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query("UPDATE users SET admin = ? WHERE id = ?")
            .bind(i64::from(admin))
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await?;
        if done.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        if !admin {
            keep_an_administrator(&mut tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Suspend an account: its sessions end, and it opens no new one until
    /// the suspension is lifted. Nothing of it is deleted.
    /// [`Error::LastAdministrator`] when it is the last administrator.
    pub async fn suspend_account(&self, account_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let done =
            sqlx::query("UPDATE users SET suspended_at = COALESCE(suspended_at, ?) WHERE id = ?")
                .bind(now_unix())
                .bind(account_id.to_string())
                .execute(&mut *tx)
                .await?;
        if done.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        keep_an_administrator(&mut tx).await?;
        sqlx::query("DELETE FROM sessions WHERE account_id = ?")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Lift a suspension. [`Error::NotFound`] for an unknown account.
    pub async fn unsuspend_account(&self, account_id: Uuid) -> Result<()> {
        let done = sqlx::query("UPDATE users SET suspended_at = NULL WHERE id = ?")
            .bind(account_id.to_string())
            .execute(&self.pool)
            .await?;
        if done.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Delete an account on an administrator's decision: as
    /// [`delete_account`](Self::delete_account), but never the last
    /// administrator. Returns whether the account existed.
    pub async fn remove_account(&self, account_id: Uuid) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let had_one = administrators(&mut tx).await? > 0;
        let done = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await?;
        if had_one {
            keep_an_administrator(&mut tx).await?;
        }
        tx.commit().await?;
        Ok(done.rows_affected() > 0)
    }

    /// Every account, as an administrator sees it, oldest first.
    pub async fn list_accounts(&self) -> Result<Vec<AccountSummary>> {
        let rows = sqlx::query(
            "SELECT u.id, u.username, u.created_at, u.admin, u.suspended_at, u.last_sign_in_at, \
               (SELECT COUNT(*) FROM webauthn_credentials c WHERE c.user_id = u.id) AS passkeys, \
               EXISTS (SELECT 1 FROM account_recovery r \
                       WHERE r.user_id = u.id AND r.recovery_index IS NOT NULL) AS recovery_code \
             FROM users u ORDER BY u.created_at, u.id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let id: Uuid = row.try_get::<String, _>("id")?.parse()?;
                let key = user_key(&self.master, &id)?;
                Ok(AccountSummary {
                    id,
                    username: String::from_utf8(dec(
                        &key,
                        &row.try_get::<Vec<u8>, _>("username")?,
                    )?)?,
                    created_at: OffsetDateTime::parse(
                        &row.try_get::<String, _>("created_at")?,
                        &Rfc3339,
                    )
                    .map_err(|e| Error::Time(e.to_string()))?,
                    admin: row.try_get::<i64, _>("admin")? != 0,
                    suspended_at: row.try_get("suspended_at")?,
                    last_sign_in_at: row.try_get("last_sign_in_at")?,
                    passkeys: row.try_get("passkeys")?,
                    recovery_code: row.try_get::<i64, _>("recovery_code")? != 0,
                })
            })
            .collect()
    }

    // -- Links ---------------------------------------------------------------------

    /// Make a link: 128 random bits, of which only the hash is stored, so
    /// this is the one time it can be read. It can be used `uses` times
    /// during `ttl`. `created_by` is the administrator who made it, `None`
    /// on the machine.
    pub async fn create_link(
        &self,
        kind: LinkKind,
        uses: u32,
        ttl: std::time::Duration,
        created_by: Option<Uuid>,
    ) -> Result<(Link, Zeroizing<String>)> {
        let raw = Zeroizing::new(helpers4::random::random_bytes(16)?);
        let token = Zeroizing::new(base64_url(&raw));
        let now = now_unix();
        let link = Link {
            id: Uuid::new_v4(),
            kind,
            uses_left: i64::from(uses.max(1)),
            created_at: now,
            expires_at: now.saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX)),
        };
        sqlx::query(
            "INSERT INTO links (id, token_hash, kind, uses_left, created_at, expires_at, created_by) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(link.id.to_string())
        .bind(session_hash(&token))
        .bind(kind.as_str())
        .bind(link.uses_left)
        .bind(link.created_at)
        .bind(link.expires_at)
        .bind(created_by.map(|id| id.to_string()))
        .execute(&self.pool)
        .await?;
        Ok((link, token))
    }

    /// What the link `token` is for, if it can still be used. Spends nothing.
    pub async fn link_kind(&self, token: &str) -> Result<Option<LinkKind>> {
        let kind: Option<String> = sqlx::query_scalar(
            "SELECT kind FROM links WHERE token_hash = ? AND uses_left > 0 AND expires_at > ?",
        )
        .bind(session_hash(token))
        .bind(now_unix())
        .fetch_optional(&self.pool)
        .await?;
        Ok(kind.as_deref().and_then(LinkKind::parse))
    }

    /// Spend the administrator link `token` for `account_id`: the account
    /// gets the role, and the link is used. [`Error::LinkSpent`] when the
    /// link is not a usable administrator link; [`Error::NotFound`] when the
    /// account does not exist. Nothing changes in either case.
    pub async fn claim_administrator(&self, token: &str, account_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        if spend_link(&mut tx, token).await? != Some(LinkKind::Admin) {
            return Err(Error::LinkSpent);
        }
        let done = sqlx::query("UPDATE users SET admin = 1 WHERE id = ?")
            .bind(account_id.to_string())
            .execute(&mut *tx)
            .await?;
        if done.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        tx.commit().await?;
        Ok(())
    }

    /// The links of `kind` that can still be used, oldest first. Expired and
    /// used-up ones are deleted on the way.
    pub async fn list_links(&self, kind: LinkKind) -> Result<Vec<Link>> {
        sqlx::query("DELETE FROM links WHERE uses_left <= 0 OR expires_at <= ?")
            .bind(now_unix())
            .execute(&self.pool)
            .await?;
        let rows = sqlx::query(
            "SELECT id, kind, uses_left, created_at, expires_at FROM links \
             WHERE kind = ? ORDER BY created_at, id",
        )
        .bind(kind.as_str())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(Link {
                    id: row.try_get::<String, _>("id")?.parse()?,
                    kind,
                    uses_left: row.try_get("uses_left")?,
                    created_at: row.try_get("created_at")?,
                    expires_at: row.try_get("expires_at")?,
                })
            })
            .collect()
    }

    /// Revoke the link `id` of `kind`. Returns whether it existed.
    pub async fn revoke_link(&self, kind: LinkKind, id: Uuid) -> Result<bool> {
        let done = sqlx::query("DELETE FROM links WHERE id = ? AND kind = ?")
            .bind(id.to_string())
            .bind(kind.as_str())
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Revoke every link of `kind`: a new setup link replaces the earlier one.
    pub async fn revoke_links(&self, kind: LinkKind) -> Result<()> {
        sqlx::query("DELETE FROM links WHERE kind = ?")
            .bind(kind.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // -- The sign-up policy --------------------------------------------------------

    /// Who may create an account. By invitation until an administrator, or
    /// the operator on the machine, says otherwise.
    pub async fn signup_policy(&self) -> Result<SignupPolicy> {
        let value: Option<String> =
            sqlx::query_scalar("SELECT value FROM settings WHERE name = 'signup'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(value
            .as_deref()
            .and_then(SignupPolicy::parse)
            .unwrap_or(SignupPolicy::Invitation))
    }

    pub async fn set_signup_policy(&self, policy: SignupPolicy) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (name, value) VALUES ('signup', ?) \
             ON CONFLICT (name) DO UPDATE SET value = excluded.value",
        )
        .bind(policy.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // -- The log of administrative actions -----------------------------------------

    /// Write an administrative action to the log.
    pub async fn log_admin_action(&self, action: &AdminAction) -> Result<()> {
        let key = server_secret_key(&self.master)?;
        sqlx::query("INSERT INTO admin_log (at, entry) VALUES (?, ?)")
            .bind(now_unix())
            .bind(enc_json(&key, action)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The latest `limit` entries of the log, the newest first.
    pub async fn admin_log(&self, limit: u32) -> Result<Vec<AdminLogEntry>> {
        let key = server_secret_key(&self.master)?;
        let rows = sqlx::query("SELECT at, entry FROM admin_log ORDER BY id DESC LIMIT ?")
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(AdminLogEntry {
                    at: row.try_get("at")?,
                    action: dec_json(&key, &row.try_get::<Vec<u8>, _>("entry")?)?,
                })
            })
            .collect()
    }

    /// Delete the entries of the log written before `before` (Unix seconds).
    /// Returns how many were deleted. The server calls it with its retention
    /// period: the log is not kept for ever.
    pub async fn purge_admin_log(&self, before: i64) -> Result<u64> {
        let done = sqlx::query("DELETE FROM admin_log WHERE at < ?")
            .bind(before)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }

    /// The generated usernames of `accounts`, for those that still exist: to
    /// show the log to an administrator. An account that was deleted has no
    /// entry, and its log entries name nobody.
    pub async fn usernames(&self, accounts: &[Uuid]) -> Result<Vec<(Uuid, String)>> {
        let mut names = Vec::new();
        for id in accounts {
            let raw: Option<Vec<u8>> =
                sqlx::query_scalar("SELECT username FROM users WHERE id = ?")
                    .bind(id.to_string())
                    .fetch_optional(&self.pool)
                    .await?;
            if let Some(raw) = raw {
                let key = user_key(&self.master, id)?;
                names.push((*id, String::from_utf8(dec(&key, &raw)?)?));
            }
        }
        Ok(names)
    }
}

async fn administrators(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE admin = 1 AND suspended_at IS NULL")
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// Fails the transaction when the change it holds leaves no administrator
/// who can sign in, on a server that had one.
async fn keep_an_administrator(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<()> {
    if administrators(tx).await? == 0 {
        return Err(Error::LastAdministrator);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use brigid_crypto::MasterKey;

    use super::*;
    use crate::model::{Credential, User};

    fn master() -> MasterKey {
        MasterKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    async fn store() -> EncryptedStore {
        EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap()
    }

    fn account(name: &str) -> (User, Credential) {
        let user = User {
            id: Uuid::new_v4(),
            username: name.to_owned(),
            server: "example.com".to_owned(),
            created_at: OffsetDateTime::now_utc(),
        };
        let credential = Credential {
            id: Uuid::new_v4(),
            user_id: user.id,
            data: b"passkey".to_vec(),
        };
        (user, credential)
    }

    async fn register(store: &EncryptedStore, name: &str, link: Option<&str>) -> Result<Uuid> {
        let (user, credential) = account(name);
        store
            .register_user_with_credential(&user, &credential, link)
            .await?;
        Ok(user.id)
    }

    const HOUR: Duration = Duration::from_secs(3600);

    #[tokio::test]
    async fn sign_up_is_by_invitation_until_someone_says_otherwise() {
        let store = store().await;
        assert_eq!(
            store.signup_policy().await.unwrap(),
            SignupPolicy::Invitation
        );
        for policy in [
            SignupPolicy::Open,
            SignupPolicy::Closed,
            SignupPolicy::Invitation,
        ] {
            store.set_signup_policy(policy).await.unwrap();
            assert_eq!(store.signup_policy().await.unwrap(), policy);
        }
    }

    #[tokio::test]
    async fn a_setup_link_makes_the_first_administrator_once() {
        let store = store().await;
        assert_eq!(store.count_accounts().await.unwrap(), 0);
        assert_eq!(store.count_administrators().await.unwrap(), 0);
        let (link, token) = store
            .create_link(LinkKind::Setup, 1, HOUR, None)
            .await
            .unwrap();
        assert_eq!(link.uses_left, 1);
        assert_eq!(token.len(), 22, "128 bits in base64url");
        assert_eq!(
            store.link_kind(&token).await.unwrap(),
            Some(LinkKind::Setup)
        );
        // Only the hash is stored.
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM links")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_ne!(stored, *token);

        let admin = register(&store, "first", Some(&token)).await.unwrap();
        let standing = store.account_standing(admin).await.unwrap().unwrap();
        assert!(standing.admin && !standing.suspended);
        assert_eq!(store.count_administrators().await.unwrap(), 1);

        // Used: it opens nothing more, and creates no second account.
        assert_eq!(store.link_kind(&token).await.unwrap(), None);
        assert!(matches!(
            register(&store, "second", Some(&token)).await,
            Err(Error::LinkSpent)
        ));
        assert_eq!(store.count_accounts().await.unwrap(), 1);
        // A link that does not exist creates nothing either.
        assert!(matches!(
            register(&store, "third", Some("no-such-link")).await,
            Err(Error::LinkSpent)
        ));
        assert_eq!(store.count_accounts().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn an_invitation_creates_as_many_ordinary_accounts_as_it_says() {
        let store = store().await;
        let (link, token) = store
            .create_link(LinkKind::Invitation, 2, HOUR, None)
            .await
            .unwrap();
        for name in ["one", "two"] {
            let id = register(&store, name, Some(&token)).await.unwrap();
            let standing = store.account_standing(id).await.unwrap().unwrap();
            assert!(!standing.admin, "an invitation grants no role");
        }
        assert!(matches!(
            register(&store, "three", Some(&token)).await,
            Err(Error::LinkSpent)
        ));
        assert_eq!(store.count_accounts().await.unwrap(), 2);

        // Listed while usable, with what is left; revoked, it is gone.
        let (kept, kept_token) = store
            .create_link(LinkKind::Invitation, 5, HOUR, None)
            .await
            .unwrap();
        register(&store, "four", Some(&kept_token)).await.unwrap();
        let listed = store.list_links(LinkKind::Invitation).await.unwrap();
        assert_eq!(listed.len(), 1, "the used-up one is gone: {listed:?}");
        assert_eq!(listed[0].id, kept.id);
        assert_eq!(listed[0].uses_left, 4);
        assert!(!store.revoke_link(LinkKind::Setup, kept.id).await.unwrap());
        assert!(
            store
                .revoke_link(LinkKind::Invitation, kept.id)
                .await
                .unwrap()
        );
        assert_eq!(store.link_kind(&kept_token).await.unwrap(), None);
        let _ = link;

        // Expired, a link is worth nothing.
        let (_, late) = store
            .create_link(LinkKind::Invitation, 1, Duration::ZERO, None)
            .await
            .unwrap();
        assert_eq!(store.link_kind(&late).await.unwrap(), None);
        assert!(matches!(
            register(&store, "five", Some(&late)).await,
            Err(Error::LinkSpent)
        ));
    }

    #[tokio::test]
    async fn an_administrator_link_grants_the_role_to_an_existing_account() {
        let store = store().await;
        let person = register(&store, "person", None).await.unwrap();
        let (_, token) = store
            .create_link(LinkKind::Admin, 1, HOUR, None)
            .await
            .unwrap();
        // It creates no account.
        assert!(matches!(
            register(&store, "new", Some(&token)).await,
            Err(Error::LinkSpent)
        ));
        assert_eq!(
            store.link_kind(&token).await.unwrap(),
            Some(LinkKind::Admin),
            "refused, it was not spent"
        );
        // Not for an account that does not exist.
        assert!(matches!(
            store.claim_administrator(&token, Uuid::new_v4()).await,
            Err(Error::NotFound)
        ));
        store.claim_administrator(&token, person).await.unwrap();
        assert!(store.account_standing(person).await.unwrap().unwrap().admin);
        // Once.
        let other = register(&store, "other", None).await.unwrap();
        assert!(matches!(
            store.claim_administrator(&token, other).await,
            Err(Error::LinkSpent)
        ));
        // An invitation grants no role.
        let (_, invitation) = store
            .create_link(LinkKind::Invitation, 1, HOUR, None)
            .await
            .unwrap();
        assert!(matches!(
            store.claim_administrator(&invitation, other).await,
            Err(Error::LinkSpent)
        ));
        assert!(!store.account_standing(other).await.unwrap().unwrap().admin);
    }

    #[tokio::test]
    async fn the_last_administrator_keeps_the_role_and_the_account() {
        let store = store().await;
        let first = register(&store, "first", None).await.unwrap();
        let second = register(&store, "second", None).await.unwrap();
        store.set_administrator(first, true).await.unwrap();

        // Alone, the role cannot be withdrawn, nor the account suspended or
        // removed by an administrator's decision.
        assert!(matches!(
            store.set_administrator(first, false).await,
            Err(Error::LastAdministrator)
        ));
        assert!(matches!(
            store.suspend_account(first).await,
            Err(Error::LastAdministrator)
        ));
        assert!(matches!(
            store.remove_account(first).await,
            Err(Error::LastAdministrator)
        ));
        let standing = store.account_standing(first).await.unwrap().unwrap();
        assert!(standing.admin && !standing.suspended);

        // With another administrator, each of them can.
        store.set_administrator(second, true).await.unwrap();
        store.set_administrator(first, false).await.unwrap();
        assert!(!store.account_standing(first).await.unwrap().unwrap().admin);
        // A suspended administrator does not count as one.
        store.set_administrator(first, true).await.unwrap();
        store.suspend_account(first).await.unwrap();
        assert_eq!(store.count_administrators().await.unwrap(), 1);
        assert!(matches!(
            store.set_administrator(second, false).await,
            Err(Error::LastAdministrator)
        ));
        assert!(store.remove_account(first).await.unwrap());
        assert!(!store.remove_account(first).await.unwrap());
        assert!(matches!(
            store.set_administrator(Uuid::new_v4(), true).await,
            Err(Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn a_suspended_account_loses_its_sessions_and_nothing_else() {
        let store = store().await;
        let admin = register(&store, "admin", None).await.unwrap();
        store.set_administrator(admin, true).await.unwrap();
        let person = register(&store, "person", None).await.unwrap();
        let session = store.create_session(person, HOUR, HOUR).await.unwrap();
        assert!(store.use_session(&session, HOUR).await.unwrap().is_some());

        store.suspend_account(person).await.unwrap();
        assert!(
            store
                .account_standing(person)
                .await
                .unwrap()
                .unwrap()
                .suspended
        );
        assert!(store.use_session(&session, HOUR).await.unwrap().is_none());
        // The account and its passkey are still there.
        assert!(store.fetch_user(person).await.unwrap().is_some());
        assert_eq!(store.fetch_credentials(person).await.unwrap().len(), 1);
        // Suspending again keeps the date; lifting it clears it.
        let since: i64 = sqlx::query_scalar("SELECT suspended_at FROM users WHERE id = ?")
            .bind(person.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        store.suspend_account(person).await.unwrap();
        let again: i64 = sqlx::query_scalar("SELECT suspended_at FROM users WHERE id = ?")
            .bind(person.to_string())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(since, again);
        store.unsuspend_account(person).await.unwrap();
        assert!(
            !store
                .account_standing(person)
                .await
                .unwrap()
                .unwrap()
                .suspended
        );
        assert!(matches!(
            store.suspend_account(Uuid::new_v4()).await,
            Err(Error::NotFound)
        ));
    }

    #[tokio::test]
    async fn an_administrator_sees_accounts_and_a_session_remembers_its_last_ceremony() {
        let store = store().await;
        let person = register(&store, "swift-otter-4821", None).await.unwrap();
        let listed = store.list_accounts().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, person);
        assert_eq!(listed[0].username, "swift-otter-4821");
        assert_eq!(listed[0].passkeys, 1);
        assert!(!listed[0].admin && !listed[0].recovery_code);
        assert_eq!(listed[0].last_sign_in_at, None);
        assert_eq!(listed[0].suspended_at, None);

        store
            .set_recovery_code(person, &[1u8; 8], &[2u8; 32])
            .await
            .unwrap();
        let token = store.create_session(person, HOUR, HOUR).await.unwrap();
        let listed = store.list_accounts().await.unwrap();
        assert!(listed[0].recovery_code);
        assert!(listed[0].last_sign_in_at.is_some());

        // The session knows when a passkey was last used in it.
        sqlx::query("UPDATE sessions SET created_at = 1000, confirmed_at = 1000")
            .execute(&store.pool)
            .await
            .unwrap();
        let info = store.use_session(&token, HOUR).await.unwrap().unwrap();
        assert_eq!(info.confirmed_at, 1000);
        assert!(store.confirm_session(&token).await.unwrap());
        let info = store.use_session(&token, HOUR).await.unwrap().unwrap();
        assert!(info.confirmed_at > 1000);
        assert_eq!(info.created_at, 1000, "the session is not made younger");
        assert!(!store.confirm_session("no-such-session").await.unwrap());
    }

    #[tokio::test]
    async fn the_log_names_no_one_is_unreadable_in_a_dump_and_does_not_last() {
        let mut store = store().await;
        let admin = register(&store, "quiet-heron-0042", None).await.unwrap();
        let person = register(&store, "brave-lynx-7310", None).await.unwrap();
        let suspend = AdminAction {
            action: "account.suspend".into(),
            actor: Some(admin),
            account: Some(person),
            detail: None,
        };
        let policy = AdminAction {
            action: "signup.policy".into(),
            actor: None,
            account: None,
            detail: Some("open".into()),
        };
        store.log_admin_action(&suspend).await.unwrap();
        store.log_admin_action(&policy).await.unwrap();

        // The newest first, as written.
        let log = store.admin_log(10).await.unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].action, policy);
        assert_eq!(log[1].action, suspend);
        assert_eq!(store.admin_log(1).await.unwrap().len(), 1);

        // Nothing of it can be read in a copy of the database, and no name
        // is in it at all: accounts are identifiers.
        let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT entry FROM admin_log")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        let raw: Vec<u8> = rows.concat();
        for readable in [
            "account.suspend",
            "quiet-heron",
            "brave-lynx",
            &admin.to_string(),
            &person.to_string(),
        ] {
            assert!(
                !raw.windows(readable.len())
                    .any(|w| w == readable.as_bytes()),
                "{readable} readable in the dump"
            );
        }
        let json = serde_json::to_string(&suspend).unwrap();
        assert!(!json.contains("heron") && !json.contains("lynx"));

        // Names are looked up when the log is read; a deleted account has
        // none any more, and its entries name nobody.
        let names = store.usernames(&[admin, person]).await.unwrap();
        assert_eq!(names.len(), 2);
        assert!(store.delete_account(person).await.unwrap());
        let names = store.usernames(&[admin, person]).await.unwrap();
        assert_eq!(names, vec![(admin, "quiet-heron-0042".to_owned())]);
        assert_eq!(
            store.admin_log(10).await.unwrap().len(),
            2,
            "the log is kept"
        );

        // A rotation of the master key keeps it readable.
        store
            .rotate_master_key(MasterKey::from_hex(&"cd".repeat(32)).unwrap())
            .await
            .unwrap();
        assert_eq!(store.admin_log(10).await.unwrap()[1].action, suspend);

        // It does not last: what is older than the period is deleted.
        sqlx::query("UPDATE admin_log SET at = 1000 WHERE id = (SELECT MIN(id) FROM admin_log)")
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(store.purge_admin_log(2000).await.unwrap(), 1);
        let log = store.admin_log(10).await.unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, policy);
    }
}
