use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// In-memory JTI store for replay protection.
///
/// Evicts expired entries before each check to keep the store bounded.
/// The store must persist for at least the maximum token lifetime.
///
/// # Limitation
///
/// This store is process-local. Blacklisted JTIs are lost on service restart,
/// so tokens revoked before `exp` may be accepted again after a restart.
/// A future phase should persist the JTI blacklist in the SQLite `jti_blacklist`
/// table with TTL = token `exp` to survive restarts.
// TODO(phase-5): migrate JTI blacklist to SQLite for persistence across restarts.
pub struct JtiStore {
    entries: HashMap<String, i64>, // jti → exp (unix secs)
}

impl Default for JtiStore {
    fn default() -> Self {
        Self::new()
    }
}

impl JtiStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Explicitly blacklists `jti` without a replay check.
    ///
    /// Use this for logout: the token is invalidated and subsequent calls to
    /// [`is_blacklisted`](Self::is_blacklisted) will return `true` until it expires.
    pub fn blacklist(&mut self, jti: &str, exp: i64) {
        // Evict expired entries to keep the store bounded even under sustained logout load.
        let now = now_unix();
        self.entries.retain(|_, exp_ts| *exp_ts > now);
        self.entries.insert(jti.to_string(), exp);
    }

    /// Returns `true` if `jti` is currently blacklisted and not yet expired.
    pub fn is_blacklisted(&self, jti: &str) -> bool {
        match self.entries.get(jti) {
            Some(&exp) => exp > now_unix(),
            None => false,
        }
    }

    /// Checks that `jti` has not been used since `exp`.
    ///
    /// Evicts all expired entries first (keeps the store bounded).
    /// Returns `Err(JtiReplay)` if the JTI is already present and not yet expired.
    pub fn check_and_insert(&mut self, jti: &str, exp: i64) -> Result<()> {
        let now = now_unix();
        self.entries.retain(|_, exp_ts| *exp_ts > now);
        if self.entries.contains_key(jti) {
            return Err(Error::JtiReplay);
        }
        self.entries.insert(jti.to_string(), exp);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_creates_empty_store() {
        let mut store = JtiStore::default();
        assert!(store.check_and_insert("jti-def", i64::MAX).is_ok());
    }

    #[test]
    fn new_jti_is_accepted() {
        let mut store = JtiStore::new();
        assert!(store.check_and_insert("jti-1", i64::MAX).is_ok());
    }

    #[test]
    fn replayed_jti_is_rejected() {
        let mut store = JtiStore::new();
        store.check_and_insert("jti-x", i64::MAX).unwrap();
        let err = store.check_and_insert("jti-x", i64::MAX).unwrap_err();
        assert!(matches!(err, Error::JtiReplay));
    }

    #[test]
    fn expired_jti_is_evicted_and_reusable() {
        let mut store = JtiStore::new();
        // Insert with exp = 1 (already expired)
        store.check_and_insert("jti-old", 1).unwrap();
        // Same jti should now succeed because the old entry is evicted
        assert!(store.check_and_insert("jti-old", i64::MAX).is_ok());
    }
}
