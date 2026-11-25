//! What every node of a server must see the same, and that lives minutes:
//! passkey ceremonies in progress, sign-in requests of applications waiting
//! for the person, authorization codes, and the assertions of clients
//! already presented (spec `forest.md` §2–§3).
//!
//! A server made of one node keeps it in its memory ([`Memory`]). A server
//! made of several gives [`AppState`](crate::state::AppState) another
//! [`Shared`], which keeps it where all its nodes read it. The routes do not
//! know which one they talk to.
//!
//! The contract, whatever keeps the state:
//!
//! - a value is kept under a [`Kind`] and an identifier, until its kind's
//!   time has passed; afterwards it is as if it had never been kept;
//! - [`Shared::take`] gives a value **once**: of any number of callers that
//!   take the same identifier at the same instant, one gets it;
//! - a value kept under one kind is never found under another: a ceremony
//!   begun to sign in cannot be finished as something else;
//! - beyond [`CAPACITY`] values of one [`Family`], nothing more is kept;
//! - an assertion of a client is a first use once.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Passkey ceremonies in progress expire after 5 minutes.
pub(crate) const CEREMONY_TTL: Duration = Duration::from_secs(300);

/// A person has ten minutes to sign in and choose an identity.
pub(crate) const AUTHORIZATION_TTL: Duration = Duration::from_secs(600);

/// A relying party has one minute to exchange a code.
pub(crate) const CODE_TTL: Duration = Duration::from_secs(60);

/// Hard upper bound on the number of values kept for each [`Family`].
///
/// Expiry bounds how long a value is kept, not how many are: a sustained
/// burst of `begin` requests faster than the expiry would otherwise grow
/// without limit. This cap turns that growth into a backpressure signal
/// (HTTP 429) instead of letting a flood exhaust what keeps the state.
///
/// Sized to keep the worst case in memory below ~10 MB for the ceremonies,
/// comfortably above the per-IP rate limit (20 requests a minute) for a
/// small deployment, and small enough to detect floods.
pub const CAPACITY: usize = 10_000;

/// Assertions of clients live minutes; this many at once is a flood.
pub const ASSERTIONS_CAPACITY: usize = 100_000;

/// What a value was kept for. A `finish` endpoint takes only its own kind,
/// so a ceremony begun to add a passkey, or to recover an account, cannot
/// be completed as something else: under another kind it is not there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A registration ceremony for a new account (`/auth/register/*`).
    Signup,
    /// A registration ceremony for one more passkey (`/auth/passkeys/add/*`).
    AddPasskey,
    /// A registration ceremony allowed by a recovery code (`/auth/recovery/*`).
    Recovery,
    /// An authentication ceremony that opens a session (`/auth/login/*`).
    SignIn,
    /// An authentication ceremony that deletes the account (`/account/delete/*`).
    DeleteAccount,
    /// An authentication ceremony that confirms the person is there
    /// (`/auth/confirm/*`).
    Confirm,
    /// A sign-in request of an application, waiting for the person.
    Authorization,
    /// An authorization code, waiting to be exchanged.
    Code,
}

/// Kinds that are counted together against [`CAPACITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Registrations,
    Authentications,
    Authorizations,
    Codes,
}

impl Kind {
    /// How long a value of this kind is kept.
    pub fn ttl(self) -> Duration {
        match self {
            Self::Signup
            | Self::AddPasskey
            | Self::Recovery
            | Self::SignIn
            | Self::DeleteAccount
            | Self::Confirm => CEREMONY_TTL,
            Self::Authorization => AUTHORIZATION_TTL,
            Self::Code => CODE_TTL,
        }
    }

    /// The kinds this one is counted with.
    pub fn family(self) -> Family {
        match self {
            Self::Signup | Self::AddPasskey | Self::Recovery => Family::Registrations,
            Self::SignIn | Self::DeleteAccount | Self::Confirm => Family::Authentications,
            Self::Authorization => Family::Authorizations,
            Self::Code => Family::Codes,
        }
    }

    /// A stable name, for whatever keeps the state outside the process.
    /// A value whose shape changes gets a new kind and a new name: nodes of
    /// two versions never read each other's values wrongly.
    pub fn name(self) -> &'static str {
        match self {
            Self::Signup => "signup",
            Self::AddPasskey => "add-passkey",
            Self::Recovery => "recovery",
            Self::SignIn => "sign-in",
            Self::DeleteAccount => "delete-account",
            Self::Confirm => "confirm",
            Self::Authorization => "authorization",
            Self::Code => "code",
        }
    }
}

/// Why the state could not be read or written. Memory never fails; what
/// keeps the state outside the process can.
pub type SharedError = Box<dyn std::error::Error + Send + Sync>;

pub type SharedFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SharedError>> + Send + 'a>>;

/// What keeps the state every node must see the same. See the module's
/// documentation for the contract.
pub trait Shared: Send + Sync {
    /// Keeps `value` under `kind` and `id` for [`Kind::ttl`]. `false` when
    /// [`CAPACITY`] values of the kind's family are kept already: nothing
    /// was kept.
    fn put<'a>(&'a self, kind: Kind, id: &'a str, value: Vec<u8>) -> SharedFuture<'a, bool>;

    /// The value kept under `kind` and `id`, left in place. `None` when
    /// there is none, or it expired.
    fn get<'a>(&'a self, kind: Kind, id: &'a str) -> SharedFuture<'a, Option<Vec<u8>>>;

    /// Takes the value kept under `kind` and `id` out: given to one caller,
    /// once. `None` when there is none, it expired, or another caller took
    /// it.
    fn take<'a>(&'a self, kind: Kind, id: &'a str) -> SharedFuture<'a, Option<Vec<u8>>>;

    /// Whether the assertion `jti` of `client_id` is presented for the first
    /// time; it is remembered until `expires` (Unix seconds, as `now` is).
    /// `false` too when [`ASSERTIONS_CAPACITY`] are remembered already.
    fn first_use<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires: i64,
        now: i64,
    ) -> SharedFuture<'a, bool>;
}

struct Kept {
    value: Vec<u8>,
    until: Instant,
}

/// The values of one family, by kind and identifier.
type Values = HashMap<(Kind, String), Kept>;

/// The state of a server made of one node: in its memory, lost when it
/// stops.
#[derive(Default)]
pub struct Memory {
    kept: Mutex<HashMap<Family, Values>>,
    /// (`client_id`, `jti`) → Unix time the assertion expires.
    used_assertions: Mutex<HashMap<(String, String), i64>>,
}

impl Memory {
    pub fn new() -> Self {
        Self::default()
    }

    fn put_until(&self, kind: Kind, id: &str, value: Vec<u8>, until: Instant) -> bool {
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        let family = kept.entry(kind.family()).or_default();
        // What expired leaves room first.
        let now = Instant::now();
        family.retain(|_, v| v.until > now);
        if family.len() >= CAPACITY {
            return false;
        }
        family.insert((kind, id.to_owned()), Kept { value, until });
        true
    }
}

impl Shared for Memory {
    fn put<'a>(&'a self, kind: Kind, id: &'a str, value: Vec<u8>) -> SharedFuture<'a, bool> {
        Box::pin(async move { Ok(self.put_until(kind, id, value, Instant::now() + kind.ttl())) })
    }

    fn get<'a>(&'a self, kind: Kind, id: &'a str) -> SharedFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
            Ok(kept
                .get(&kind.family())
                .and_then(|family| family.get(&(kind, id.to_owned())))
                .filter(|v| v.until > Instant::now())
                .map(|v| v.value.clone()))
        })
    }

    fn take<'a>(&'a self, kind: Kind, id: &'a str) -> SharedFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
            Ok(kept
                .get_mut(&kind.family())
                .and_then(|family| family.remove(&(kind, id.to_owned())))
                // Taken out even when expired: it is of no use to anyone.
                .filter(|v| v.until > Instant::now())
                .map(|v| v.value))
        })
    }

    fn first_use<'a>(
        &'a self,
        client_id: &'a str,
        jti: &'a str,
        expires: i64,
        now: i64,
    ) -> SharedFuture<'a, bool> {
        Box::pin(async move {
            let mut used = self
                .used_assertions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            used.retain(|_, until| *until >= now);
            if used.len() >= ASSERTIONS_CAPACITY {
                return Ok(false);
            }
            Ok(used
                .insert((client_id.to_owned(), jti.to_owned()), expires)
                .is_none())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn a_value_is_read_as_often_as_asked_and_taken_once() {
        let shared = Memory::new();
        assert!(
            shared
                .put(Kind::Authorization, "a", b"v".to_vec())
                .await
                .unwrap()
        );
        for _ in 0..3 {
            assert_eq!(
                shared.get(Kind::Authorization, "a").await.unwrap(),
                Some(b"v".to_vec())
            );
        }
        assert_eq!(
            shared.take(Kind::Authorization, "a").await.unwrap(),
            Some(b"v".to_vec())
        );
        assert_eq!(shared.take(Kind::Authorization, "a").await.unwrap(), None);
        assert_eq!(shared.get(Kind::Authorization, "a").await.unwrap(), None);
    }

    /// The property several nodes rely on: whoever presents an identifier at
    /// the same instant, one caller gets the value.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn of_many_callers_at_once_one_takes_the_value() {
        let shared: Arc<dyn Shared> = Arc::new(Memory::new());
        for round in 0..50 {
            let id = format!("code-{round}");
            assert!(shared.put(Kind::Code, &id, b"v".to_vec()).await.unwrap());
            let start = Arc::new(tokio::sync::Barrier::new(64));
            let mut callers = tokio::task::JoinSet::new();
            for _ in 0..64 {
                let (shared, start, id) = (shared.clone(), start.clone(), id.clone());
                callers.spawn(async move {
                    start.wait().await;
                    shared.take(Kind::Code, &id).await.unwrap().is_some()
                });
            }
            let mut taken = 0;
            while let Some(got) = callers.join_next().await {
                taken += usize::from(got.unwrap());
            }
            assert_eq!(taken, 1, "round {round}");
        }
    }

    /// A ceremony begun for one thing is not there for another, and stays
    /// for the one it was begun for.
    #[tokio::test]
    async fn a_value_is_found_under_its_own_kind_only() {
        let shared = Memory::new();
        shared.put(Kind::SignIn, "s", b"v".to_vec()).await.unwrap();
        assert_eq!(shared.take(Kind::DeleteAccount, "s").await.unwrap(), None);
        assert_eq!(shared.take(Kind::Confirm, "s").await.unwrap(), None);
        assert_eq!(shared.get(Kind::Signup, "s").await.unwrap(), None);
        assert_eq!(
            shared.take(Kind::SignIn, "s").await.unwrap(),
            Some(b"v".to_vec())
        );
    }

    #[tokio::test]
    async fn an_expired_value_is_as_if_never_kept() {
        let shared = Memory::new();
        let past = Instant::now() - Duration::from_secs(1);
        assert!(shared.put_until(Kind::Code, "read", b"v".to_vec(), past));
        assert!(shared.put_until(Kind::Code, "taken", b"v".to_vec(), past));
        assert_eq!(shared.get(Kind::Code, "read").await.unwrap(), None);
        assert_eq!(shared.take(Kind::Code, "taken").await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_family_keeps_no_more_than_its_capacity() {
        let shared = Memory::new();
        for n in 0..CAPACITY {
            // Two kinds of one family count together.
            let kind = if n % 2 == 0 {
                Kind::Signup
            } else {
                Kind::AddPasskey
            };
            assert!(shared.put(kind, &n.to_string(), Vec::new()).await.unwrap());
        }
        assert!(
            !shared
                .put(Kind::Recovery, "one more", Vec::new())
                .await
                .unwrap()
        );
        assert_eq!(shared.get(Kind::Recovery, "one more").await.unwrap(), None);
        // Another family has its own room.
        assert!(shared.put(Kind::SignIn, "other", Vec::new()).await.unwrap());
        // A value taken leaves room.
        assert!(shared.take(Kind::Signup, "0").await.unwrap().is_some());
        assert!(
            shared
                .put(Kind::Recovery, "one more", Vec::new())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn what_expired_leaves_room() {
        let shared = Memory::new();
        let past = Instant::now() - Duration::from_secs(1);
        for n in 0..CAPACITY {
            assert!(shared.put_until(Kind::Code, &n.to_string(), Vec::new(), past));
        }
        assert!(shared.put(Kind::Code, "new", Vec::new()).await.unwrap());
    }

    #[tokio::test]
    async fn an_assertion_is_a_first_use_once() {
        let shared = Memory::new();
        assert!(shared.first_use("c", "j1", 100, 50).await.unwrap());
        assert!(!shared.first_use("c", "j1", 100, 60).await.unwrap());
        assert!(shared.first_use("other", "j1", 100, 60).await.unwrap());
        // Past its expiry it is forgotten: a replay is refused by its date.
        assert!(shared.first_use("c", "j1", 300, 200).await.unwrap());
    }

    #[test]
    fn every_kind_has_its_own_name() {
        let kinds = [
            Kind::Signup,
            Kind::AddPasskey,
            Kind::Recovery,
            Kind::SignIn,
            Kind::DeleteAccount,
            Kind::Confirm,
            Kind::Authorization,
            Kind::Code,
        ];
        let names: std::collections::HashSet<_> = kinds.iter().map(|k| k.name()).collect();
        assert_eq!(names.len(), kinds.len());
    }
}
