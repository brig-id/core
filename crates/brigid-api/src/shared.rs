//! What every node of a server must see the same, and that lives minutes:
//! passkey ceremonies in progress, sign-in requests of applications waiting
//! for the person, authorization codes, and the assertions of clients
//! already presented (spec `forest.md` §2–§3).
//!
//! A server made of one node keeps it in its memory ([`Memory`]). A server
//! made of several gives [`AppState`](crate::state::AppState) [`Stored`],
//! which keeps it in the database all its nodes read. The routes do not know
//! which one they talk to.
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
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use brigid_store::EncryptedStore;

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

    /// A stable name, for what keeps the state outside the process.
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

impl Family {
    /// A stable name, for what keeps the state outside the process.
    pub fn name(self) -> &'static str {
        match self {
            Self::Registrations => "registrations",
            Self::Authentications => "authentications",
            Self::Authorizations => "authorizations",
            Self::Codes => "codes",
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

/// How long a node trusts what it counted in the database. Counting at
/// every `begin` would cost a query each; a node counts every few seconds
/// and adds what it keeps itself in between. Several nodes can therefore
/// pass the cap together by what they keep within that time: the cap bounds
/// a flood, it is not an exact number.
const COUNT_FOR: Duration = Duration::from_secs(5);

struct Counted {
    count: i64,
    at: Instant,
}

/// The state of a server made of several nodes: in the database they share
/// (`brigid_store::kept`, spec `forest.md` §3). The tables are created by
/// what initialises the server ([`EncryptedStore::prepare_kept`]), never by
/// a node.
pub struct Stored {
    store: Arc<EncryptedStore>,
    capacity: i64,
    assertions_capacity: i64,
    kept: Mutex<HashMap<Family, Counted>>,
    assertions: Mutex<Option<Counted>>,
}

impl Stored {
    pub fn new(store: Arc<EncryptedStore>) -> Self {
        Self::with_capacity(store, CAPACITY, ASSERTIONS_CAPACITY)
    }

    fn with_capacity(store: Arc<EncryptedStore>, capacity: usize, assertions: usize) -> Self {
        Self {
            store,
            capacity: i64::try_from(capacity).unwrap_or(i64::MAX),
            assertions_capacity: i64::try_from(assertions).unwrap_or(i64::MAX),
            kept: Mutex::new(HashMap::new()),
            assertions: Mutex::new(None),
        }
    }

    /// Removes what expired. Every node calls it every few seconds.
    pub async fn sweep(&self) -> Result<u64, SharedError> {
        Ok(self.store.sweep_kept(unix_now()).await?)
    }

    /// Whether `family` is at its cap, from a count at most [`COUNT_FOR`] old.
    async fn full(&self, family: Family, now: i64) -> Result<bool, SharedError> {
        let known = self
            .kept
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&family)
            .filter(|counted| counted.at.elapsed() < COUNT_FOR)
            .map(|counted| counted.count);
        let count = match known {
            Some(count) => count,
            None => {
                let count = self.store.count_kept(family.name(), now).await?;
                self.kept.lock().unwrap_or_else(|e| e.into_inner()).insert(
                    family,
                    Counted {
                        count,
                        at: Instant::now(),
                    },
                );
                count
            }
        };
        Ok(count >= self.capacity)
    }

    /// Whether as many assertions as allowed are remembered, likewise.
    async fn assertions_full(&self, now: i64) -> Result<bool, SharedError> {
        let known = self
            .assertions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|counted| counted.at.elapsed() < COUNT_FOR)
            .map(|counted| counted.count);
        let count = match known {
            Some(count) => count,
            None => {
                let count = self.store.count_assertions(now).await?;
                *self.assertions.lock().unwrap_or_else(|e| e.into_inner()) = Some(Counted {
                    count,
                    at: Instant::now(),
                });
                count
            }
        };
        Ok(count >= self.assertions_capacity)
    }
}

/// A value read from the database, or nothing when it cannot be decrypted
/// or was not kept under that row: kept under another master key, or
/// tampered with. Either way it is of no use, and is refused as absent.
fn readable(
    kind: Kind,
    read: brigid_store::Result<Option<Vec<u8>>>,
) -> Result<Option<Vec<u8>>, SharedError> {
    match read {
        Ok(value) => Ok(value),
        Err(e @ (brigid_store::Error::InvalidBlob | brigid_store::Error::Crypto(_))) => {
            tracing::warn!(kind = kind.name(), error = %e, "a kept value could not be read");
            Ok(None)
        }
        Err(e) => Err(Box::new(e)),
    }
}

fn unix_now() -> i64 {
    helpers4::time::unix_now().map_or(0, |secs| secs as i64)
}

impl Shared for Stored {
    fn put<'a>(&'a self, kind: Kind, id: &'a str, value: Vec<u8>) -> SharedFuture<'a, bool> {
        Box::pin(async move {
            let now = unix_now();
            let family = kind.family();
            if self.full(family, now).await? {
                return Ok(false);
            }
            let expires = now.saturating_add(i64::try_from(kind.ttl().as_secs()).unwrap_or(0));
            self.store
                .keep(kind.name(), family.name(), id, &value, expires)
                .await?;
            if let Some(counted) = self
                .kept
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&family)
            {
                counted.count += 1;
            }
            Ok(true)
        })
    }

    fn get<'a>(&'a self, kind: Kind, id: &'a str) -> SharedFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move { readable(kind, self.store.kept(kind.name(), id, unix_now()).await) })
    }

    fn take<'a>(&'a self, kind: Kind, id: &'a str) -> SharedFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            readable(
                kind,
                self.store.take_kept(kind.name(), id, unix_now()).await,
            )
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
            if self.assertions_full(now).await? {
                return Ok(false);
            }
            let first = self
                .store
                .first_use_of_assertion(client_id, jti, expires, now)
                .await?;
            if first
                && let Some(counted) = self
                    .assertions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_mut()
            {
                counted.count += 1;
            }
            Ok(first)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store on an empty database (SQLite, or PostgreSQL when
    /// `BRIGID_TEST_POSTGRES` says so), with the tables of the shared state.
    async fn store() -> Arc<EncryptedStore> {
        let master = brigid_crypto::MasterKey::from_hex(&"ab".repeat(32)).unwrap();
        let store = EncryptedStore::new(&brigid_store::testing::url().await, master)
            .await
            .unwrap();
        store.prepare_kept().await.unwrap();
        Arc::new(store)
    }

    // -- The contract, checked on whatever keeps the state ------------------

    async fn read_as_often_as_asked_and_taken_once(shared: &dyn Shared) {
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
    async fn of_many_callers_one_takes(shared: Arc<dyn Shared>, rounds: usize, callers: usize) {
        for round in 0..rounds {
            let id = format!("code-{round}");
            assert!(shared.put(Kind::Code, &id, b"v".to_vec()).await.unwrap());
            let start = Arc::new(tokio::sync::Barrier::new(callers));
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..callers {
                let (shared, start, id) = (shared.clone(), start.clone(), id.clone());
                tasks.spawn(async move {
                    start.wait().await;
                    shared.take(Kind::Code, &id).await.unwrap().is_some()
                });
            }
            let mut taken = 0;
            while let Some(got) = tasks.join_next().await {
                taken += usize::from(got.unwrap());
            }
            assert_eq!(taken, 1, "round {round}");
        }
    }

    /// A ceremony begun for one thing is not there for another, and stays
    /// for the one it was begun for.
    async fn found_under_its_own_kind_only(shared: &dyn Shared) {
        shared.put(Kind::SignIn, "s", b"v".to_vec()).await.unwrap();
        assert_eq!(shared.take(Kind::DeleteAccount, "s").await.unwrap(), None);
        assert_eq!(shared.take(Kind::Confirm, "s").await.unwrap(), None);
        assert_eq!(shared.get(Kind::Signup, "s").await.unwrap(), None);
        assert_eq!(
            shared.take(Kind::SignIn, "s").await.unwrap(),
            Some(b"v".to_vec())
        );
    }

    async fn an_assertion_is_a_first_use_once(shared: &dyn Shared) {
        assert!(shared.first_use("c", "j1", 100, 50).await.unwrap());
        assert!(!shared.first_use("c", "j1", 100, 60).await.unwrap());
        assert!(shared.first_use("other", "j1", 100, 60).await.unwrap());
        // Past its expiry it is forgotten: a replay is refused by its date.
        assert!(shared.first_use("c", "j1", 300, 200).await.unwrap());
    }

    // -- In memory ------------------------------------------------------------

    #[tokio::test]
    async fn memory_a_value_is_read_as_often_as_asked_and_taken_once() {
        read_as_often_as_asked_and_taken_once(&Memory::new()).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn memory_of_many_callers_at_once_one_takes_the_value() {
        of_many_callers_one_takes(Arc::new(Memory::new()), 50, 64).await;
    }

    #[tokio::test]
    async fn memory_a_value_is_found_under_its_own_kind_only() {
        found_under_its_own_kind_only(&Memory::new()).await;
    }

    #[tokio::test]
    async fn memory_an_assertion_is_a_first_use_once() {
        an_assertion_is_a_first_use_once(&Memory::new()).await;
    }

    #[tokio::test]
    async fn memory_an_expired_value_is_as_if_never_kept() {
        let shared = Memory::new();
        let past = Instant::now() - Duration::from_secs(1);
        assert!(shared.put_until(Kind::Code, "read", b"v".to_vec(), past));
        assert!(shared.put_until(Kind::Code, "taken", b"v".to_vec(), past));
        assert_eq!(shared.get(Kind::Code, "read").await.unwrap(), None);
        assert_eq!(shared.take(Kind::Code, "taken").await.unwrap(), None);
    }

    #[tokio::test]
    async fn memory_a_family_keeps_no_more_than_its_capacity() {
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
    async fn memory_what_expired_leaves_room() {
        let shared = Memory::new();
        let past = Instant::now() - Duration::from_secs(1);
        for n in 0..CAPACITY {
            assert!(shared.put_until(Kind::Code, &n.to_string(), Vec::new(), past));
        }
        assert!(shared.put(Kind::Code, "new", Vec::new()).await.unwrap());
    }

    // -- In the database ------------------------------------------------------

    #[tokio::test]
    async fn stored_a_value_is_read_as_often_as_asked_and_taken_once() {
        read_as_often_as_asked_and_taken_once(&Stored::new(store().await)).await;
    }

    /// Two nodes are two `Stored` on one database: of all the callers of
    /// both, one takes the value.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn stored_of_many_callers_on_two_nodes_one_takes_the_value() {
        let store = store().await;
        let nodes: [Arc<dyn Shared>; 2] = [
            Arc::new(Stored::new(store.clone())),
            Arc::new(Stored::new(store)),
        ];
        for round in 0..20 {
            let id = format!("code-{round}");
            assert!(nodes[0].put(Kind::Code, &id, b"v".to_vec()).await.unwrap());
            let start = Arc::new(tokio::sync::Barrier::new(16));
            let mut tasks = tokio::task::JoinSet::new();
            for caller in 0..16 {
                let (node, start, id) = (nodes[caller % 2].clone(), start.clone(), id.clone());
                tasks.spawn(async move {
                    start.wait().await;
                    node.take(Kind::Code, &id).await.unwrap().is_some()
                });
            }
            let mut taken = 0;
            while let Some(got) = tasks.join_next().await {
                taken += usize::from(got.unwrap());
            }
            assert_eq!(taken, 1, "round {round}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn stored_of_many_callers_at_once_one_takes_the_value() {
        of_many_callers_one_takes(Arc::new(Stored::new(store().await)), 20, 16).await;
    }

    #[tokio::test]
    async fn stored_a_value_is_found_under_its_own_kind_only() {
        found_under_its_own_kind_only(&Stored::new(store().await)).await;
    }

    #[tokio::test]
    async fn stored_an_assertion_is_a_first_use_once() {
        an_assertion_is_a_first_use_once(&Stored::new(store().await)).await;
    }

    /// What one node keeps, another reads and takes.
    #[tokio::test]
    async fn stored_what_one_node_keeps_another_takes() {
        let store = store().await;
        let (one, other) = (Stored::new(store.clone()), Stored::new(store));
        assert!(one.put(Kind::SignIn, "s", b"v".to_vec()).await.unwrap());
        assert_eq!(
            other.get(Kind::SignIn, "s").await.unwrap(),
            Some(b"v".to_vec())
        );
        assert_eq!(
            other.take(Kind::SignIn, "s").await.unwrap(),
            Some(b"v".to_vec())
        );
        assert_eq!(one.take(Kind::SignIn, "s").await.unwrap(), None);
        assert!(
            one.first_use("c", "j", unix_now() + 60, unix_now())
                .await
                .unwrap()
        );
        assert!(
            !other
                .first_use("c", "j", unix_now() + 60, unix_now())
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn stored_a_family_keeps_no_more_than_its_capacity() {
        let shared = Stored::with_capacity(store().await, 3, 2);
        for (n, kind) in [Kind::Signup, Kind::AddPasskey, Kind::Recovery]
            .into_iter()
            .enumerate()
        {
            assert!(shared.put(kind, &n.to_string(), Vec::new()).await.unwrap());
        }
        assert!(
            !shared
                .put(Kind::Signup, "one more", Vec::new())
                .await
                .unwrap()
        );
        assert_eq!(shared.get(Kind::Signup, "one more").await.unwrap(), None);
        // Another family has its own room.
        assert!(shared.put(Kind::SignIn, "other", Vec::new()).await.unwrap());
        // And so have the assertions.
        let now = unix_now();
        assert!(shared.first_use("c", "1", now + 60, now).await.unwrap());
        assert!(shared.first_use("c", "2", now + 60, now).await.unwrap());
        assert!(!shared.first_use("c", "3", now + 60, now).await.unwrap());
    }

    /// A node that starts counts what the others already keep.
    #[tokio::test]
    async fn stored_a_new_node_counts_what_is_already_kept() {
        let store = store().await;
        let first = Stored::with_capacity(store.clone(), 2, 2);
        assert!(first.put(Kind::Code, "a", Vec::new()).await.unwrap());
        assert!(first.put(Kind::Code, "b", Vec::new()).await.unwrap());
        let second = Stored::with_capacity(store, 2, 2);
        assert!(!second.put(Kind::Code, "c", Vec::new()).await.unwrap());
    }

    #[tokio::test]
    async fn stored_sweeping_removes_what_expired_only() {
        let store = store().await;
        let shared = Stored::new(store.clone());
        assert!(shared.put(Kind::Code, "live", b"v".to_vec()).await.unwrap());
        store
            .keep("code", "codes", "old", b"v", unix_now() - 1)
            .await
            .unwrap();
        assert_eq!(shared.sweep().await.unwrap(), 1);
        assert_eq!(
            shared.get(Kind::Code, "live").await.unwrap(),
            Some(b"v".to_vec())
        );
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
