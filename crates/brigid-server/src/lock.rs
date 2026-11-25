//! Who uses the database: a lock next to it, `<database>.lock`.
//!
//! The server, and every command that opens the database, hold it shared
//! for as long as they run. `restore` takes it exclusive: it refuses while
//! anything holds it, and whatever starts during a restore waits for its end.
//!
//! The lock is the operating system's (`flock`): it ends with the process
//! that holds it, however it ends. It is a separate file because SQLite
//! keeps its own locks on the database file, of another kind.

use std::{
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _},
    path::{Path, PathBuf},
};

/// The lock file of `database`.
pub fn path(database: &Path) -> PathBuf {
    brigid_store::backup::sidecar(database, ".lock")
}

fn open(database: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path(database))
}

/// `flock(operation | LOCK_NB)`: `Ok(false)` when another process holds a
/// lock that conflicts.
fn try_flock(file: &File, operation: libc::c_int) -> io::Result<bool> {
    // SAFETY: a plain system call on a descriptor this function borrows.
    if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(error)
    }
}

/// Holds the lock of `database` shared, for as long as the file returned is
/// open. While a restore holds it, says so on standard error and waits.
pub fn shared(database: &Path) -> io::Result<File> {
    let file = open(database)?;
    if !try_flock(&file, libc::LOCK_SH)? {
        eprintln!(
            "A restore of {} is in progress: waiting for it to end.",
            database.display()
        );
        // SAFETY: as in `try_flock`; this one blocks.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(file)
}

/// Holds the lock of `database` alone, or `None` at once when anything else
/// holds it: a server or a command is using the database.
pub fn exclusive(database: &Path) -> io::Result<Option<File>> {
    let file = open(database)?;
    Ok(try_flock(&file, libc::LOCK_EX)?.then_some(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exclusive_lock_is_refused_while_a_shared_one_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("brigid.db");
        let held = shared(&database).unwrap();
        assert!(exclusive(&database).unwrap().is_none());
        drop(held);
        let alone = exclusive(&database).unwrap().expect("nothing holds it");
        assert!(exclusive(&database).unwrap().is_none());
        drop(alone);
        assert!(exclusive(&database).unwrap().is_some());
    }
}
