//! Who the process runs as.
//!
//! The server never runs as root. A command typed as root on the machine
//! (`<server> client list`) reads the key as root, then becomes the owner of
//! the database before it opens it: no file of the database ever belongs to
//! root.

use std::{
    fs, io,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

/// The effective user of this process.
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Becomes the owner of the database's directory, for a command run as
/// root: the files of the database never belong to root, or the server,
/// which does not run as root, could not open them.
pub fn become_owner_of_database(database: &Path) -> Result<(), String> {
    let dir = match database.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_owned(),
        _ => PathBuf::from("."),
    };
    let meta = fs::metadata(&dir).map_err(|e| {
        format!(
            "{}: {e}. Start the server once: it creates its data directory, owned by the user \
             it runs as.",
            dir.display()
        )
    })?;
    let (uid, gid) = (meta.uid(), meta.gid());
    if uid == 0 {
        return Err(format!(
            "{} belongs to root, and the server does not run as root. Give it to the user the \
             server runs as.",
            dir.display()
        ));
    }
    // SAFETY: plain system calls with no pointer but the empty group list;
    // glibc and musl apply them to every thread of the process.
    let ok = unsafe {
        libc::setgroups(0, std::ptr::null()) == 0
            && libc::setgid(gid) == 0
            && libc::setuid(uid) == 0
    };
    if !ok || effective_uid() != uid {
        return Err(format!(
            "could not become the owner of {} (uid {uid}): {}",
            dir.display(),
            io::Error::last_os_error()
        ));
    }
    Ok(())
}
