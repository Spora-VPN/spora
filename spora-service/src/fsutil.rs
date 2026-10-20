//! File helpers shared by the log, crash, bundle, state and upload code.

use std::fs::{File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// A directory, made owner-only (Unix) if this creates it; one that exists
/// is left as it is.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// A new file, readable by its owner only on Unix.
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Make a new directory entry durable (Unix; elsewhere the file's own sync
/// is all there is).
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

pub(crate) struct FileInfo {
    pub(crate) path: PathBuf,
    pub(crate) name: String,
    pub(crate) modified: SystemTime,
    pub(crate) len: u64,
    /// The listed file's identity (device, inode), which [`open_listed`]
    /// holds the opened file to.
    #[cfg(unix)]
    pub(crate) id: (u64, u64),
}

/// Open a file a listing found, for reading — that same file or nothing.
/// The listing kept regular files only, but the path is only a name: by now
/// it may be a symlink (to a file the reader may read and the directory's
/// owner may not: root bundling a user's directory), a FIFO (whose open
/// would block) or another file. On Unix the open follows no symlink and
/// does not wait, and the file opened must be the regular file listed (same
/// device and inode); anything else is an error and nothing is read.
pub(crate) fn open_listed(f: &FileInfo) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&f.path)?;
        let m = file.metadata()?;
        if !m.is_file() || (m.dev(), m.ino()) != f.id {
            return Err(io::Error::other("not the file listed there"));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let file = File::open(&f.path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("not the file listed there"));
        }
        Ok(file)
    }
}

/// Open (creating it if need be, 0600 on Unix) a file that exists only to be
/// locked.
pub(crate) fn open_lock_file(path: &Path) -> io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Open another process's lock file to try its lock, creating nothing.
/// Read and write, though nothing is written: on NFS, Linux emulates
/// `flock(2)` with whole-file `fcntl` locks, and an exclusive one needs a
/// descriptor open for writing — through a read-only one the attempt fails
/// with `EBADF` whether or not anyone holds the lock, which would make every
/// live writer look dead and every dead one's lock look held.
pub(crate) fn open_lock_probe(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
}

/// [`File::try_lock`] (exclusive, non-blocking; released when the file is
/// closed), on Android too: std answers `Unsupported` there, though bionic
/// has `flock(2)` — the call std makes on Linux. Where locks really are
/// unsupported the error's kind is [`io::ErrorKind::Unsupported`].
pub(crate) fn try_lock(f: &File) -> Result<(), TryLockError> {
    #[cfg(target_os = "android")]
    {
        flock(f)
    }
    #[cfg(not(target_os = "android"))]
    {
        f.try_lock()
    }
}

/// `flock(fd, LOCK_EX | LOCK_NB)`, answered as std answers it. Built for the
/// Linux tests too, which hold it to std's own.
#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
fn flock(f: &File) -> Result<(), TryLockError> {
    use std::os::fd::AsRawFd;
    // SAFETY: flock(2) on a descriptor `f` keeps open for the whole call.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.kind() == io::ErrorKind::WouldBlock {
        Err(TryLockError::WouldBlock)
    } else {
        Err(TryLockError::Error(e))
    }
}

/// Regular files in `dir` whose names pass `keep`, oldest first (by
/// modification time, then name). A missing directory has no files, and
/// neither has one that cannot be read; an entry that cannot be read is left
/// out.
pub(crate) fn list_matching(dir: &Path, keep: impl Fn(&str) -> bool) -> Vec<FileInfo> {
    list(dir, keep, false).unwrap_or_default()
}

/// [`list_matching`] for a caller that must tell "no files" from "could not
/// look": a directory or an entry that cannot be read is an error (a missing
/// directory, or a file that vanished while listing, is not).
pub(crate) fn try_list_matching(
    dir: &Path,
    keep: impl Fn(&str) -> bool,
) -> io::Result<Vec<FileInfo>> {
    list(dir, keep, true)
}

fn list(dir: &Path, keep: impl Fn(&str) -> bool, strict: bool) -> io::Result<Vec<FileInfo>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut files = Vec::new();
    for e in entries {
        let e = match e {
            Ok(e) => e,
            Err(e) if strict => return Err(e),
            Err(_) => continue,
        };
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        if !keep(&name) {
            continue;
        }
        let m = match e.metadata() {
            Ok(m) => m,
            Err(e) if strict && e.kind() != io::ErrorKind::NotFound => return Err(e),
            Err(_) => continue,
        };
        if !m.is_file() {
            continue;
        }
        files.push(FileInfo {
            path: e.path(),
            name,
            modified: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            len: m.len(),
            #[cfg(unix)]
            id: {
                use std::os::unix::fs::MetadataExt;
                (m.dev(), m.ino())
            },
        });
    }
    files.sort_by(|a, b| a.modified.cmp(&b.modified).then(a.name.cmp(&b.name)));
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Held through one open file, the lock is refused through another
    /// until the first is closed: on every platform, Android included.
    #[test]
    fn a_lock_excludes_until_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.lock");
        let a = open_lock_file(&path).unwrap();
        try_lock(&a).unwrap();
        let b = open_lock_probe(&path).unwrap();
        assert!(matches!(try_lock(&b), Err(TryLockError::WouldBlock)));
        drop(a);
        try_lock(&b).unwrap();
    }

    /// A probe creates nothing, and opens for writing too (NFS's flock
    /// emulation refuses an exclusive lock through a read-only descriptor).
    #[test]
    fn a_lock_probe_creates_nothing_and_can_write() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.lock");
        assert_eq!(
            open_lock_probe(&path).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(!path.exists());
        let held = open_lock_file(&path).unwrap();
        try_lock(&held).unwrap();
        let probe = open_lock_probe(&path).unwrap();
        assert!(matches!(try_lock(&probe), Err(TryLockError::WouldBlock)));
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: F_GETFL on a descriptor `probe` keeps open.
            let flags = unsafe { libc::fcntl(probe.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(flags & libc::O_ACCMODE, libc::O_RDWR);
        }
    }

    fn listed(dir: &Path, name: &str) -> FileInfo {
        list_matching(dir, |n| n == name).pop().expect("listed")
    }

    #[test]
    fn a_listed_file_opens_as_listed() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a"), b"one\n").unwrap();
        let f = listed(tmp.path(), "a");
        let mut buf = String::new();
        io::Read::read_to_string(&mut open_listed(&f).unwrap(), &mut buf).unwrap();
        assert_eq!(buf, "one\n");
    }

    /// Whatever has taken a listed file's name since is not opened: a
    /// symlink (to a file only the reader may read), another file, a FIFO
    /// (without blocking on it).
    #[cfg(unix)]
    #[test]
    fn a_listed_file_replaced_since_is_not_opened() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let secret = dir.join("secret");
        std::fs::write(&secret, b"secret\n").unwrap();
        let path = dir.join("a");

        std::fs::write(&path, b"one\n").unwrap();
        let f = listed(dir, "a");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&secret, &path).unwrap();
        assert!(open_listed(&f).is_err());

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"one\n").unwrap();
        let f = listed(dir, "a");
        let keep = dir.join("kept"); // so the inode is not reused at once
        std::fs::rename(&path, &keep).unwrap();
        std::fs::write(&path, b"other\n").unwrap();
        assert!(open_listed(&f).is_err());

        std::fs::remove_file(&path).unwrap();
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
            return; // no FIFOs here (Android's shell domain); nothing to test
        }
        let started = std::time::Instant::now();
        assert!(open_listed(&f).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    /// Android's lock is std's Linux one: the same call, the same answers,
    /// and each sees the other's lock.
    #[cfg(target_os = "linux")]
    #[test]
    fn flock_is_std_try_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x.lock");
        let a = open_lock_file(&path).unwrap();
        let b = File::open(&path).unwrap();
        flock(&a).unwrap();
        assert!(matches!(flock(&b), Err(TryLockError::WouldBlock)));
        assert!(matches!(b.try_lock(), Err(TryLockError::WouldBlock)));
        // Closing releases it.
        drop(a);
        b.try_lock().unwrap();
        let c = File::open(&path).unwrap();
        assert!(matches!(flock(&c), Err(TryLockError::WouldBlock)));
        drop(b);
        flock(&c).unwrap();
    }
}
