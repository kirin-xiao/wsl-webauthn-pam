//! Safe, symlink-hardened filesystem helpers for the installer (plan D6, §10).
//!
//! The installer never walks through a symlink and never writes in place: every
//! file is written to a temporary file **in the same directory** and then
//! `rename(2)`d over the destination, so a crash leaves either the old or the new
//! file, never a truncated one.
//!
//! Everything here is implemented with safe `std` APIs except a tiny, audited `raw`
//! submodule (the crate is `#![deny(unsafe_code)]`): [`std`] has no `openat`/`renameat`,
//! which are required to bind the destination's parent directory by descriptor and close
//! the parent-swap TOCTOU window in [`atomic_write`] (L12-11).
//!
//! * [`lstat_opt`] uses [`std::fs::symlink_metadata`] — the safe `lstat(2)`.
//! * `O_NOFOLLOW`/`O_CLOEXEC` are applied through
//!   [`std::os::unix::fs::OpenOptionsExt::custom_flags`], which is safe.
//! * Modes are pinned with [`std::fs::File::set_permissions`] (an `fchmod` on the
//!   open descriptor), defeating both `umask` and a symlinked path.
//!
//! Deliberately **no shell**: this module only performs direct syscalls.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

/// Raw `*at(2)` syscalls bound to a held parent directory descriptor.
///
/// This is the **only** `unsafe` in the module: `std` exposes no `openat`/`renameat`, which
/// [`atomic_write`] needs to create the temp file and rename it relative to a
/// dev/ino-verified parent directory (L12-11). The wrappers are small and each documents
/// the ownership invariant it discharges, mirroring `wsl-webauthn-store`'s `sys` module so
/// callers never write `unsafe`.
mod raw {
    #![allow(unsafe_code)]

    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io;
    use std::os::fd::{FromRawFd as _, RawFd};
    use std::os::unix::ffi::OsStrExt as _;

    /// Convert a single path component to a NUL-terminated C string.
    fn cstr(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL byte"))
    }

    /// `openat(dirfd, name, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, mode)`.
    ///
    /// `name` must be a single component (no `/`); the temp file is created exactly beside
    /// the destination, relative to the already-verified parent descriptor.
    pub(super) fn create_at(dirfd: RawFd, name: &OsStr, mode: u32) -> io::Result<File> {
        let c = cstr(name)?;
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `dirfd` is an owned directory descriptor; `c` is a valid NUL-terminated
        // single component; `mode` is applied through umask and pinned afterwards by
        // `fchmod`. `openat` returns an owned descriptor or -1.
        let fd = unsafe { libc::openat(dirfd, c.as_ptr(), flags, mode as libc::mode_t) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor this call owns exclusively; nothing else
        // observes it, so handing ownership to `File` cannot double-close.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// `renameat(olddirfd, old, newdirfd, new)`.
    pub(super) fn rename_at(
        olddirfd: RawFd,
        old: &OsStr,
        newdirfd: RawFd,
        new: &OsStr,
    ) -> io::Result<()> {
        let old_c = cstr(old)?;
        let new_c = cstr(new)?;
        // SAFETY: both are valid NUL-terminated single components; the directory
        // descriptors are owned and held for the duration of the call.
        let rc = unsafe { libc::renameat(olddirfd, old_c.as_ptr(), newdirfd, new_c.as_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `unlinkat(dirfd, name, 0)`: remove a single component relative to a held directory.
    pub(super) fn unlink_at(dirfd: RawFd, name: &OsStr) -> io::Result<()> {
        let c = cstr(name)?;
        // SAFETY: as in `rename_at`; `unlinkat` never follows a final symlink.
        let rc = unsafe { libc::unlinkat(dirfd, c.as_ptr(), 0) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Monotonic suffix for temporary files, so concurrent installers never collide.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Marker embedded in temporary file names and backup file names.
pub(crate) const TEMP_MARKER: &str = ".wsl-webauthn-tmp";
/// Marker embedded in backup file names (also used to skip backups when scanning).
pub(crate) const BACKUP_MARKER: &str = ".wsl-webauthn-bak";

/// `lstat(2)`: metadata for `path` **without** following a final symlink.
pub(crate) fn lstat(path: &Path) -> io::Result<Metadata> {
    std::fs::symlink_metadata(path)
}

/// Like [`lstat`] but maps `NotFound` to `None`.
pub(crate) fn lstat_opt(path: &Path) -> io::Result<Option<Metadata>> {
    match lstat(path) {
        Ok(md) => Ok(Some(md)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Permission bits (low 12 bits) of a metadata record.
pub(crate) fn mode_of(md: &Metadata) -> u32 {
    md.permissions().mode() & 0o7777
}

fn symlink_error(path: &Path, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("refusing to follow symlink at {what}: {}", path.display()),
    )
}

/// Refuse if `path` exists and is a symbolic link.
pub(crate) fn refuse_symlink(path: &Path, what: &str) -> io::Result<()> {
    if let Some(md) = lstat_opt(path)?
        && md.file_type().is_symlink()
    {
        return Err(symlink_error(path, what));
    }
    Ok(())
}

/// Read a regular file, refusing symlinks and verifying that the path did not change
/// between the `lstat` and the `open` (a cheap TOCTOU check).
pub(crate) fn read_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let before = lstat(path)?;
    if before.file_type().is_symlink() {
        return Err(symlink_error(path, "source"));
    }
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a regular file: {}", path.display()),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)?;
    let after = file.metadata()?;
    if after.dev() != before.dev() || after.ino() != before.ino() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path changed during open: {}", path.display()),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// A unique temporary path in `dir` (same filesystem as any sibling destination).
fn temp_path(dir: &Path) -> PathBuf {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("{TEMP_MARKER}.{}.{n}", std::process::id()))
}

/// Open `parent` as a directory bound to a descriptor, re-verifying its identity.
///
/// `before` is the metadata from the caller's `lstat`. An explicit `O_NOFOLLOW` flag makes
/// the kernel refuse a symlinked parent (`ELOOP`) rather than silently follow it, and the
/// opened descriptor is `fstat`ed and compared `(dev, ino)` with `before`, so a directory
/// swapped in between the caller's `lstat` and this open is rejected (L12-11). The returned
/// `File` owns the descriptor and must stay alive while the temp file is created and
/// renamed relative to it.
fn open_checked_dir(parent: &Path, before: &Metadata) -> io::Result<File> {
    if before.file_type().is_symlink() {
        return Err(symlink_error(parent, "destination directory"));
    }
    if !before.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "destination parent is not a directory: {}",
                parent.display()
            ),
        ));
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(parent)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("opening destination directory {}: {e}", parent.display()),
            )
        })?;
    let after = dir.metadata()?;
    if after.dev() != before.dev() || after.ino() != before.ino() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path changed during open: {}", parent.display()),
        ));
    }
    Ok(dir)
}

/// Atomically replace `path` with `bytes`, pinned to `mode`.
///
/// Refuses a symlinked destination or a symlinked parent, and binds the parent directory by
/// descriptor (see [`open_checked_dir`]): the temp file is created and renamed via
/// `openat`/`renameat` relative to the held, `(dev, ino)`-verified parent descriptor, so a
/// parent directory swapped between the `lstat` and the rename is rejected instead of being
/// written into (L12-11, mirroring the store's `open_checked_dir`).
///
/// The temp file is `fchmod`ed exactly, `fsync`ed, then `renameat`ed into place, and the
/// directory is `fsync`ed on success; it is removed on every error path.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no parent directory: {}", path.display()),
        )
    })?;
    let dest_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no file name: {}", path.display()),
        )
    })?;
    let pmd = lstat(parent)?;
    if let Some(md) = lstat_opt(path)? {
        if md.file_type().is_symlink() {
            return Err(symlink_error(path, "destination"));
        }
        if !md.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("destination is not a regular file: {}", path.display()),
            ));
        }
    }

    // Bind the parent by descriptor so the checks above cannot be invalidated by a
    // directory swapped in before the create/rename below.
    let dir = open_checked_dir(parent, &pmd)?;
    let dir_fd = dir.as_raw_fd();

    let temp = temp_path(parent);
    let temp_name: OsString = temp
        .file_name()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("temporary path has no file name: {}", temp.display()),
            )
        })?
        .to_os_string();
    let result = (|| -> io::Result<()> {
        let mut file = raw::create_at(dir_fd, &temp_name, mode)?;
        file.write_all(bytes)?;
        // `mode` at creation is filtered through umask; pin it exactly.
        file.set_permissions(Permissions::from_mode(mode))?;
        file.sync_all()?;
        drop(file);
        raw::rename_at(dir_fd, &temp_name, dir_fd, dest_name)?;
        // Persist the directory entry (best effort: some filesystems reject fsync on a
        // directory, which is not fatal for correctness of the rename itself).
        let _ = dir.sync_all();
        Ok(())
    })();
    if result.is_err() {
        // Best effort, relative to the held descriptor so it cannot be redirected.
        let _ = raw::unlink_at(dir_fd, &temp_name);
    }
    result
}

/// Atomically copy a regular file (refusing a symlinked source or destination).
pub(crate) fn copy_file_atomic(src: &Path, dst: &Path, mode: u32) -> io::Result<()> {
    let bytes = read_nofollow(src)?;
    atomic_write(dst, &bytes, mode)
}

/// `mkdir -p`, refusing to traverse a symlinked component.
///
/// Unlike [`std::fs::create_dir_all`], every existing component is `lstat`ed and a
/// symlink anywhere in the path is an error (D6: no symlink traversal). Missing
/// components are created with the process umask; callers pin the final directory's mode
/// with [`set_mode`].
pub(crate) fn create_dir_all(path: &Path) -> io::Result<()> {
    let mut cur = PathBuf::new();
    for component in path.components() {
        cur.push(component);
        match lstat_opt(&cur)? {
            Some(md) => {
                if md.file_type().is_symlink() {
                    return Err(symlink_error(&cur, "directory component"));
                }
                if !md.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("path is not a directory: {}", cur.display()),
                    ));
                }
            }
            None => std::fs::create_dir(&cur)?,
        }
    }
    Ok(())
}

/// `chmod(2)` a path (follows the path; callers pass non-symlinked paths only).
pub(crate) fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    std::fs::set_permissions(path, Permissions::from_mode(mode))
}

/// Remove a file (or symlink), ignoring a missing path.
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Remove a directory only if it is empty; ignore a missing or non-empty directory.
pub(crate) fn remove_dir_if_empty(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Recursively remove a directory tree **without following symlinks**.
///
/// Symlinked entries are unlinked (the link, not its target). Regular files are
/// removed; directories are emptied bottom-up. This is the uninstall path.
///
/// The walk is an explicit worklist rather than recursion: the uninstaller runs as root
/// and an attacker-supplied (or accidental) pathologically deep tree must not overflow the
/// stack. Directories are removed only after their children, by visiting each one twice
/// (pre-order to descend, post-order to `rmdir`).
pub(crate) fn remove_tree(path: &Path) -> io::Result<()> {
    let md = match lstat_opt(path)? {
        Some(md) => md,
        None => return Ok(()),
    };
    if md.file_type().is_symlink() || md.is_file() {
        return remove_file(path);
    }
    if !md.is_dir() {
        // A device/socket/fifo: leave it alone rather than risk deleting something
        // unexpected.
        return Ok(());
    }

    // `(path, visited)`: `visited == false` means "descend", `true` means "all children
    // are gone, so remove this now-empty directory".
    let mut stack: Vec<(PathBuf, bool)> = vec![(path.to_path_buf(), false)];
    while let Some((dir, visited)) = stack.pop() {
        if visited {
            remove_dir_if_empty(&dir)?;
            continue;
        }
        stack.push((dir.clone(), true));
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let child = entry.path();
            let cmd = entry.metadata()?;
            if cmd.is_dir() && !cmd.file_type().is_symlink() {
                // `DirEntry::metadata` does not follow symlinks, so this is an lstat.
                stack.push((child, false));
            } else {
                remove_file(&child)?;
            }
        }
    }
    Ok(())
}

/// Lowercase hex encoding of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A short preview (first 12 characters) of a hex digest.
pub(crate) fn short_hash(hex: &str) -> String {
    let preview: String = hex.chars().take(12).collect();
    if hex.len() > 12 {
        format!("{preview}…")
    } else {
        preview
    }
}

/// SHA-256 of a regular file as lowercase hex, read in bounded chunks.
///
/// Streaming keeps the CLI's memory use independent of the (potentially large) bridge
/// executable; the whole-file variant it replaces allocated the entire file.
pub(crate) fn sha256_hex_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn mode(path: &Path) -> u32 {
        mode_of(&lstat(path).unwrap())
    }

    #[test]
    fn atomic_write_creates_with_exact_mode() {
        let dir = TempDir::new().unwrap();
        let dst = dir.path().join("f");
        atomic_write(&dst, b"hello", 0o600).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"hello");
        assert_eq!(mode(&dst), 0o600);
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(TEMP_MARKER))
            .collect();
        assert!(leftovers.is_empty(), "temp file leaked");
    }

    #[test]
    fn atomic_write_replaces_existing() {
        let dir = TempDir::new().unwrap();
        let dst = dir.path().join("f");
        atomic_write(&dst, b"old", 0o644).unwrap();
        atomic_write(&dst, b"new", 0o600).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"new");
        assert_eq!(mode(&dst), 0o600);
    }

    #[test]
    fn atomic_write_refuses_symlink_destination() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("real");
        std::fs::write(&target, b"original").unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();

        let err = atomic_write(&link, b"attacker", 0o644).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        // The real file must be untouched and the link must still be a link.
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
        assert!(lstat(&link).unwrap().file_type().is_symlink());
    }

    /// L12-11: `atomic_write` must bind the parent directory by descriptor.
    ///
    /// `open_checked_dir` is the only place the parent `(dev, ino)` is re-verified, so a
    /// direct unit test of it against a swapped-in directory is the deterministic check of
    /// the new behaviour (a race from a single test thread cannot hit the window reliably).
    #[test]
    fn atomic_write_rejects_swapped_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        // `before` models the parent captured by `atomic_write`'s pre-open `lstat`.
        let before = lstat(&dir).unwrap();

        // Replace the directory at the same path with a different inode, as an attacker
        // would between the lstat and the open. Renaming the original away (rather than
        // `remove_dir`) keeps its inode alive, so the filesystem cannot hand the new
        // `create_dir` the same (dev, ino) and make this assertion non-deterministic.
        std::fs::rename(&dir, tmp.path().join("original")).unwrap();
        std::fs::create_dir(&dir).unwrap();
        assert_ne!(
            (lstat(&dir).unwrap().dev(), lstat(&dir).unwrap().ino()),
            (before.dev(), before.ino()),
            "the swap must produce a different inode"
        );

        let err = open_checked_dir(&dir, &before).unwrap_err();
        assert!(err.to_string().contains("changed during open"), "{err}");

        // The same directory (unswapped) passes the check and can be written through.
        let after = open_checked_dir(&dir, &lstat(&dir).unwrap());
        assert!(after.is_ok(), "an unswapped parent must be accepted");
    }

    #[test]
    fn atomic_write_refuses_symlinked_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        symlink(&real, &link).unwrap();

        // `link/f` would follow the parent symlink without the O_NOFOLLOW binding.
        let err = atomic_write(&link.join("f"), b"x", 0o600).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(!real.join("f").exists());
    }

    #[test]
    fn atomic_write_replaces_existing_without_leaking_temp() {
        // The descriptor-relative create/rename must still leave exactly one file and no
        // `.wsl-webauthn-tmp` siblings (regression guard for the `openat`/`renameat` path).
        let dir = TempDir::new().unwrap();
        let dst = dir.path().join("f");
        atomic_write(&dst, b"one", 0o600).unwrap();
        atomic_write(&dst, b"two", 0o600).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"two");
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "a temp file leaked");
    }

    #[test]
    fn copy_file_atomic_refuses_symlinked_source() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, b"x").unwrap();
        let link = dir.path().join("src-link");
        symlink(&real, &link).unwrap();

        let err = copy_file_atomic(&link, &dir.path().join("dst"), 0o644).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn copy_file_atomic_refuses_symlinked_destination() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        std::fs::write(&src, b"payload").unwrap();
        let realdst = dir.path().join("realdst");
        std::fs::write(&realdst, b"keep").unwrap();
        let link = dir.path().join("dst-link");
        symlink(&realdst, &link).unwrap();

        let err = copy_file_atomic(&src, &link, 0o644).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert_eq!(std::fs::read(&realdst).unwrap(), b"keep");
    }

    #[test]
    fn remove_tree_does_not_follow_symlinks() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("keep"), b"keep").unwrap();
        let tree = dir.path().join("tree/sub");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("f"), b"x").unwrap();
        symlink(outside.path(), dir.path().join("tree/escape")).unwrap();

        remove_tree(&dir.path().join("tree")).unwrap();
        assert!(!dir.path().join("tree").exists());
        // The symlink target survives.
        assert!(outside.path().join("keep").exists());
    }

    #[test]
    fn refuse_symlink_detects_link() {
        let dir = TempDir::new().unwrap();
        let link = dir.path().join("l");
        symlink(dir.path().join("nope"), &link).unwrap();
        assert!(refuse_symlink(&link, "dest").is_err());
        assert!(refuse_symlink(&dir.path().join("absent"), "dest").is_ok());
    }

    #[test]
    fn read_nofollow_rejects_directory() {
        let dir = TempDir::new().unwrap();
        let err = read_nofollow(dir.path()).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    #[test]
    fn create_dir_all_refuses_symlinked_component() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        // Create under the symlinked component: must be refused.
        let err = create_dir_all(&link.join("sub")).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(!real.join("sub").exists());
        // A normal nested create works.
        create_dir_all(&dir.path().join("a/b/c")).unwrap();
        assert!(dir.path().join("a/b/c").is_dir());
    }

    /// L4-2: `remove_tree` must not consume one stack frame per directory level.
    ///
    /// A ~1500-deep chain is built (the deepest that fits `PATH_MAX`) and removed on a
    /// deliberately tiny 128 KiB thread stack. The recursive form this replaced would
    /// overflow such a stack; the explicit worklist must not.
    #[test]
    fn remove_tree_handles_a_deep_tree_without_stack_overflow() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("deep");
        let mut path = root.clone();
        // Two bytes of path per level ("/d") keeps the total under PATH_MAX (4096).
        for _ in 0..1500 {
            path.push("d");
        }
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("leaf"), b"x").unwrap();

        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || remove_tree(&root))
            .unwrap()
            .join()
            .expect("remove_tree must not overflow the stack")
            .expect("remove_tree must succeed");

        assert!(!dir.path().join("deep").exists());
    }

    /// L7-5 = L10-1: the shared helpers must agree with the SHA-256 test vector.
    #[test]
    fn sha256_hex_file_matches_known_vector() {
        let dir = TempDir::new().unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(
            sha256_hex_file(&empty).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = dir.path().join("abc");
        std::fs::write(&abc, b"abc").unwrap();
        assert_eq!(
            sha256_hex_file(&abc).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_and_short_hash_are_bounded() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(short_hash("0123456789abcdef"), "0123456789ab…");
        assert_eq!(short_hash("abc"), "abc");
    }
}
