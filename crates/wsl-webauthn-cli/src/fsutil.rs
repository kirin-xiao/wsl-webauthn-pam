//! Safe, symlink-hardened filesystem helpers for the installer (plan D6, §10).
//!
//! The installer never walks through a symlink and never writes in place: every
//! file is written to a temporary file **in the same directory** and then
//! `rename(2)`d over the destination, so a crash leaves either the old or the new
//! file, never a truncated one.
//!
//! Everything here is implemented with safe `std` APIs (this crate is
//! `#![deny(unsafe_code)]`):
//!
//! * [`lstat_opt`] uses [`std::fs::symlink_metadata`] — the safe `lstat(2)`.
//! * `O_NOFOLLOW`/`O_CLOEXEC` are applied through
//!   [`std::os::unix::fs::OpenOptionsExt::custom_flags`], which is safe.
//! * Modes are pinned with [`std::fs::File::set_permissions`] (an `fchmod` on the
//!   open descriptor), defeating both `umask` and a symlinked path.
//!
//! Deliberately **no shell**: this module only performs direct syscalls.

use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Atomically replace `path` with `bytes`, pinned to `mode`.
///
/// Refuses a symlinked destination (or a symlinked parent), writes a temp file in the
/// same directory, `fchmod`s it exactly, `fsync`s it, then `rename(2)`s it into place
/// and `fsync`s the directory. The temp file is removed on every error path.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no parent directory: {}", path.display()),
        )
    })?;
    let pmd = lstat(parent)?;
    if pmd.file_type().is_symlink() {
        return Err(symlink_error(parent, "destination directory"));
    }
    if !pmd.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "destination parent is not a directory: {}",
                parent.display()
            ),
        ));
    }
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

    let temp = temp_path(parent);
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY)
            .open(&temp)?;
        file.write_all(bytes)?;
        // `mode` at creation is filtered through umask; pin it exactly.
        file.set_permissions(Permissions::from_mode(mode))?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)?;
        // Persist the directory entry (best effort: some filesystems reject fsync on a
        // directory, which is not fatal for correctness of the rename itself).
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
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
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        remove_tree(&entry.path())?;
    }
    remove_dir_if_empty(path)
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
}
