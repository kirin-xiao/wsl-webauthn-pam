//! Minimal, audited `libc` bindings for the credential store.
//!
//! This is the **only** module in the crate permitted to contain `unsafe`
//! (see `lib.rs`), and it is deliberately tiny: it exposes safe wrappers around the
//! small set of syscalls the store needs. Every wrapper documents the exact safety
//! obligation it discharges internally, so callers never write `unsafe`.
//!
//! Syscalls used:
//! * `open(2)` / `openat(2)` — `O_RDONLY|O_NOFOLLOW|O_NOCTTY|O_CLOEXEC` credential reads
//!   and `O_DIRECTORY|…` directory handles for `fsync`/`rename`.
//! * `fstat(2)` — ownership/mode checks on an opened fd (post-open, TOCTOU-safe).
//! * `mkstemp(3)` — create a uniquely named temp file in the target directory.
//! * `fchmod(2)` / `fsync(2)` / `rename(2)` — atomic, root-owned writes.
//! * `unlink(2)` — temp cleanup.
//! * `mkdir(2)` — create the credentials directory.
//! * `lstat(2)` / `fstatat(2)` — symlink detection on every path component, including
//!   relative to a held directory descriptor.
//! * `unlinkat(2)` — remove a record relative to a held directory descriptor.

#![allow(unsafe_code)]

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

/// Convert a path to a NUL-terminated C string.
///
/// Returns [`io::ErrorKind::InvalidInput`] if the path contains an interior NUL byte;
/// the store treats that as a hard error rather than truncating silently.
pub(crate) fn cpath(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))
}

/// File status captured by `lstat(2)` (does not follow a final symlink).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stat {
    pub mode: u32,
    pub uid: u32,
    pub dev: u64,
    pub ino: u64,
}

impl Stat {
    /// Returns `true` if the final component is a symbolic link (`S_IFLNK`).
    pub fn is_symlink(self) -> bool {
        (self.mode & libc::S_IFMT) == libc::S_IFLNK
    }

    /// Returns `true` if the final component is a regular file (`S_IFREG`).
    pub fn is_file(self) -> bool {
        (self.mode & libc::S_IFMT) == libc::S_IFREG
    }

    /// Returns `true` if the final component is a directory (`S_IFDIR`).
    pub fn is_dir(self) -> bool {
        (self.mode & libc::S_IFMT) == libc::S_IFDIR
    }

    /// Permission bits (low 12 bits, including setuid/setgid/sticky).
    pub fn perm_bits(self) -> u32 {
        self.mode & 0o7777
    }
}

// The `as` casts below are required for portability: `st_mode` is `u16` on some libc
// targets and `st_dev`/`st_ino` vary between 32- and 64-bit off_t/ino_t. They are
// no-ops on x86_64, hence the targeted `allow`.
#[allow(clippy::unnecessary_cast)]
fn stat_from_raw(raw: libc::stat) -> Stat {
    Stat {
        mode: raw.st_mode as u32,
        uid: raw.st_uid,
        dev: raw.st_dev as u64,
        ino: raw.st_ino as u64,
    }
}

/// `lstat(2)`: stat `path` without following a final symlink.
pub(crate) fn lstat(path: &Path) -> io::Result<Stat> {
    let c = cpath(path)?;
    // SAFETY: `c` is a valid NUL-terminated C string; `out` is zero-initialized and
    // only read by lstat, which never retains the pointer.
    let mut out: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::lstat(c.as_ptr(), &mut out) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat_from_raw(out))
}

/// `fstat(2)`: stat an already-open file descriptor.
///
/// Used both for ownership checks and for the post-open TOCTOU identity comparison.
pub(crate) fn fstat(fd: RawFd) -> io::Result<Stat> {
    // SAFETY: `fd` is a descriptor this crate opened and still owns; `out` is
    // zero-initialized and only read by fstat.
    let mut out: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut out) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat_from_raw(out))
}

/// Open `path` read-only with hardening flags and no symlink following.
pub(crate) fn open_readonly(path: &Path) -> io::Result<Fd> {
    let c = cpath(path)?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: `c` is a valid NUL-terminated path; open returns an owned fd or -1.
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Fd(fd))
}

/// `fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)`: stat a single path component relative to
/// an open directory without following a final symlink.
///
/// `name` must be a single component (the store only ever passes a validated `*.json`
/// leaf). Operating relative to a held directory descriptor removes the path-swap window
/// that a second absolute `lstat` would otherwise open.
pub(crate) fn fstatat_nofollow(dirfd: RawFd, name: &OsStr) -> io::Result<Stat> {
    let c = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL byte"))?;
    // SAFETY: `dirfd` is an owned directory descriptor, `c` is a valid NUL-terminated
    // single component, `out` is zero-initialized and only read by fstatat.
    let mut out: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatat(dirfd, c.as_ptr(), &mut out, libc::AT_SYMLINK_NOFOLLOW) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat_from_raw(out))
}

/// `unlinkat(dirfd, name)`: unlink a single path component relative to an open directory.
///
/// `unlinkat` never follows a final symlink; it removes the link itself. Callers stat the
/// entry with [`fstatat_nofollow`] first when they need to distinguish a symlink.
pub(crate) fn unlinkat(dirfd: RawFd, name: &OsStr) -> io::Result<()> {
    let c = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL byte"))?;
    // SAFETY: `dirfd` is an owned directory descriptor and `c` is a valid NUL-terminated
    // single component; unlinkat takes no ownership of the buffer.
    let rc = unsafe { libc::unlinkat(dirfd, c.as_ptr(), 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Open a directory for `fsync`/`rename` bookkeeping with `O_DIRECTORY|O_NOFOLLOW`.
pub(crate) fn open_dir(path: &Path) -> io::Result<Fd> {
    let c = cpath(path)?;
    let flags =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC;
    // SAFETY: as in `open_readonly`; O_DIRECTORY makes a non-directory fail closed.
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Fd(fd))
}

/// `close(2)`.
pub(crate) fn close(fd: RawFd) {
    // SAFETY: `fd` is an owned descriptor; closing twice is caller error, and all
    // callers close exactly once.
    unsafe {
        libc::close(fd);
    }
}

/// RAII guard closing a raw fd exactly once.
#[derive(Debug)]
pub(crate) struct Fd(pub RawFd);

impl Fd {
    pub fn raw(&self) -> RawFd {
        self.0
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        close(self.0);
    }
}

/// `mkdir(2)` with an explicit mode.
pub(crate) fn mkdir(path: &Path, mode: u32) -> io::Result<()> {
    let c = cpath(path)?;
    // SAFETY: `c` is a valid NUL-terminated path; mode is applied through umask.
    let rc = unsafe { libc::mkdir(c.as_ptr(), mode as libc::mode_t) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `unlink(2)`, ignoring a missing file.
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    let c = cpath(path)?;
    // SAFETY: `c` is a valid NUL-terminated path.
    let rc = unsafe { libc::unlink(c.as_ptr()) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// `rename(2)` — atomic within a single filesystem.
pub(crate) fn rename(from: &Path, to: &Path) -> io::Result<()> {
    let from_c = cpath(from)?;
    let to_c = cpath(to)?;
    // SAFETY: both are valid NUL-terminated paths; rename replaces the destination.
    let rc = unsafe { libc::rename(from_c.as_ptr(), to_c.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fchmod(2)`.
pub(crate) fn fchmod(fd: RawFd, mode: u32) -> io::Result<()> {
    // SAFETY: `fd` is an owned descriptor.
    let rc = unsafe { libc::fchmod(fd, mode as libc::mode_t) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fsync(2)`, retrying `EINTR` and mapping `EINVAL`/`ENOTSUP` (unsupported filesystems)
/// to success so the store still works on exotic mounts while keeping durability
/// best-effort.
pub(crate) fn fsync(fd: RawFd) -> io::Result<()> {
    loop {
        // SAFETY: `fd` is an owned descriptor.
        let rc = unsafe { libc::fsync(fd) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if matches!(err.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTSUP)) {
            return Ok(());
        }
        return Err(err);
    }
}

/// Create a uniquely named temp file in `dir` with a `0600` mode.
///
/// The template is `<dir>/.tmp-XXXXXX`; `mkstemp` replaces the `XXXXXX` with a unique
/// suffix and opens the file `O_RDWR|O_CREAT|O_EXCL` with mode `0600` (subject to umask,
/// hence the explicit `fchmod` by the caller). Returns the fd and the chosen name.
pub(crate) fn mkstemp_in(dir: &Path) -> io::Result<(Fd, OsString)> {
    let mut template = OsString::from(dir.as_os_str());
    template.push(OsStr::new("/.tmp-XXXXXX"));
    // `mkstemp` wants a mutable, NUL-terminated buffer it may modify in place.
    let mut buf = template.into_vec();
    buf.push(0);
    // SAFETY: `buf` is a mutable, NUL-terminated byte buffer owned for the duration of
    // the call; mkstemp writes at most the six placeholder bytes and returns an fd.
    let fd = unsafe { libc::mkstemp(buf.as_mut_ptr().cast::<libc::c_char>()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Recover the final name from the mutated buffer (up to the first NUL).
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = OsString::from_vec(buf[..end].to_vec());
    Ok((Fd(fd), name))
}

/// `write(2)` a complete buffer to `fd`, retrying short writes.
pub(crate) fn write_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `fd` is an owned descriptor and `buf` is a valid readable slice.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

/// `read(2)` up to `cap` bytes from `fd`.
///
/// Returns `Ok(Some(bytes))` on a complete read, `Ok(None)` if the stream exceeds `cap`
/// (the extra byte is observed but never accumulated), and `Err` for IO failures.
pub(crate) fn read_capped(fd: RawFd, cap: usize) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // SAFETY: `fd` is an owned descriptor and `chunk` is a valid writable slice.
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast::<libc::c_void>(), chunk.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Ok(Some(out));
        }
        let n = n as usize;
        if out.len() + n > cap {
            return Ok(None);
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// `link(2)`: create `to` as a hard link to `from`, failing with `EEXIST` if `to` exists.
///
/// Used to install a file without ever clobbering an existing one (`replace == false`).
pub(crate) fn link(from: &Path, to: &Path) -> io::Result<()> {
    let from_c = cpath(from)?;
    let to_c = cpath(to)?;
    // SAFETY: both are valid NUL-terminated paths; link never follows a final symlink.
    let rc = unsafe { libc::link(from_c.as_ptr(), to_c.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `getuid(2)` — real uid of the calling process.
pub(crate) fn getuid() -> u32 {
    // SAFETY: getuid is always safe to call and cannot fail.
    unsafe { libc::getuid() }
}

/// `geteuid(2)` — effective uid of the calling process.
pub(crate) fn geteuid() -> u32 {
    // SAFETY: geteuid is always safe to call and cannot fail.
    unsafe { libc::geteuid() }
}

/// Whether a path exists as a symlink (used by tests and diagnostics).
#[allow(dead_code)]
pub(crate) fn is_symlink(path: &Path) -> bool {
    lstat(path).map(Stat::is_symlink).unwrap_or(false)
}
