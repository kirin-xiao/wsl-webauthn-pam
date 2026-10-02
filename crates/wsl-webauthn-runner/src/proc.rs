//! Minimal, audited `libc` bindings for the interop runner.
//!
//! This is the only module in the crate permitted to contain `unsafe`; the rest of the
//! crate is `#![deny(unsafe_code)]`. It exposes safe wrappers for exactly the syscalls
//! the deadline loop needs:
//!
//! * `fcntl(2)` — put the child's stdout/stderr pipes into non-blocking mode.
//! * `poll(2)` — wait for readability with a computed timeout (never blocks past the
//!   caller's deadline).
//! * `read(2)` — drain the pipes once readable.
//! * `write(2)` — hand the request frame to the child's stdin. Unlike a plain
//!   `write(2)`, this wrapper blocks `SIGPIPE` for the calling thread and drains any
//!   pending `SIGPIPE` before restoring the mask, so a closed read end can never
//!   terminate a non-Rust host.
//!
//! The crate is loaded as a `cdylib` into `sudo`/`su`/`sshd`, none of which install a
//! `SIGPIPE` handler. Rust's runtime normally sets `SIGPIPE` to `SIG_IGN` from its
//! `main` shim, which never runs here; blocking the signal for our own thread is the
//! only remedy that does not mutate global process state.

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A bridge executable opened once and held, so hash→spawn cannot be raced.
///
/// The bridge path is opened `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`; the path itself is never
/// executed. Instead the descriptor is `F_DUPFD_CLOEXEC`'d to the lowest free descriptor
/// at/above `3` (skipping the runner's stdio), `FD_CLOEXEC` is cleared on the duplicate,
/// and the child is spawned via `/proc/self/fd/N`, so the kernel executes exactly the
/// inode that was opened (and can be `fstat`ed) — a later swap of the path cannot change
/// the image.
///
/// `F_DUPFD_CLOEXEC` (rather than `F_DUPFD`) is used because `F_DUPFD` fails with
/// `EINVAL` whenever its minimum is at/above the *soft* `RLIMIT_NOFILE`; that limit is
/// 1024 on a default WSL/systemd host, so a fixed high minimum such as 1024 would make
/// every spawn fail before it starts. A low minimum also avoids colliding with an
/// existing high-numbered descriptor in a long-lived host process.
///
/// `FD_CLOEXEC` is deliberately *not* set on the inherited descriptor: the WSL binfmt
/// handler (`WSLInterop`, flags `PF`) needs the descriptor to survive into the child
/// `/init` interpreter, and a `CLOEXEC` descriptor makes the interop exec fail with
/// `EINVAL`. The descriptor is closed when this value drops.
pub(crate) struct TrustedFile {
    /// Inheritable duplicate referenced by `fd_path` and inherited by the child. Keeps
    /// the opened inode alive and is the object of the identity recheck.
    inherit: OwnedFd,
    fd_path: PathBuf,
    dev: u64,
    ino: u64,
}

impl TrustedFile {
    /// Open `path` read-only, refusing symbolic links.
    pub(crate) fn open(path: &Path) -> io::Result<TrustedFile> {
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // SAFETY: `cpath` is a valid NUL-terminated C string and the flags are constants.
        // `open` takes no ownership of the string.
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh owned descriptor from `open`, so `File` may own it.
        let file = unsafe { File::from_raw_fd(fd) };
        let (dev, ino) = stat_identity(file.as_raw_fd())?;

        // `F_DUPFD_CLOEXEC` returns the lowest free descriptor at/above 3 and, unlike
        // `F_DUPFD`, does not fail when its minimum is at/above a low soft
        // `RLIMIT_NOFILE` (1024 on a default WSL/systemd host). `FD_CLOEXEC` is then
        // cleared so the descriptor survives `exec` into the WSL binfmt interpreter; the
        // original stays `CLOEXEC` and closes when `file` drops.
        // SAFETY: `F_DUPFD_CLOEXEC` takes the fd and a minimum; it returns a new owned
        // fd or -1.
        let dup = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `dup` is a fresh owned descriptor returned by `fcntl`.
        let inherit = unsafe { OwnedFd::from_raw_fd(dup) };
        // Clear `FD_CLOEXEC` on the duplicate: it must be inherited by the child's
        // interpreter (see the `TrustedFile` docs). The original descriptor is
        // unaffected and remains `CLOEXEC`.
        // SAFETY: F_GETFD/F_SETFD take an owned fd and an int; both always succeed for a
        // valid descriptor and only read/modify the close-on-exec flag.
        let flags = unsafe { libc::fcntl(inherit.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above.
        let rc = unsafe {
            libc::fcntl(
                inherit.as_raw_fd(),
                libc::F_SETFD,
                flags & !libc::FD_CLOEXEC,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd_path = PathBuf::from(format!("/proc/self/fd/{}", inherit.as_raw_fd()));
        Ok(TrustedFile {
            inherit,
            fd_path,
            dev,
            ino,
        })
    }

    /// `(st_dev, st_ino)` of the held descriptor.
    pub(crate) fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }

    /// Path to the held descriptor, suitable for `Command::new` (`/proc/self/fd/N`).
    pub(crate) fn fd_path(&self) -> &Path {
        &self.fd_path
    }

    /// The inheritable descriptor that the child will execute.
    fn inherit_fd(&self) -> RawFd {
        self.inherit.as_raw_fd()
    }
}

/// `fstat(fd)` → `(st_dev, st_ino)`, async-signal-safe.
fn stat_identity(fd: RawFd) -> io::Result<(u64, u64)> {
    // SAFETY: `fstat` writes into our local `stat` and only reads the fd.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((st.st_dev as u64, st.st_ino as u64))
}

/// Install a `pre_exec` guard that re-checks the held bridge descriptor immediately
/// before `execve`.
///
/// This is belt-and-braces on top of the held-fd spawn: the executed object is already
/// the opened descriptor, so the only race left is another thread reusing the descriptor
/// number. The guard stats the inherited fd in the forked child and fails the exec with
/// `ESTALE` if either the descriptor is gone or its `(dev, ino)` no longer matches what
/// was opened.
pub(crate) fn set_spawn_guard(command: &mut Command, trusted: &TrustedFile) {
    let fd = trusted.inherit_fd();
    let (dev, ino) = trusted.identity();
    // SAFETY: `pre_exec` runs in the forked child between `fork` and `execve`. The closure
    // calls only `fstat` (async-signal-safe) and produces a `Repr::Os` `io::Error` (no
    // allocation), so it is safe in that context.
    unsafe {
        command.pre_exec(move || match stat_identity(fd) {
            Ok(got) if got == (dev, ino) => Ok(()),
            _ => Err(io::Error::from_raw_os_error(libc::ESTALE)),
        });
    }
}

/// Set `O_NONBLOCK` on `fd`.
pub(crate) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL/F_SETFL take an owned fd and an int; both are always valid to call
    // and only read/modify kernel descriptor flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Poll `fds` for readiness for at most `timeout_ms` milliseconds.
///
/// Returns the number of ready descriptors, `0` on timeout, and maps `EINTR`/other
/// errors to `Err`. `EINTR` is reported as an error with `ErrorKind::Interrupted` so the
/// caller can simply retry.
pub(crate) fn poll(fds: &mut [libc::pollfd], timeout_ms: i32) -> io::Result<usize> {
    // `nfds_t` may be narrower than `usize` on some targets; never narrow silently. The
    // call sites pass one or two descriptors so this cannot realistically fail, but the
    // error is surfaced rather than panicking inside the root auth deadline loop.
    let nfds = libc::nfds_t::try_from(fds.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "poll descriptor count does not fit in nfds_t",
        )
    })?;
    // SAFETY: `fds` is a valid mutable slice of pollfd; nfds matches its length; the
    // kernel only writes readiness flags into the slice.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), nfds, timeout_ms) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc as usize)
}

/// `read(2)` once, returning the number of bytes read (`0` = EOF).
pub(crate) fn read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is an owned descriptor and `buf` is a valid writable slice.
    let rc = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc as usize)
}

/// RAII guard that blocks `SIGPIPE` for the calling thread while alive.
///
/// Drop restores the previous signal mask, first draining a pending `SIGPIPE` (with a
/// zero timeout) so a write that raced with the read end closing cannot deliver the
/// signal the moment the mask is lifted. The mask is per-thread, so this is safe to use
/// from a threaded PAM host and never changes process-global signal state.
struct SigpipeGuard {
    old_mask: libc::sigset_t,
}

impl SigpipeGuard {
    /// Block `SIGPIPE` for the current thread, remembering the previous mask.
    fn block() -> io::Result<SigpipeGuard> {
        // SAFETY: sigemptyset/sigaddset initialize a local sigset_t; pthread_sigmask
        // reads the set and writes the old mask into another local.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGPIPE);
            let mut old_mask: libc::sigset_t = std::mem::zeroed();
            // pthread_sigmask returns the error number directly (does not set errno).
            let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old_mask);
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc));
            }
            Ok(SigpipeGuard { old_mask })
        }
    }

    /// Consume a `SIGPIPE` that a failed write left pending, without blocking.
    fn drain(&self) {
        // SAFETY: as above; sigtimedwait with a zero timeout only dequeues an already
        // pending signal and cannot block.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGPIPE);
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            libc::sigtimedwait(&set, std::ptr::null_mut(), &timeout);
        }
    }
}

impl Drop for SigpipeGuard {
    fn drop(&mut self) {
        // A write that returned `EPIPE` may have queued a blocked SIGPIPE; consume it
        // before unblocking, otherwise restoring the mask delivers it immediately.
        self.drain();
        // SAFETY: `old_mask` was produced by pthread_sigmask for this thread.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.old_mask, std::ptr::null_mut());
        }
    }
}

/// `write(2)` once, returning the number of bytes written (`0` = peer closed).
///
/// `SIGPIPE` is blocked for the duration of the call and any signal a closed peer
/// queues is drained before the mask is restored, so this can never terminate a
/// `SIGPIPE=SIG_DFL` host process. A closed read end is reported as `EPIPE`.
pub(crate) fn write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    let guard = SigpipeGuard::block()?;
    // SAFETY: `fd` is an owned descriptor and `buf` is a valid readable slice.
    let rc = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
    let result = if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    };
    // `guard`'s Drop drains a pending SIGPIPE and restores the previous mask.
    drop(guard);
    result
}

/// Whether `pid` still exists (or is a zombie), used by lifecycle regression tests.
///
/// `kill(pid, 0)` performs only the existence/permission check; it delivers no signal.
#[cfg(test)]
pub(crate) fn process_alive(pid: u32) -> bool {
    // SAFETY: signal 0 is the null signal; it only probes for the process.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// CPU time consumed by the *calling thread* so far.
///
/// Used by regression tests to prove an over-cap descriptor no longer spins the drain
/// loop; process-wide accounting would be polluted by tests running in parallel.
#[cfg(test)]
pub(crate) fn thread_cpu_time() -> std::time::Duration {
    // SAFETY: clock_gettime writes a timespec into our local.
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) != 0 {
            return std::time::Duration::ZERO;
        }
        std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_exe(path: &Path, body: &str) {
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("write helper");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    /// Lower this process's soft `RLIMIT_NOFILE` to at most `limit`.
    ///
    /// A default WSL/systemd host ships a soft limit of 1024, which is exactly the value
    /// that made the old `F_DUPFD(fd, 1024)` held-fd spawn fail with `EINVAL` before the
    /// fix. Reproducing that limit here keeps the regression meaningful on CI hosts with
    /// a huge ambient limit. Only the soft limit is lowered (always permitted without
    /// privilege); the hard limit is untouched, and restoring is unnecessary because the
    /// lower value is what production sees.
    fn lower_soft_nofile_to_at_most(limit: u64) {
        // SAFETY: `getrlimit`/`setrlimit` read/write a local `rlimit`; lowering only the
        // soft limit is always allowed for the calling process.
        unsafe {
            let mut rl: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
                panic!(
                    "getrlimit(RLIMIT_NOFILE) failed: {}",
                    io::Error::last_os_error()
                );
            }
            if rl.rlim_cur > limit {
                rl.rlim_cur = limit;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                    panic!(
                        "setrlimit(RLIMIT_NOFILE, {limit}) failed: {}",
                        io::Error::last_os_error()
                    );
                }
            }
        }
    }

    /// L2-2: once the bridge is opened, replacing its path must not change the executed
    /// image — the held descriptor still points at the originally opened inode.
    ///
    /// The soft `RLIMIT_NOFILE` is lowered first so this exercises the default
    /// WSL/systemd host limit under which the old `F_DUPFD(fd, 1024)` spawn failed.
    #[test]
    fn held_fd_exec_is_not_affected_by_path_replacement() {
        lower_soft_nofile_to_at_most(1024);
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("tool");
        write_exe(&path, "echo original");

        let trusted = TrustedFile::open(&path).expect("open bridge");
        let (dev, ino) = trusted.identity();

        // The inherited duplicate must be a low, non-CLOEXEC descriptor so it survives
        // into the WSL binfmt interpreter and cannot collide with a high fd in the host.
        let inherit_fd = trusted.inherit_fd();
        assert!(
            (3..1024).contains(&inherit_fd),
            "held fd {inherit_fd} must be a low inheritable descriptor"
        );
        // SAFETY: F_GETFD only reads the descriptor flags of a live owned fd.
        let fd_flags = unsafe { libc::fcntl(inherit_fd, libc::F_GETFD) };
        assert!(
            fd_flags >= 0,
            "F_GETFD failed: {}",
            io::Error::last_os_error()
        );
        assert_eq!(
            fd_flags & libc::FD_CLOEXEC,
            0,
            "the inherited descriptor must not be CLOEXEC (it must survive exec)"
        );

        // Swap a different executable over the path after the open.
        let replacement = dir.path().join("replacement");
        write_exe(&replacement, "echo replacement");
        std::fs::rename(&replacement, &path).expect("replace path");

        // The held fd still reads the original bytes, and the identity is unchanged.
        assert_eq!(
            std::fs::read(trusted.fd_path()).expect("read held fd"),
            b"#!/bin/sh\necho original\n"
        );
        assert_eq!(
            stat_identity(trusted.inherit_fd()).expect("fstat held fd"),
            (dev, ino),
            "held descriptor identity drifted"
        );

        // Executing the held descriptor runs the *original* program, not the replacement.
        let mut command = Command::new(trusted.fd_path());
        set_spawn_guard(&mut command, &trusted);
        let out = command.output().expect("exec held fd");
        assert!(out.status.success(), "held-fd exec failed: {out:?}");
        assert_eq!(
            out.stdout, b"original\n",
            "held fd must execute the originally opened inode, not the path replacement"
        );

        // Belt-and-braces: the pre_exec guard fails closed if the fd is gone.
        // SAFETY: closing an owned descriptor that we are about to abandon.
        unsafe {
            libc::close(trusted.inherit_fd());
        }
        let mut command = Command::new("/bin/true");
        set_spawn_guard(&mut command, &trusted);
        let err = command
            .spawn()
            .expect_err("guard must fail when the held descriptor is gone");
        assert_eq!(err.raw_os_error(), Some(libc::ESTALE), "{err:?}");
        // Avoid a double-close of the same fd when `trusted` drops.
        std::mem::forget(trusted);
    }
}
