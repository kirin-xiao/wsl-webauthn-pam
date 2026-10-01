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

use std::io;
use std::os::fd::RawFd;

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
