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
//! * `kill(2)` — `SIGKILL` the shim child on deadline expiry.

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
    // SAFETY: `fds` is a valid mutable slice of pollfd; nfds matches its length; the
    // kernel only writes readiness flags into the slice.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
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

/// `write(2)` once, returning the number of bytes written (`0` = peer closed).
pub(crate) fn write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `fd` is an owned descriptor and `buf` is a valid readable slice.
    let rc = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc as usize)
}

/// Send `SIGKILL` to `pid`, ignoring a missing process.
pub(crate) fn kill_sigkill(pid: i32) {
    // SAFETY: kill takes a pid and a signal number; it cannot cause memory unsafety.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
}
