//! `sigpipe-probe` — test double for the L9-1 SIGPIPE host-kill regression.
//!
//! Test support only. It emulates a non-Rust PAM host (the runner is a `cdylib` loaded
//! into `sudo`/`su`/`sshd`, none of which set `SIGPIPE` to `SIG_IGN`) by resetting
//! `SIGPIPE` to `SIG_DFL`, then:
//!
//! 1. writes to a pipe whose read end is closed, via the runner's real SIGPIPE-safe
//!    write path — a missing fix terminates this process with `SIGPIPE` (exit 141);
//! 2. if `FAKE_BRIDGE` is set, drives the fake bridge in `closestdin=1` mode (a child
//!    that closes its stdin before the request is written) and requires a clean probe.
//!
//! Exits 0 on success; any other status (including death by signal) fails the test.

use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    // Undo the Rust runtime's SIGPIPE=SIG_IGN so a stray SIGPIPE is fatal, exactly as it
    // is in the real host. Every write below must be protected by the runner's mask.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    if let Some(code) = direct_closed_pipe() {
        return code;
    }

    if let Some(code) = child_closing_stdin() {
        return code;
    }

    ExitCode::SUCCESS
}

/// Write to a pipe whose read end is already closed. With the fix this returns `EPIPE`;
/// without it, `SIGPIPE` kills the process before the call returns.
fn direct_closed_pipe() -> Option<ExitCode> {
    let mut pipefd: [libc::c_int; 2] = [0; 2];
    // SAFETY: pipe(2) writes two owned fds into our array.
    if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
        eprintln!("sigpipe-probe: pipe() failed");
        return Some(ExitCode::from(2));
    }
    let (read_fd, write_fd) = (pipefd[0], pipefd[1]);
    // SAFETY: close an owned fd.
    unsafe {
        libc::close(read_fd);
    }

    let result = wsl_webauthn_runner::test_write_fd(write_fd, b"framed request");
    // SAFETY: close an owned fd.
    unsafe {
        libc::close(write_fd);
    }

    match result {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => None,
        Err(e) => {
            eprintln!("sigpipe-probe: unexpected write error: {e}");
            Some(ExitCode::from(4))
        }
        Ok(n) => {
            eprintln!("sigpipe-probe: expected EPIPE, wrote {n} bytes");
            Some(ExitCode::from(3))
        }
    }
}

/// Drive the fake bridge with a child that closes its stdin before the write, proving
/// the end-to-end path neither crashes nor hangs.
fn child_closing_stdin() -> Option<ExitCode> {
    let Ok(fake) = std::env::var("FAKE_BRIDGE") else {
        return None;
    };
    let cwd = std::env::var("FAKE_BRIDGE_CWD").unwrap_or_else(|_| "/tmp".to_string());
    let runner = wsl_webauthn_runner::Runner::without_interop_check(&fake, &cwd)
        .taskkill_program("/bin/true")
        .args(["ok", "closestdin=1"]);
    match runner.probe(Duration::from_secs(5)) {
        Ok(_) => None,
        Err(e) => {
            eprintln!("sigpipe-probe: child driver failed: {e}");
            Some(ExitCode::from(5))
        }
    }
}
