//! `WSLWebAuthnBridge.exe` — the Windows half of the wsl-webauthn-pam pair
//! (plan §5).
//!
//! The process contract is strict and small:
//!
//! * stdin: exactly one length-prefixed JSON request (≤ 8 KiB).
//! * stdout: exactly one length-prefixed JSON response (≤ 64 KiB), or nothing
//!   when the transport itself failed.
//! * stderr: first line `PID <windows-pid>`, then diagnostics.
//! * exit code: `0` whenever a framed response was written (even an `ok:false`
//!   ceremony failure); non-zero only for transport/protocol failures.
//!
//! Exit codes:
//!
//! | code | meaning |
//! |---|---|
//! | `0` | a framed response was written (including an `ok:false` ceremony failure) |
//! | `3` | malformed/oversized/truncated request frame, non-JSON, or a request body that fails schema validation |
//! | `4` | valid JSON object whose `op` is not `probe`/`enroll`/`assert` |
//! | `5` | stdout write/flush failure while emitting the response |
//!
//! Any non-zero exit (or a missing/extra frame) is a *transport* failure on the Linux
//! side (fail-closed `PAM_AUTHINFO_UNAVAIL`), never a ceremony result.
//!
//! On non-Windows hosts the binary is a stub (the crate still builds and its
//! platform-independent layers are unit-tested there).

// The platform-independent layers are compiled for the real Windows build and
// for the Linux test build (so `cargo test -p wsl-webauthn-bridge` exercises
// the ceremony logic without `webauthn.dll`).
#[cfg(any(windows, test))]
mod api;
#[cfg(any(windows, test))]
mod ceremony;
#[cfg(windows)]
mod ffi;
#[cfg(any(windows, test))]
mod wire;

#[cfg(not(windows))]
fn main() {
    eprintln!("WSLWebAuthnBridge is Windows-only");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::io::Write as _;

    // First stderr line: the Windows PID for backstop `taskkill.exe` cancellation.
    let pid = ffi::current_process_id();
    {
        let stderr = std::io::stderr();
        let mut lock = stderr.lock();
        let _ = writeln!(lock, "PID {pid}");
        let _ = lock.flush();
    }

    // Read exactly one framed request.
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let req = match wire::read_request(&mut input) {
        Ok(req) => req,
        Err(wire::InputError::BadFrame) => return std::process::ExitCode::from(3),
        Err(wire::InputError::UnknownOp) => return std::process::ExitCode::from(4),
    };

    // Load the platform API. A missing/old webauthn.dll is a *ceremony* failure
    // (`not_supported`), reported in-band with exit 0.
    let api = match ffi::load() {
        Ok(api) => api,
        Err(e) => return write_response(&wsl_webauthn_protocol::Response::error(e)),
    };

    let resp = ceremony::dispatch(&api, &req);
    write_response(&resp)
}

/// Write one framed response and translate a stdio failure into exit code 5.
#[cfg(windows)]
fn write_response(resp: &wsl_webauthn_protocol::Response) -> std::process::ExitCode {
    use std::io::Write as _;

    let framed = wire::encode_response(resp);
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if lock.write_all(&framed).and_then(|_| lock.flush()).is_err() {
        return std::process::ExitCode::from(5);
    }
    std::process::ExitCode::from(0)
}
