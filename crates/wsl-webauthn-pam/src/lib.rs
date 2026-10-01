//! `pam_wsl_webauthn.so` — a Linux-PAM module that authenticates via the Windows
//! WebAuthn / FIDO2 platform authenticator (plan §8).
//!
//! The module is a `cdylib`. Its exported surface is exactly the six `pam_sm_*`
//! entry points plus the hand-rolled PAM bindings; all verification happens here on
//! the Linux side. Nothing is written to stdout, ever — diagnostics go to `syslog`
//! under `LOG_AUTHPRIV`.
//!
//! # Authentication flow (`pam_sm_authenticate`)
//!
//! 1. `pam_get_user` → validate the name with the store's `^[A-Za-z_][A-Za-z0-9._-]{0,31}$`
//!    validator (rejecting null/empty first).
//! 2. Load `/etc/wsl_webauthn/config` and the user's credential record.
//! 3. Unless `noverifypin`, compare the SHA-256 of the configured bridge executable
//!    with the digest pinned in the record (plan D11); a mismatch refuses to launch.
//! 4. Mint a 32-byte challenge, build the exact `clientDataJSON`, optionally emit a
//!    `pam_conv` consent pre-prompt (skipped under `PAM_SILENT`), and run the bridge.
//! 5. Verify the response with `wsl-webauthn-verifier` (echo consistency, credential
//!    id, then the full cryptographic assertion with the stored sign counter).
//!
//! # Mapping table (fail-closed)
//!
//! This is the contract of the module; every row is covered by a test.
//!
//! | Situation | PAM code |
//! |---|---|
//! | Verified assertion | `PAM_SUCCESS` |
//! | No credential record for the user (`StoreError::NotFound`) | `PAM_USER_UNKNOWN` |
//! | Null/empty/invalid username | `PAM_USER_UNKNOWN` |
//! | Config missing/invalid, store error (ownership, symlink, corrupt, I/O), bridge pin mismatch/missing, OS entropy unavailable for the challenge, `RunnerError` (interop unavailable, bridge missing, spawn, transport, timeout), `BridgeError::{not_available,not_supported,timeout,busy,invalid_parameter,internal}` | `PAM_AUTHINFO_UNAVAIL` |
//! | `BridgeError::user_cancelled` | `PAM_AUTH_ERR` |
//! | Any `VerifyError`, echo mismatch, credential-id mismatch, malformed response field | `PAM_AUTH_ERR` |
//! | Panic in module code | `PAM_ABORT` |
//! | `pam_sm_setcred` | `PAM_SUCCESS` |
//! | Any other non-authentication `pam_sm_*` | `PAM_IGNORE` |
//!
//! Note: plan §8 collapses the bridge taxonomy into "no UV platform" →
//! `PAM_AUTHINFO_UNAVAIL` and "user_cancelled / bad signature / challenge mismatch" →
//! `PAM_AUTH_ERR`. This module interprets every non-cancel ceremony failure
//! (`not_available`, `not_supported`, `timeout`, `busy`, `invalid_parameter`,
//! `internal`) as an unavailable service, which agrees with the plan's coarse rows.
//!
//! Failure paths request `pam_fail_delay(pamh, 2_000_000)` (2 s) before returning,
//! matching plan §3/CR-14. No attempt counter is persisted across processes: the PAM
//! stack owns retry policy (plan §3).
//!
//! # Log severity
//!
//! Every failure line names the PAM code and its symbolic name, e.g.
//! `authentication failed: PAM_AUTHINFO_UNAVAIL(9): ...`. Severity follows the class:
//! an authentication decision (`PAM_AUTH_ERR` — a rejected/forged assertion, malformed
//! response, or a user cancel) is the conventional `LOG_NOTICE`; a missing/unknown
//! identity (`PAM_USER_UNKNOWN`) is `LOG_WARNING`; infrastructure unavailability
//! (`PAM_AUTHINFO_UNAVAIL` and any other code) is `LOG_ERR`. This lets an admin grepping
//! `authpriv` tell the three classes apart.
//!
//! # Module arguments
//!
//! ```text
//! auth [success=end default=ignore] pam_wsl_webauthn.so [debug] [timeout=<secs>] [noverifypin]
//! ```
//!
//! * `debug` — `LOG_DEBUG` detail (never secrets, challenges, or signatures).
//! * `timeout=<secs>` — whole-child deadline; overrides the config value and the 60 s
//!   default. The runner's own 5 s `taskkill` budget may add to the wall time.
//! * `noverifypin` — **disables** the bridge SHA-256 pin check (defence in depth
//!   removed). Its use is logged loudly at `LOG_ERR` on every authentication.
//!
//! Unknown arguments are ignored and debug-logged. Parsing never panics.
//!
//! # Lockout guidance
//!
//! Enrolling this module makes Windows Hello a *requirement* for the services it is
//! added to. Always keep at least one working `sudo`/`su` path (a second TTY, a root
//! shell, or the local password) before enabling it, and test with a non-critical
//! service first. See the installer's lockout warning (plan §10) and `SECURITY.md`.
//!
//! # Wire facts that shape this module
//!
//! * The Windows Hello prompt shows the **RP ID**, not `RP_NAME`; the `pam_conv`
//!   pre-prompt above is therefore the primary consent-naming mechanism (plan SR-11).
//! * The runner's deadline includes a 5 s `taskkill` budget, so total wall time can
//!   reach `deadline + 5 s`; the default 60 s deadline leaves the bridge's 55 s
//!   advisory timeout a 5 s margin (plan §3).
//! * The PAM module does **not** write the credential store. Signature-counter
//!   persistence is deferred (the counter is advisory and Windows Hello reports zero);
//!   the observed value is debug-logged.

#![warn(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
// The module's `unsafe` surface is the PAM C ABI: the six exported `pam_sm_*`
// entry points plus the raw bindings. Those items carry a documented
// `#[allow(unsafe_code)]`; everything else must stay safe.
#![deny(unsafe_code)]

// The module maps a panic in Rust code to `PAM_ABORT` via `catch_unwind`
// (fail-closed). With `panic = "abort"` that mapping is silently lost and a
// panic would unwind across the FFI boundary / abort the host process. Require
// unwinding panics in every profile.
#[cfg(not(panic = "unwind"))]
compile_error!(
    "wsl-webauthn-pam must be built with panic=unwind; panic=abort would disable \
     the catch_unwind -> PAM_ABORT fail-closed mapping across the PAM FFI boundary"
);

pub mod args;
pub mod bindings;
pub mod logger;
pub mod logic;
pub mod seam;

pub use args::ModuleArgs;
pub use logic::{AuthOutcome, Deps, FAIL_DELAY_USEC, SystemDeps, authenticate, run};
pub use seam::{PamSeam, RealPamSeam, SeamError};

use std::ffi::{c_char, c_int};

use crate::bindings::{LOG_CRIT, PAM_ABORT, PAM_IGNORE, PAM_SUCCESS, pam_handle_t};

/// Wrap a PAM entry point so a panic becomes `PAM_ABORT` instead of unwinding across
/// the FFI boundary (undefined behaviour) or aborting the process.
fn guarded<F>(what: &str, body: F) -> c_int
where
    F: FnOnce() -> c_int,
{
    // Root-cause fix for L8-1: replace the default stderr-printing panic hook with
    // one that logs to syslog before `catch_unwind` can observe the panic.
    logger::install_panic_hook();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => {
            logger::auth(
                LOG_CRIT,
                &format!("panic in {what}; returning PAM_ABORT (fail closed)"),
            );
            PAM_ABORT
        }
    }
}

/// Copy the `(argc, argv)` module-argument array into owned `String`s.
///
/// Never panics: null pointers, non-UTF-8 entries, and out-of-range counts are
/// skipped. There is no `argv[argc] == NULL` assumption.
///
/// # Safety
///
/// `argv` must be null or point at `argc` valid `const char *` entries.
#[allow(unsafe_code)] // raw C string array marshalling (PAM ABI)
unsafe fn collect_args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    if argv.is_null() || argc <= 0 {
        return Vec::new();
    }
    let count = argc as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: the caller guarantees `argc` valid pointers at `argv`.
        let ptr = unsafe { *argv.add(i) };
        if let Some(s) = unsafe { bindings::cstr_to_str(ptr) } {
            out.push(s.to_string());
        }
    }
    out
}

/// Authenticate the user via a Windows Hello assertion.
///
/// # Safety
///
/// `pamh` must be a valid `pam_handle_t *` supplied by libpam, and `argv` must be the
/// argument array libpam passed alongside `argc`.
///
/// The function is deliberately *not* marked `unsafe`: it has the C ABI libpam
/// requires, and Rust's `unsafe fn` marker would not be visible to the PAM stack.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[allow(unsafe_code)] // PAM C ABI entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    guarded("pam_sm_authenticate", || {
        // SAFETY: the caller (libpam) owns `argv` for the duration of this call.
        let raw_args = unsafe { collect_args(argc, argv) };
        let deps = SystemDeps::new();
        // SAFETY: `pamh` is a valid handle for the duration of this call.
        let mut seam = unsafe { RealPamSeam::new(pamh) };
        run(&mut seam, &deps, flags, &raw_args)
    })
}

/// Set credentials: nothing to do for WebAuthn, so report success.
///
/// # Safety
///
/// `pamh` must be a valid `pam_handle_t *` supplied by libpam.
#[allow(unsafe_code)] // PAM C ABI entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guarded("pam_sm_setcred", || PAM_SUCCESS)
}

/// Account management: not our concern, so ignore the module.
///
/// # Safety
///
/// `pamh` must be a valid `pam_handle_t *` supplied by libpam.
#[allow(unsafe_code)] // PAM C ABI entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guarded("pam_sm_acct_mgmt", || PAM_IGNORE)
}

/// Session open: not our concern, so ignore the module.
///
/// # Safety
///
/// `pamh` must be a valid `pam_handle_t *` supplied by libpam.
#[allow(unsafe_code)] // PAM C ABI entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guarded("pam_sm_open_session", || PAM_IGNORE)
}

/// Session close: not our concern, so ignore the module.
///
/// # Safety
///
/// `pamh` must be a valid `pam_handle_t *` supplied by libpam.
#[allow(unsafe_code)] // PAM C ABI entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guarded("pam_sm_close_session", || PAM_IGNORE)
}

/// Password change: not our concern, so ignore the module.
///
/// # Safety
///
/// `pamh` must be a valid `pam_handle_t *` supplied by libpam.
#[allow(unsafe_code)] // PAM C ABI entry point
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    guarded("pam_sm_chauthtok", || PAM_IGNORE)
}

#[cfg(test)]
// Test-only `dup2`/`dup` to capture stderr for the L8-1 assertion below; the production
// module surface stays `unsafe`-free (see the crate-level `deny(unsafe_code)` guard).
#[allow(unsafe_code)]
mod tests {
    use super::*;

    /// Redirect the process's stderr to a temp file for the duration of `f`, restoring
    /// it even if `f` panics, and return what `f` wrote. Serialized process-wide so two
    /// tests cannot interleave redirections.
    fn capture_stderr<F: FnOnce()>(f: F) -> String {
        use std::io::Write as _;
        use std::os::unix::io::AsRawFd as _;

        /// Restores stderr when dropped, including on the unwind path.
        struct Restore(i32);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::io::stderr().flush();
                // SAFETY: `self.0` is the descriptor returned by `dup` and is closed
                // exactly once; `dup2` restores the original stderr.
                unsafe {
                    libc::dup2(self.0, libc::STDERR_FILENO);
                    libc::close(self.0);
                }
            }
        }

        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let _ = std::io::stderr().flush();
        // SAFETY: `dup`/`dup2` act on this process's own descriptors; the original is
        // restored by `Restore` before the mutex is released.
        let saved = unsafe { libc::dup(libc::STDERR_FILENO) };
        assert!(saved >= 0, "dup(stderr) failed");
        let redirected = unsafe { libc::dup2(file.as_file().as_raw_fd(), libc::STDERR_FILENO) };
        assert!(redirected >= 0, "dup2(stderr) failed");

        {
            let _restore = Restore(saved);
            f();
            std::fs::read_to_string(file.path()).unwrap_or_default()
        }
    }

    /// L8-1: a panic contained by [`guarded`] must map to `PAM_ABORT` *and* leave the
    /// invoking terminal untouched — the payload goes to syslog, never stderr.
    #[test]
    fn panic_in_guarded_logs_to_syslog_and_not_to_stderr() {
        // Ensure the production syslog hook (not the default stderr hook) is installed.
        logger::install_panic_hook();

        let stderr = capture_stderr(|| {
            let code = guarded("panic-hook-test", || panic!("L8-1 stderr sentinel"));
            assert_eq!(code, PAM_ABORT, "a panic must still map to PAM_ABORT");
        });

        assert!(
            !stderr.contains("L8-1 stderr sentinel") && !stderr.contains("panicked"),
            "the panic payload must not reach stderr, got: {stderr:?}"
        );
    }
}
