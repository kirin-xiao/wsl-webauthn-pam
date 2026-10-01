//! syslog-only logging for the PAM module (plan §8).
//!
//! The module must **never** write to stdout (it would corrupt the PAM stack's
//! stdio contract) and must honour `PAM_SILENT` for user-facing output. All
//! diagnostic output therefore goes to `syslog` under `LOG_AUTHPRIV`.
//!
//! `openlog` is called once per process (lazily, guarded by a [`OnceLock`]) rather
//! than once per authentication: the module can be loaded into a long-lived process
//! that authenticates many times, and re-`openlog`ing each time is both wasteful and
//! racy. `closelog` is intentionally never called for the same reason.
//!
//! The message is always passed to libc as a `%s` *argument*, never interpolated into
//! the format string, so attacker-influenced text (a username, a path) cannot perform
//! format-string expansion.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::bindings::{self, LOG_AUTHPRIV, LOG_DEBUG, LOG_PID};

static OPENLOG: OnceLock<()> = OnceLock::new();
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Configure whether [`debug`] emits messages for the lifetime of the process.
///
/// Called once from [`crate::pam_args`] parsing in `pam_sm_authenticate`.
pub fn set_debug(enabled: bool) {
    DEBUG_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Whether debug logging is currently enabled.
pub fn debug_enabled() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
}

fn ensure_openlog() {
    OPENLOG.get_or_init(|| {
        // SAFETY: `ident` is a `'static` C string and the call is idempotent.
        unsafe {
            bindings::openlog(c"pam_wsl_webauthn".as_ptr(), LOG_AUTHPRIV | LOG_PID, 0);
        }
    });
}

/// Emit `msg` at `priority` (a `LOG_*` level, OR-ed with no facility; the facility is
/// fixed by `openlog`).
pub fn auth(priority: i32, msg: &str) {
    ensure_openlog();
    let Ok(c_msg) = CString::new(msg) else {
        // Interior NUL: drop rather than risk a malformed format. This can only happen
        // if an interpolated string contained a NUL, which the callers do not produce.
        return;
    };
    // SAFETY: `%s` is a valid literal format and `c_msg` is a valid C string that
    // outlives the call. libc's `syslog` is not thread-safe, but PAM modules are
    // invoked from a single authentication thread at a time; a data race here could
    // at worst interleave log lines, never affect an authentication decision.
    unsafe {
        bindings::syslog(priority, c"%s".as_ptr(), c_msg.as_ptr());
    }
}

/// Log at `LOG_DEBUG`, but only when the `debug` module argument was supplied.
pub fn debug(msg: &str) {
    if debug_enabled() {
        auth(LOG_DEBUG, msg);
    }
}
