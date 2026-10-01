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

use crate::bindings::{self, LOG_AUTHPRIV, LOG_CRIT, LOG_DEBUG, LOG_PID};

static OPENLOG: OnceLock<()> = OnceLock::new();
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);
static PANIC_HOOK: OnceLock<()> = OnceLock::new();

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

/// Render a panic payload and location for the syslog record.
///
/// The location (an absolute source path) is deliberately included: `LOG_AUTHPRIV`
/// records are root-only, so this is the one place the path is safe to record. The
/// point of the hook is that it *never* reaches the invoking user's terminal.
fn describe_panic(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    };
    match info.location() {
        Some(location) => format!("{payload} at {}:{}", location.file(), location.line()),
        None => payload,
    }
}

/// Install the syslog-only panic hook exactly once, before the first `catch_unwind`.
///
/// Without this the *default* hook prints the panic payload and an absolute source
/// path to stderr — for a PAM module that is the invoking user's terminal — before
/// `catch_unwind` maps the panic to `PAM_ABORT`. Replacing the process-wide hook is a
/// one-time, idempotent operation ([`OnceLock`]); it changes only *where* diagnostics
/// go, never the PAM return code that `catch_unwind` produces.
pub fn install_panic_hook() {
    PANIC_HOOK.get_or_init(|| {
        std::panic::set_hook(Box::new(|info| {
            auth(
                LOG_CRIT,
                &format!(
                    "panic in pam_wsl_webauthn: {}; returning PAM_ABORT (fail closed)",
                    describe_panic(info)
                ),
            );
        }));
    });
}

fn ensure_openlog() {
    OPENLOG.get_or_init(|| {
        // SAFETY: `ident` is a `'static` C string and the call is idempotent.
        //
        // `openlog(ident, option, facility)` — the facility is the **third** argument.
        // `LOG_PID` is an *option* bit, not a facility. Passing the facility in the
        // option slot (a classic mistake) leaves the default facility (0) in place, so
        // this module's audit records would be filed under `kern` instead of `authpriv`
        // and would be visible to every unprivileged reader of `syslog`/the journal.
        // Keep the facility where it belongs.
        unsafe {
            bindings::openlog(c"pam_wsl_webauthn".as_ptr(), LOG_PID, LOG_AUTHPRIV);
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
