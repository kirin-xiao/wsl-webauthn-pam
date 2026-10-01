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
    // `CString::new` rejects any interior NUL. Dropping the record would let hostile
    // input (e.g. a username embedding NUL) suppress the audit line for its own
    // rejection, so sanitize and log a redacted line instead.
    let c_msg = match CString::new(msg) {
        Ok(c_msg) => c_msg,
        Err(_) => {
            let Ok(sanitized) = CString::new(sanitize_for_syslog(msg)) else {
                return;
            };
            sanitized
        }
    };
    // SAFETY: `%s` is a valid literal format and `c_msg` is a valid C string that
    // outlives the call. libc's `syslog` is not thread-safe, but PAM modules are
    // invoked from a single authentication thread at a time; a data race here could
    // at worst interleave log lines, never affect an authentication decision.
    unsafe {
        bindings::syslog(priority, c"%s".as_ptr(), c_msg.as_ptr());
    }
}

/// Make `msg` representable as a C string without silently losing content.
///
/// Only called when `msg` contains an interior NUL (so it cannot be a `CString`).
/// NUL becomes a visible `\0`; other control characters (which could otherwise inject
/// line breaks or terminal escapes into a log record) become `\u{..}` escapes. Normal
/// text, including newlines and tabs, is left untouched.
fn sanitize_for_syslog(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    for ch in msg.chars() {
        match ch {
            '\0' => out.push_str("\\0"),
            c if c.is_control() && c != '\n' && c != '\r' && c != '\t' => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Log at `LOG_DEBUG`, but only when the `debug` module argument was supplied.
pub fn debug(msg: &str) {
    if debug_enabled() {
        auth(LOG_DEBUG, msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_interior_nul_and_control_bytes() {
        let sanitized = sanitize_for_syslog("user\0name\nnext\x1b[31m");
        assert!(!sanitized.contains('\0'), "NUL must be escaped");
        assert!(sanitized.contains("user\\0name"), "{sanitized}");
        // Newlines are preserved (they are valid in a C string); other controls escape.
        assert!(sanitized.contains("\\u{1b}"), "{sanitized}");
        // The sanitized form is representable as a C string (no interior NUL remains).
        assert!(CString::new(sanitized).is_ok());
    }

    #[test]
    fn auth_with_interior_nul_does_not_panic_or_drop() {
        // Must not panic and must still issue a (redacted) record. We cannot inspect the
        // syslog sink here, but the sanitized path is exercised end to end.
        auth(LOG_DEBUG, "hostile\0username rejected");
    }
}
