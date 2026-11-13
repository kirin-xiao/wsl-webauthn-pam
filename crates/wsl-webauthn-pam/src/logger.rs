//! syslog-only logging for the PAM module.
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
//! `syslog` itself is serialized by a process-wide mutex: libc does not guarantee it
//! is thread-safe, and a threaded PAM consumer (a display manager, a session broker)
//! may run several `pam_sm_authenticate` calls concurrently.
//!
//! The `debug` verbosity is **per-thread**: a process-global flag would let one
//! service's `debug` argument turn on verbose logging for every concurrent
//! authentication in the same process. A PAM call runs on one thread, so a
//! thread-local flag is the correct scope and needs no locking.
//!
//! The message is always passed to libc as a `%s` *argument*, never interpolated into
//! the format string, so attacker-influenced text (a username, a path) cannot perform
//! format-string expansion.
//!
//! # Test capture
//!
//! Tests must not write synthetic auth events into the real journal, so a process can
//! switch [`auth`] to an in-process recorder ([`enable_capture`], [`begin_capture`], or
//! the [`CAPTURE_ENV`] marker). The switch is runtime rather than a cargo feature because
//! features are unified across every target in one invocation: `cargo test` or
//! `--all-targets` would also compile the capture sink into the shipped `cdylib`. The
//! marker is honoured only outside a privilege transition (`AT_SECURE == 0`), so an
//! unprivileged caller cannot use it to silence a setuid/capability auth helper. It
//! exists for the out-of-process C host in `tests/c_host.rs`, which dlopens the module and
//! cannot call [`enable_capture`] directly.

#![allow(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::ffi::CString;
#[cfg(not(test))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::bindings::{self, LOG_AUTHPRIV, LOG_CRIT, LOG_DEBUG, LOG_PID};

/// Environment marker that opts a process into the in-process recorder at first use.
///
/// Test-only; ignored under a privilege transition (see [`capture_active`]). Exposed so
/// the out-of-process C host in `tests/c_host.rs` can keep the real journal clean.
#[doc(hidden)]
pub const CAPTURE_ENV: &str = "WSL_WEBAUTHN_TEST_CAPTURE";

/// Whether this process has switched its audit output to the in-process recorder.
///
/// Absent under `cfg(test)`, where capture is always on. Production never sets it.
#[cfg(not(test))]
static CAPTURE_MODE: AtomicBool = AtomicBool::new(false);
/// Runs the one-time env-marker check exactly once, without ever clearing the flag.
#[cfg(not(test))]
static CAPTURE_INIT: OnceLock<()> = OnceLock::new();

static OPENLOG: OnceLock<()> = OnceLock::new();
static PANIC_HOOK: OnceLock<()> = OnceLock::new();
/// Serializes the non-thread-safe `syslog(3)` call across concurrent PAM calls.
static SYSLOG_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    /// Whether *this thread's* authentication emitted `debug`.
    static DEBUG_ENABLED: Cell<bool> = const { Cell::new(false) };
    /// `Some(records)` while this thread records its audit output in-process instead of
    /// calling `syslog(3)`.
    static CAPTURED: RefCell<Option<Vec<(i32, String)>>> = const { RefCell::new(None) };
    /// Nesting depth of [`enter_module_scope`] on this thread.
    ///
    /// A counter rather than a flag because `guarded` wraps `run`, which has its own
    /// `catch_unwind`: both enter the scope, so the inner guard must not clear the
    /// outer one. A thread that never entered a guard reads `0`.
    static MODULE_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// RAII marker for "this thread is inside one of the module's guarded calls".
///
/// Dropped on both the normal and the unwind path, so the depth returns to its previous
/// value even when the guarded body panics. See [`install_panic_hook`] for why the panic
/// hook needs this scope.
pub(crate) struct ModuleScope(());

impl Drop for ModuleScope {
    fn drop(&mut self) {
        // `try_with`, not `with`: this guard may be dropped during TLS teardown, where
        // accessing the thread-local would panic.
        let _ = MODULE_DEPTH.try_with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Enter the module's guarded region on this thread, returning a guard that leaves it on
/// drop.
///
/// Called immediately around each `catch_unwind` in the exported path (`guarded` in
/// `lib.rs` and `run` in `logic.rs`). Every panic raised between [`enter_module_scope`]
/// and the guard's drop is attributed to this module by [`install_panic_hook`].
pub(crate) fn enter_module_scope() -> ModuleScope {
    MODULE_DEPTH.with(|depth| depth.set(depth.get() + 1));
    ModuleScope(())
}

/// Whether this thread is currently inside one of the module's guarded calls.
///
/// Panic-safe: during TLS destruction (or if the local was already destroyed)
/// `try_with` fails and this reports `false`, so such a panic is chained to the previous
/// hook instead of re-entering [`auth`] and its `CAPTURED` thread-local.
fn in_module_scope() -> bool {
    MODULE_DEPTH
        .try_with(|depth| depth.get() > 0)
        .unwrap_or(false)
}

/// Configure whether [`debug`] emits messages for the current authentication thread.
///
/// Called from [`crate::args::parse`] via `run` in `pam_sm_authenticate`. Because the
/// flag is thread-local, a second concurrent authentication on another thread is
/// unaffected.
pub fn set_debug(enabled: bool) {
    DEBUG_ENABLED.with(|d| d.set(enabled));
}

/// Whether debug logging is currently enabled on this thread.
pub fn debug_enabled() -> bool {
    DEBUG_ENABLED.with(Cell::get)
}

/// Whether [`auth`] should record in-process rather than call `syslog(3)`.
///
/// Always true under `cfg(test)`; otherwise it follows [`enable_capture`] or the
/// first-use [`CAPTURE_ENV`] marker. Production does neither, so this is false in any
/// shipped artifact.
fn capture_active() -> bool {
    #[cfg(test)]
    {
        true
    }
    #[cfg(not(test))]
    {
        CAPTURE_INIT.get_or_init(|| {
            let requested = std::env::var_os(CAPTURE_ENV).is_some_and(|v| v == "1");
            if env_requests_capture(requested, privilege_transition()) {
                CAPTURE_MODE.store(true, Ordering::Relaxed);
            }
        });
        CAPTURE_MODE.load(Ordering::Relaxed)
    }
}

/// Whether the [`CAPTURE_ENV`] marker should switch this process to the recorder.
///
/// Never under a privilege transition: a setuid/capability `su`/`passwd` that inherited an
/// attacker-controlled environment must keep auditing. Split out so the policy is
/// unit-testable without forging `AT_SECURE`.
fn env_requests_capture(env_requested: bool, privileged: bool) -> bool {
    env_requested && !privileged
}

/// Whether the process gained privileges at exec (`AT_SECURE`), e.g. a setuid binary or
/// one with file capabilities.
#[cfg(not(test))]
fn privilege_transition() -> bool {
    // SAFETY: `getauxval` takes only an integer key and returns an integer; it has no
    // pointer arguments and cannot violate memory safety.
    unsafe { libc::getauxval(libc::AT_SECURE) != 0 }
}

/// Switch this **process** to the in-process audit recorder.
///
/// Intended for test binaries, which must not pollute the real auth journal. Idempotent
/// and process-wide; production code never calls it.
#[doc(hidden)]
pub fn enable_capture() {
    #[cfg(not(test))]
    {
        CAPTURE_INIT.get_or_init(|| {});
        CAPTURE_MODE.store(true, Ordering::Relaxed);
    }
}

/// Start a fresh thread-local capture buffer **and** enable capture for this process.
///
/// The single entry a non-test binary needs: it enables capture (as [`enable_capture`])
/// and clears this thread's buffer. Safe to call repeatedly.
#[doc(hidden)]
pub fn begin_capture() {
    enable_capture();
    CAPTURED.with(|c| *c.borrow_mut() = Some(Vec::new()));
}

/// Return the audit records captured on this thread since [`begin_capture`].
///
/// Returns an empty vector when this thread is not capturing.
#[doc(hidden)]
#[must_use]
pub fn captured() -> Vec<(i32, String)> {
    CAPTURED.with(|c| c.borrow().clone().unwrap_or_default())
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

/// Install the module's syslog-only panic hook, chained in front of the host's hook,
/// exactly once.
///
/// Without a hook the *default* hook prints the panic payload and an absolute source
/// path to stderr — for a PAM module that is the invoking user's terminal — before
/// `catch_unwind` maps the panic to `PAM_ABORT`.
///
/// # Chaining, not clobbering
///
/// A `cdylib` is loaded into a host (sshd, sudo, a display manager) that may have its
/// own panic hook for its own diagnostics. On first install this takes the current hook
/// with [`std::panic::take_hook`] and installs a hook that:
///
/// * for a panic **belonging to this module**, logs at `LOG_CRIT` and deliberately does
///   **not** call the previous hook, so the payload never reaches the invoking user's
///   terminal (the security property this hook exists for); and
/// * for **every other panic**, calls the previous hook with the original
///   [`std::panic::PanicHookInfo`], so the host keeps its diagnostics and unrelated
///   panics are no longer misattributed to `pam_wsl_webauthn` in `authpriv`.
///
/// The consequence of chaining is that a host hook does not see panics this module
/// suppresses inside its own scope. That suppression is intentional.
///
/// # Ownership discrimination
///
/// Ownership is decided by a per-thread depth counter, [`enter_module_scope`], entered
/// immediately around the `catch_unwind` in `guarded` (`lib.rs`) and in `run`
/// (`logic.rs`). A panic raised by std code called from our logic (a slice index, an
/// allocation failure in `raw_vec`, a `fmt` panic) has a std `location().file()` but is
/// still ours, so a path-prefix test would misclassify it and forward our payload to the
/// terminal. The same test would also misclassify panics from this workspace's
/// `wsl-webauthn-{store,runner,verifier}` crates (module code, different file paths) as
/// foreign. The scope, by contrast, is exactly the region whose panics we contain.
///
/// A panic on another thread while a guarded call is in flight reads depth `0` there and
/// is chained to the previous hook: it is not contained by our `catch_unwind` and is
/// therefore not ours to suppress. Panics raised on this thread outside the scope (a
/// libtest assertion in a test binary, for instance) are likewise forwarded.
///
/// # Lifetime: the hook must never be unmapped
///
/// The installed closure's code lives in this `cdylib`. If libpam or the host
/// `dlclose`s the module, the process-wide hook would still hold a pointer into unmapped
/// text and a later panic would call a stale vtable (undefined behavior). `build.rs`
/// therefore links the cdylib with `-Wl,-z,nodelete`, which sets `DF_1_NODELETE` and
/// keeps the mapping resident for the life of the process. Without that flag this hook
/// is unsound; see `build.rs`.
///
/// # Host hook installed later
///
/// Installation is latched by [`OnceLock`]: if the host calls
/// [`std::panic::set_hook`] *after* the first authentication, the host's hook replaces
/// this one and the terminal guarantee lapses for subsequent panics. There is no stable
/// API to observe that a hook was replaced, and re-installing on every call would
/// either clobber the host's hook or chain this module to itself. The module installs
/// once, before its first guarded call; a host that takes over the hook owns that
/// decision.
///
/// This changes only *where* diagnostics go, never the PAM return code that
/// `catch_unwind` produces.
pub fn install_panic_hook() {
    PANIC_HOOK.get_or_init(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(chained_hook(prev));
    });
}

/// The previous process panic hook, as returned by [`std::panic::take_hook`].
type PrevHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>;

/// Build the hook installed by [`install_panic_hook`]: log module-owned panics, delegate
/// everything else to `prev`.
///
/// Split out from the [`OnceLock`] wrapper so the ownership predicate and the chaining
/// can be reasoned about (and exercised) without needing to install a process-global hook.
fn chained_hook(prev: PrevHook) -> PrevHook {
    Box::new(move |info| {
        if in_module_scope() {
            auth(
                LOG_CRIT,
                &format!(
                    "panic in pam_wsl_webauthn: {}; returning PAM_ABORT (fail closed)",
                    describe_panic(info)
                ),
            );
        } else {
            prev(info);
        }
    })
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
    // A test process may have opted into the in-process recorder; capture on this thread
    // and skip `syslog` entirely.
    if capture_active() {
        CAPTURED.with(|c| {
            if let Some(records) = c.borrow_mut().as_mut() {
                records.push((priority, msg.to_string()));
            }
        });
        return;
    }

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
    // Serialize the non-thread-safe libc `syslog` call. A poisoned lock still lets
    // us log (recover the guard) rather than silently dropping an audit record.
    let _guard = SYSLOG_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: `%s` is a valid literal format and `c_msg` is a valid C string that
    // outlives the call.
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
    use crate::bindings::LOG_ERR;

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
        // The production sanitizer is exercised directly above. Here we assert the
        // capture path still records the hostile message (so it is not silently
        // dropped) and that `CString::new` really does reject it — which is what makes
        // production take the sanitize branch.
        assert!(CString::new("hostile\0username rejected").is_err());
        begin_capture();
        auth(LOG_ERR, "hostile\0username rejected");
        let records = captured();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, LOG_ERR);
        assert!(records[0].1.contains("hostile\0username"));
    }

    /// The `debug` flag is per-thread, so enabling it for one thread must not change
    /// another thread's verbosity.
    #[test]
    fn debug_flag_is_per_thread() {
        set_debug(false);
        assert!(!debug_enabled());
        begin_capture();
        debug("suppressed");

        let other = std::thread::spawn(|| {
            set_debug(true);
            assert!(debug_enabled());
            begin_capture();
            debug("enabled elsewhere");
            captured()
        });
        let other_records = other.join().unwrap();

        // This thread stays at its own (false) setting; it captured nothing.
        debug("still suppressed");
        assert!(captured().is_empty(), "debug=false must capture nothing");
        assert_eq!(other_records.len(), 1, "debug=true on the other thread");
        assert_eq!(other_records[0].1, "enabled elsewhere");
        assert!(!debug_enabled(), "this thread is unchanged");
    }

    /// The env marker must never switch a privileged process to the recorder, or a
    /// setuid/capability auth helper with an attacker-influenced environment could stop
    /// auditing.
    #[test]
    fn env_marker_is_ignored_under_a_privilege_transition() {
        assert!(
            env_requests_capture(true, false),
            "plain process may opt in"
        );
        assert!(
            !env_requests_capture(true, true),
            "a privilege transition must keep auditing"
        );
        assert!(!env_requests_capture(false, false), "no marker, no capture");
    }

    /// The panic-ownership scope is a counter, so `run` (which is itself inside
    /// `guarded`) can enter it again without the inner guard clearing the outer one, and
    /// it is per-thread so a concurrent authentication is not misattributed.
    #[test]
    fn module_scope_nests_and_is_thread_local() {
        assert!(
            !in_module_scope(),
            "a fresh thread starts outside the scope"
        );

        let outer = enter_module_scope();
        assert!(in_module_scope());

        let inner = enter_module_scope();
        drop(inner);
        assert!(
            in_module_scope(),
            "dropping the inner guard must not clear the outer scope"
        );

        drop(outer);
        assert!(!in_module_scope());

        let other = std::thread::spawn(in_module_scope);
        assert!(
            !other.join().unwrap(),
            "another thread's panics are not ours to suppress"
        );
    }

    /// A thread that never called [`begin_capture`] has no thread-local buffer, so
    /// [`captured`] is empty even though unit tests are always in capture mode.
    #[test]
    fn captured_is_empty_without_begin_capture() {
        let other = std::thread::spawn(|| {
            auth(LOG_ERR, "recorded in-process, but no buffer on this thread");
            assert!(captured().is_empty(), "no buffer unless begin_capture ran");
        });
        other.join().unwrap();
    }
}
