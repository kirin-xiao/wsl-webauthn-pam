//! The panic hook must **chain** to the host's hook, not replace it, and must suppress
//! only panics raised inside the module's guarded scope.
//!
//! This is its own test binary on purpose: [`install_panic_hook`] is
//! process-global and once-latched, and this test installs an observable "host" hook
//! *before* the module's install. Running it beside other panic tests in `tests/pam.rs`
//! would race on that global.
//!
//! The previous hook is observed with an `AtomicUsize` rather than stderr: under libtest
//! the default hook reports through the harness's per-thread output capture, not fd 2, so
//! a stderr assertion could not tell "forwarded" from "swallowed".

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};

use support::{FakeSeam, Fixture, PAM_ABORT};

use pam_wsl_webauthn::logger::{begin_capture, captured, install_panic_hook};
use pam_wsl_webauthn::logic::run;

/// syslog `LOG_CRIT`.
const LOG_CRIT: i32 = 2;

/// Counts calls into the hook that was installed before the module's.
static PREVIOUS_HOOK_CALLS: AtomicUsize = AtomicUsize::new(0);

fn foreign_panic_count() -> usize {
    PREVIOUS_HOOK_CALLS.load(Ordering::SeqCst)
}

#[test]
fn panic_hook_chains_to_the_host_hook_and_suppresses_only_its_own_panics() {
    // A "host" hook, installed exactly as a PAM consumer such as sshd would, before the
    // module first installs its own.
    std::panic::set_hook(Box::new(|_info| {
        PREVIOUS_HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
    }));
    // First (and only) install in this process: it must take the hook above as `prev`.
    install_panic_hook();
    begin_capture();

    // (a) A panic from code outside the module's guarded scope is delegated to `prev` and
    // must not be recorded as a `pam_wsl_webauthn` panic.
    let foreign = std::panic::catch_unwind(|| panic!("foreign sentinel"));
    assert!(foreign.is_err(), "the test panic must unwind");
    assert_eq!(
        foreign_panic_count(),
        1,
        "a foreign panic must reach the previous hook"
    );
    assert!(
        captured().is_empty(),
        "a foreign panic must not be logged as a module panic: {:?}",
        captured()
    );

    // (b) A panic inside the guarded call is logged at LOG_CRIT and is *not* forwarded,
    // so its payload can never reach the invoking user's terminal.
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let mut deps = fixture.deps(store, Vec::new());
    deps.panic = true;

    let code = run(&mut seam, &deps, 0, &[]);
    assert_eq!(code, PAM_ABORT, "injected panic must fail closed");
    assert_eq!(
        foreign_panic_count(),
        1,
        "an in-scope module panic must not be forwarded to the host hook"
    );

    let records = captured();
    let hook_records: Vec<_> = records
        .iter()
        .filter(|(priority, msg)| {
            *priority == LOG_CRIT && msg.contains("panic in pam_wsl_webauthn")
        })
        .collect();
    assert_eq!(
        hook_records.len(),
        1,
        "exactly one LOG_CRIT hook record expected, got {records:?}"
    );
    assert!(
        hook_records[0]
            .1
            .contains("injected panic for PAM_ABORT coverage"),
        "the syslog record must carry the panic payload: {:?}",
        hook_records[0].1
    );
}
