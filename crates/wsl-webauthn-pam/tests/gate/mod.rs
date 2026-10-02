//! Shared "require libpam" gate.
//!
//! `tests/dlopen.rs` and `tests/pam_start.rs` would otherwise pass by skipping when
//! the built `.so` could not be located, so a green run did not prove libpam ever
//! loaded the module. CI sets `WSL_WEBAUTHN_REQUIRE_LIBPAM=1`, which turns every such
//! skip into a hard failure; dev boxes leave it unset and still skip.
//!
//! This module has no dependencies beyond `std` so it can be included by the
//! light ABI test as well as the heavier real-libpam tests.

/// Whether the environment demands that the FFI path actually run.
pub fn active() -> bool {
    std::env::var("WSL_WEBAUTHN_REQUIRE_LIBPAM").as_deref() == Ok("1")
}

/// Called from a would-be skip branch.
///
/// Panics when the gate is set (naming the missing prerequisite); otherwise prints
/// a skip notice and returns so the caller can `return`.
pub fn enforce(what: &str) {
    if active() {
        panic!("WSL_WEBAUTHN_REQUIRE_LIBPAM=1 but {what}");
    }
    eprintln!("skipping libpam/ABI test: {what}");
}
