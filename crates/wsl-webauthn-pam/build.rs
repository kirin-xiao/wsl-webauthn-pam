//! Link the `pam_wsl_webauthn` cdylib with `DF_1_NODELETE`.
//!
//! The module installs a process-wide panic hook (see `src/logger.rs`,
//! `install_panic_hook`) whose closure is compiled into this cdylib. A host that loads the module with `dlopen` (libpam, via sshd, sudo, or a
//! display manager) may `dlclose` it when the PAM transaction ends, and PAM applications
//! do. If that unloads the mapping, the hook — still registered in the process — holds a
//! pointer into unmapped text, and the next panic anywhere in the host calls a stale
//! vtable: undefined behavior.
//!
//! `-Wl,-z,nodelete` sets `DF_1_NODELETE` on the shared object, so the dynamic loader
//! never unmaps it even after the last `dlclose`. That is mandatory, not an
//! optimization: without it the hook's lifetime is unsound.
//!
//! Scope: `rustc-cdylib-link-arg` applies only to the `cdylib` target, not to this
//! package's test binaries or the `pam-test-fake-bridge` bin (which either link the rlib
//! statically or never install the hook). It is emitted on Linux only; the project
//! targets glibc Linux (declared 2.31 floor), whose GNU ld and lld both understand
//! `-z nodelete`. `strip` and `lto` do not touch `DT_FLAGS_1`, so release builds keep the
//! flag.

fn main() {
    // The build script runs on the host, so consult the target, not the host, OS.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-z,nodelete");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
