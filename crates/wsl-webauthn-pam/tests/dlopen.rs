//! ABI smoke test: `dlopen` the built `libpam_wsl_webauthn.so` and `dlsym` all six
//! `pam_sm_*` symbols.
//!
//! `cargo test` builds the `cdylib` alongside the test binaries (it is a target of the
//! crate), so the artifact is normally present at `target/{debug,release}/deps/` (and
//! at `target/{debug,release}/` after a plain `cargo build`). This test locates it
//! robustly relative to both the running test binary and `CARGO_MANIFEST_DIR`, then:
//!
//! * **runs the real `dlopen`/`dlsym` check** when the artifact is found (always the
//!   case for a normal `cargo test`, locally or in CI);
//! * **skips with a clear, printed reason** only when the artifact is genuinely absent
//!   (e.g. a filtered build that never compiled the cdylib) — *unless*
//!   `WSL_WEBAUTHN_REQUIRE_LIBPAM=1` is set (CI does), in which case a missing artifact
//!   is a hard failure.
//!
//! The check does not depend on `CI`; in CI it runs and must pass. A richer,
//! non-Rust `dlopen` that also *calls* the entry points lives in `tests/c_host.rs`.

#![cfg(target_os = "linux")]

mod gate;

use std::ffi::{CString, c_void};
use std::path::PathBuf;

/// Locate the built cdylib.
///
/// `cargo test` builds the `cdylib` into `target/<profile>/deps/` (next to the test
/// binaries); `cargo build` puts it at `target/<profile>/`. Both are checked, along
/// with the alternate profile, resolved from the running test binary and from
/// `CARGO_MANIFEST_DIR`.
fn locate_library() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        // `target/<profile>/deps/<test>-<hash>`.
        if let Some(deps_dir) = exe.parent() {
            candidates.push(deps_dir.join("libpam_wsl_webauthn.so"));
            if let Some(profile_dir) = deps_dir.parent() {
                candidates.push(profile_dir.join("libpam_wsl_webauthn.so"));
                if let Some(target_dir) = profile_dir.parent() {
                    for profile in ["debug", "release"] {
                        candidates.push(target_dir.join(profile).join("libpam_wsl_webauthn.so"));
                        candidates.push(
                            target_dir
                                .join(profile)
                                .join("deps")
                                .join("libpam_wsl_webauthn.so"),
                        );
                    }
                }
            }
        }
    }

    // Fallback: the workspace target dir relative to this crate (`<ws>/crates/<crate>`).
    if let Some(manifest) = std::env::var_os("CARGO_MANIFEST_DIR") {
        let crate_dir = PathBuf::from(manifest);
        if let Some(workspace) = crate_dir.parent().and_then(|p| p.parent()) {
            for profile in ["debug", "release"] {
                candidates.push(
                    workspace
                        .join("target")
                        .join(profile)
                        .join("libpam_wsl_webauthn.so"),
                );
                candidates.push(
                    workspace
                        .join("target")
                        .join(profile)
                        .join("deps")
                        .join("libpam_wsl_webauthn.so"),
                );
            }
        }
    }

    candidates.into_iter().find(|p| p.exists())
}

#[test]
fn cdylib_exports_all_six_pam_symbols() {
    let Some(lib) = locate_library() else {
        // Genuinely absent (e.g. a filtered build that never compiled the cdylib).
        // Skip with a printed reason, or fail under the CI gate.
        gate::enforce(
            "libpam_wsl_webauthn.so not found; run `cargo build -p wsl-webauthn-pam` \
             (or `make test`) to exercise this ABI check",
        );
        return;
    };

    let path = CString::new(lib.to_string_lossy().as_bytes()).expect("path is a C string");
    // RTLD_NOW (2): resolve everything up front so a missing libpam symbol is caught.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
    assert!(
        !handle.is_null(),
        "dlopen({}) failed: {}",
        lib.display(),
        dlerror_string()
    );

    for symbol in [
        "pam_sm_authenticate",
        "pam_sm_setcred",
        "pam_sm_acct_mgmt",
        "pam_sm_open_session",
        "pam_sm_close_session",
        "pam_sm_chauthtok",
    ] {
        let name = CString::new(symbol).unwrap();
        let ptr = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(!ptr.is_null(), "symbol {symbol} is not exported");
        assert_ne!(ptr as *const c_void, std::ptr::null());
    }

    unsafe {
        libc::dlclose(handle);
    }
}

/// The module installs a process-wide panic hook whose closure lives in this cdylib, so
/// the mapping must survive a host `dlclose`. `build.rs` links it with `-z nodelete`,
/// which sets `DF_1_NODELETE` (GNU ld/lld) and, on older binutils, a `NODELETE` flag on
/// the `FLAGS` line. Strip and thin LTO do not touch dynamic flags.
#[test]
fn cdylib_is_marked_nodelete() {
    let Some(lib) = locate_library() else {
        gate::enforce(
            "libpam_wsl_webauthn.so not found; run `cargo build -p wsl-webauthn-pam` \
             to exercise this link-flag check",
        );
        return;
    };

    let output = match std::process::Command::new("readelf")
        .arg("-d")
        .arg(&lib)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            // readelf is not part of the Rust toolchain; its absence is environmental,
            // not a module defect.
            eprintln!(
                "SKIP: cannot run readelf ({error}); not verifying DF_1_NODELETE on {}",
                lib.display()
            );
            return;
        }
    };
    assert!(
        output.status.success(),
        "readelf -d {} failed: {}",
        lib.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let dynamic = String::from_utf8_lossy(&output.stdout);
    assert!(
        dynamic.contains("NODELETE"),
        "{} must be linked with -z nodelete (DF_1_NODELETE) so the panic hook's code is \
         never unmapped by dlclose; readelf -d said:\n{dynamic}",
        lib.display()
    );
}

fn dlerror_string() -> String {
    unsafe {
        let ptr = libc::dlerror();
        if ptr.is_null() {
            "(no dlerror)".to_string()
        } else {
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}
