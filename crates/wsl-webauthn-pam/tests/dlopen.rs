//! ABI smoke test: `dlopen` the built `libpam_wsl_webauthn.so` and `dlsym` all six
//! `pam_sm_*` symbols (plan §8, §12.4).
//!
//! This test needs the `cdylib` artifact to already exist. `cargo test` builds
//! `rlib`/test binaries but **not** the neighbouring `cdylib`, so this test locates
//! `target/{debug,release}/libpam_wsl_webauthn.so` relative to this crate and:
//!
//! * **fails** when running in CI (`CI=true`), because the release gates build the
//!   library first (`cargo build -p wsl-webauthn-pam --locked`, or `make test`);
//! * **skips with a clear message** otherwise, so a bare `cargo test` on a developer
//!   machine does not fail for a missing artifact.
//!
//! `make test` and CI both build the `cdylib` before testing, so the real check runs.

#![cfg(target_os = "linux")]

use std::ffi::{CString, c_void};
use std::path::PathBuf;

/// Locate the built cdylib.
///
/// `cargo test` builds the `cdylib` into `target/<profile>/deps/` (next to the test
/// binaries); `cargo build` puts it at `target/<profile>/`. Both are checked, along
/// with the alternate profile.
fn locate_library() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // `target/<profile>/deps/<test>-<hash>`.
    let deps_dir = exe.parent()?;
    let profile_dir = deps_dir.parent()?;
    let target_dir = profile_dir.parent()?;

    let mut candidates = Vec::new();
    // `cargo test` location.
    candidates.push(deps_dir.join("libpam_wsl_webauthn.so"));
    // `cargo build` location, current profile then the other.
    candidates.push(profile_dir.join("libpam_wsl_webauthn.so"));
    for profile in ["debug", "release"] {
        candidates.push(target_dir.join(profile).join("libpam_wsl_webauthn.so"));
        candidates.push(
            target_dir
                .join(profile)
                .join("deps")
                .join("libpam_wsl_webauthn.so"),
        );
    }
    candidates.into_iter().find(|p| p.exists())
}

#[test]
fn cdylib_exports_all_six_pam_symbols() {
    let Some(lib) = locate_library() else {
        let msg = "libpam_wsl_webauthn.so not found; run `cargo build -p wsl-webauthn-pam` \
                   (or `make test`) before this test";
        if std::env::var_os("CI").is_some() {
            panic!("{msg}");
        }
        eprintln!("skipping dlopen test: {msg}");
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
