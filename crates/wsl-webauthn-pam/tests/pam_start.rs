//! End-to-end integration through a **real libpam**.
//!
//! The unit/suite tests in `tests/pam.rs` drive the state machine through the
//! [`pam_wsl_webauthn::seam::PamSeam`] abstraction. This test instead lets the real
//! `libpam` load the built `pam_wsl_webauthn.so` and calls it exactly as `sudo`/`su`
//! would, so the genuine FFI path is exercised:
//!
//! * `pam_sm_authenticate` is reached through `dlopen`/`dlsym` by libpam itself;
//! * `pam_get_user` returns the account libpam was started with;
//! * the production `SystemDeps` (`Store::system()` at `/etc/wsl_webauthn`) runs;
//! * `pam_fail_delay` and `syslog` are invoked through the real library;
//! * the `catch_unwind` boundary and the returned PAM code are observed end to end.
//!
//! Linux-PAM ≥ 1.4 provides `pam_start_confdir`, which reads the service file from an
//! arbitrary directory, so no writes to `/etc/pam.d` and no root are needed. A minimal
//! config dir is written to a tempdir containing one line pointing at the just-built
//! `.so`.
//!
//! On a machine without `/etc/wsl_webauthn/config` (any CI runner, and a fresh dev
//! box) the module must therefore fail **closed** with `PAM_AUTHINFO_UNAVAIL` (config
//! missing) or `PAM_USER_UNKNOWN` (no record). That is the assertion below. The
//! conversation pre-prompt and `pam_get_item(PAM_CONV)` are only reached after a
//! successful config+record load, so they cannot be exercised without a root-owned
//! `/etc/wsl_webauthn`; `tests/pam.rs` covers those through the seam.

#![cfg(target_os = "linux")]

mod gate;
mod support;

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::PathBuf;
use std::sync::Mutex;

use support::{PAM_ABORT, PAM_AUTHINFO_UNAVAIL, PAM_SUCCESS, PAM_USER_UNKNOWN};
use support::{pam_conv, pam_handle_t, pam_message, pam_response};

// ---------------------------------------------------------------------------
// libpam application-side API (not needed by the module itself, so declared here)
// ---------------------------------------------------------------------------

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start_confdir(
        service_name: *const c_char,
        user: *const c_char,
        pam_conversation: *const pam_conv,
        confdir: *const c_char,
        pamh: *mut *mut pam_handle_t,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut pam_handle_t, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut pam_handle_t, pam_status: c_int) -> c_int;
    fn pam_strerror(pamh: *mut pam_handle_t, errnum: c_int) -> *const c_char;
}

/// Conversation messages observed by the stub, across the whole test binary.
static CONV_MESSAGES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// A minimal PAM conversation: accept/record info messages, never prompt.
///
/// The module only ever emits `PAM_TEXT_INFO` on the paths this test can reach, so
/// returning no response struct is correct.
unsafe extern "C" fn conversation(
    num_msg: c_int,
    msg: *mut *const pam_message,
    resp: *mut *mut pam_response,
    _appdata_ptr: *mut c_void,
) -> c_int {
    if !resp.is_null() {
        // SAFETY: libpam handed us a writable `struct pam_response **`.
        unsafe { *resp = std::ptr::null_mut() };
    }
    if !msg.is_null() && num_msg > 0 {
        for i in 0..num_msg as isize {
            // SAFETY: libpam guarantees `num_msg` valid message pointers.
            let m = unsafe { *msg.offset(i) };
            if m.is_null() {
                continue;
            }
            // SAFETY: the message is valid for the duration of the call.
            let style = unsafe { (*m).msg_style };
            let text = if unsafe { (*m).msg }.is_null() {
                String::new()
            } else {
                // SAFETY: `msg` is a NUL-terminated C string.
                unsafe { CStr::from_ptr((*m).msg) }
                    .to_string_lossy()
                    .into_owned()
            };
            if let Ok(mut v) = CONV_MESSAGES.lock() {
                v.push(format!("style={style}: {text}"));
            }
        }
    }
    PAM_SUCCESS
}

/// Locate the built cdylib (mirrors `tests/dlopen.rs`; no `CI` dependence).
fn locate_library() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(deps_dir) = exe.parent()
    {
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

fn strerror(pamh: *mut pam_handle_t, rc: c_int) -> String {
    // SAFETY: `pamh` is a live handle from `pam_start_confdir`.
    let p = unsafe { pam_strerror(pamh, rc) };
    if p.is_null() {
        return format!("rc {rc}");
    }
    // SAFETY: `pam_strerror` returns a static NUL-terminated string.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[test]
fn real_libpam_loads_module_and_fails_closed() {
    let Some(lib) = locate_library() else {
        // Dev boxes may not have built the cdylib; CI sets the gate and must fail.
        // The provisioned success/deny/conversation path through libpam is covered
        // by `tests/c_host.rs` (which needs a namespace and a scripted bridge).
        gate::enforce(
            "libpam_wsl_webauthn.so not found; run `cargo build -p wsl-webauthn-pam` first",
        );
        return;
    };

    // A private PAM config dir with a single service file pointing at the built module.
    let confdir = tempfile::TempDir::new().expect("tempdir");
    let service = "pam_wsl_webauthn_selftest";
    let service_file = confdir.path().join(service);
    std::fs::write(&service_file, format!("auth required {}\n", lib.display()))
        .expect("write service file");

    let service_c = CString::new(service).unwrap();
    let user_c = CString::new("alice").unwrap();
    let confdir_c = CString::new(confdir.path().to_str().unwrap()).unwrap();
    let conv = pam_conv {
        conv: Some(conversation),
        appdata_ptr: std::ptr::null_mut(),
    };
    let mut pamh: *mut pam_handle_t = std::ptr::null_mut();

    // SAFETY: all pointers are valid C strings / a valid `pam_conv`; `pamh` is writable.
    let start = unsafe {
        pam_start_confdir(
            service_c.as_ptr(),
            user_c.as_ptr(),
            &conv,
            confdir_c.as_ptr(),
            &mut pamh,
        )
    };
    assert_eq!(
        start,
        PAM_SUCCESS,
        "pam_start_confdir failed: {start} ({}); service file {}",
        if pamh.is_null() {
            "no handle".to_string()
        } else {
            strerror(pamh, start)
        },
        service_file.display()
    );
    assert!(!pamh.is_null(), "pam_start_confdir returned no handle");

    // SAFETY: `pamh` is a live handle.
    let auth = unsafe { pam_authenticate(pamh, 0) };
    let provisioned = std::path::Path::new("/etc/wsl_webauthn/config").exists();
    assert_ne!(
        auth, PAM_SUCCESS,
        "must be fail-closed when the store is absent"
    );
    assert_ne!(
        auth,
        PAM_ABORT,
        "module must not abort: {}",
        strerror(pamh, auth)
    );
    if !provisioned {
        assert!(
            auth == PAM_AUTHINFO_UNAVAIL || auth == PAM_USER_UNKNOWN,
            "expected a fail-closed code, got {auth}: {}",
            strerror(pamh, auth)
        );
    }

    // `pam_setcred` after a *failed* authentication is short-circuited by libpam
    // itself to `PAM_PERM_DENIED` before any module runs (verified against a trivial
    // sentinel module), so it cannot be observed here. The module's own
    // `pam_sm_setcred` → `PAM_SUCCESS` contract is asserted directly (and without a
    // live stack) in `tests/pam.rs::non_auth_exports_return_expected_codes`.

    // SAFETY: `pamh` is a live handle and is consumed by `pam_end`.
    let end = unsafe { pam_end(pamh, auth) };
    assert_eq!(end, PAM_SUCCESS, "pam_end failed: {end}");
}
