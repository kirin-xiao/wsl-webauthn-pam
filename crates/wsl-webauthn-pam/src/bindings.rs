//! Hand-rolled Linux-PAM FFI bindings (plan §8).
//!
//! No `bindgen`, no `libclang`: the handful of types and constants the module needs
//! are declared here faithfully to `<security/_pam_types.h>` and
//! `<security/pam_modules.h>`. Layout is pinned by unit tests using
//! [`std::mem::offset_of!`] and [`std::mem::size_of`], so a wrong declaration fails
//! the test suite rather than corrupting a live PAM stack.
//!
//! Everything the module touches lives behind a *seam* (see [`crate::seam`]): the
//! production implementation in this file is a thin wrapper over libpam, while the
//! unit tests substitute a `#[cfg(test)]` fake. This keeps the unsafe surface tiny
//! and the authentication logic fully testable without a live PAM application.
//!
//! `#[link(name = "pam")]` is link-time only; CI provides `libpam0g-dev`.

#![allow(non_camel_case_types)]
#![allow(unsafe_code)]
// This module deliberately mirrors the full slice of `<security/pam_*.h>` the
// module *could* use, not only the entries the current source calls: a constant
// such as `PAM_ERROR_MSG` documents the ABI even when only a cfg(test) layout
// check touches it. Now that the module is `pub(crate)` (L6-7) those entries are
// no longer externally reachable, so silence the resulting dead-code warnings
// rather than deleting the ABI mirror.
#![allow(dead_code)]

use std::ffi::{CStr, c_char, c_int, c_void};

/// Opaque PAM handle (`typedef struct pam_handle pam_handle_t;`).
///
/// Only ever held behind a pointer; the module never inspects its layout.
#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
}

// ---------------------------------------------------------------------------
// Return codes (`<security/_pam_types.h>`)
// ---------------------------------------------------------------------------

/// Successful function return.
pub const PAM_SUCCESS: c_int = 0;
/// Authentication failure.
pub const PAM_AUTH_ERR: c_int = 7;
/// Underlying authentication service cannot retrieve authentication information.
pub const PAM_AUTHINFO_UNAVAIL: c_int = 9;
/// User not known to the underlying authentication module.
pub const PAM_USER_UNKNOWN: c_int = 10;
/// Ignore the underlying module regardless of the control flag.
pub const PAM_IGNORE: c_int = 25;
/// Critical error (module failure).
pub const PAM_ABORT: c_int = 26;

// ---------------------------------------------------------------------------
// Flags and items (`<security/_pam_types.h>`)
// ---------------------------------------------------------------------------

/// Authentication service should not generate any messages.
pub const PAM_SILENT: c_int = 0x8000;
/// `pam_get_item` item: the service name.
pub const PAM_SERVICE: c_int = 1;
/// `pam_get_item` item: the user name.
pub const PAM_USER: c_int = 2;
/// `pam_get_item` item: the [`pam_conv`] structure.
pub const PAM_CONV: c_int = 5;

// ---------------------------------------------------------------------------
// Conversation structures (`<security/_pam_types.h>`)
// ---------------------------------------------------------------------------

/// Message style: `PAM_TEXT_INFO` (informatory text, no reply expected).
pub const PAM_TEXT_INFO: c_int = 4;
/// Message style: `PAM_ERROR_MSG`.
pub const PAM_ERROR_MSG: c_int = 3;

/// A message passed to the application's conversation function.
///
/// `msg` is a NUL-terminated C string owned by the caller for the duration of the
/// conversation call.
#[repr(C)]
pub struct pam_message {
    /// One of the `PAM_*_MSG` / prompt styles.
    pub msg_style: c_int,
    /// The message text (NUL-terminated).
    pub msg: *const c_char,
}

/// The application's reply to a [`pam_message`].
///
/// `resp` is a heap-allocated C string the *callee* (this module, on the
/// allocation side) transfers ownership of to libpam. For an info/error message no
/// reply is expected, so the module passes a null response pointer.
#[repr(C)]
pub struct pam_response {
    /// The reply text (NUL-terminated), or null when none is expected.
    pub resp: *mut c_char,
    /// Return code; unused, zero expected (libpam convention).
    pub resp_retcode: c_int,
}

/// The application conversation function and its opaque application data.
#[repr(C)]
pub struct pam_conv {
    /// The callback libpam invokes to talk to the user.
    pub conv: Option<
        unsafe extern "C" fn(
            num_msg: c_int,
            msg: *mut *const pam_message,
            resp: *mut *mut pam_response,
            appdata_ptr: *mut c_void,
        ) -> c_int,
    >,
    /// Opaque pointer passed back to [`pam_conv::conv`].
    pub appdata_ptr: *mut c_void,
}

// ---------------------------------------------------------------------------
// libpam functions used by the production seam
// ---------------------------------------------------------------------------

// `#[link(name = "pam")]` is link-time only (plan §8): it records a `DT_NEEDED`
// entry so the `.so` resolves these symbols even when loaded into a process that has
// not itself already pulled in libpam. CI provides `libpam0g-dev`.
#[link(name = "pam")]
unsafe extern "C" {
    /// Retrieve the username associated with `pamh`.
    pub fn pam_get_user(
        pamh: *mut pam_handle_t,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    /// Retrieve a PAM item (e.g. [`PAM_SERVICE`], [`PAM_CONV`]).
    pub fn pam_get_item(
        pamh: *const pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;
    /// Request a delay on failures (plan §3, CR-14).
    pub fn pam_fail_delay(pamh: *mut pam_handle_t, musec_delay: u32) -> c_int;
}

// ---------------------------------------------------------------------------
// syslog (`<syslog.h>`)
// ---------------------------------------------------------------------------

/// Security/authorization messages (private facility).
pub const LOG_AUTHPRIV: c_int = 10 << 3;
/// Log the PID with each message.
pub const LOG_PID: c_int = 0x01;
/// Critical conditions.
pub const LOG_CRIT: c_int = 2;
/// Error conditions.
pub const LOG_ERR: c_int = 3;
/// Warning conditions.
pub const LOG_WARNING: c_int = 4;
/// Normal but significant condition.
pub const LOG_NOTICE: c_int = 5;
/// Informational.
pub const LOG_INFO: c_int = 6;
/// Debug-level messages.
pub const LOG_DEBUG: c_int = 7;

unsafe extern "C" {
    /// Open a connection to the system logger.
    pub fn openlog(ident: *const c_char, option: c_int, facility: c_int);
    /// Write a message to the system logger.
    pub fn syslog(priority: c_int, format: *const c_char, ...);
    /// Close the connection to the system logger.
    pub fn closelog();
}

/// Read a `*const c_char` as a `&str`, returning `None` for null or non-UTF-8.
///
/// # Safety
///
/// `ptr` must be null or point at a valid NUL-terminated C string.
pub unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a valid NUL-terminated string.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn pam_message_layout() {
        assert_eq!(size_of::<pam_message>(), 16);
        assert_eq!(offset_of!(pam_message, msg_style), 0);
        assert_eq!(offset_of!(pam_message, msg), 8);
    }

    #[test]
    fn pam_response_layout() {
        // `char *resp` (8) + `int resp_retcode` (4) + 4 padding.
        assert_eq!(size_of::<pam_response>(), 16);
        assert_eq!(offset_of!(pam_response, resp), 0);
        assert_eq!(offset_of!(pam_response, resp_retcode), 8);
    }

    #[test]
    fn pam_conv_layout() {
        assert_eq!(size_of::<pam_conv>(), 16);
        assert_eq!(offset_of!(pam_conv, conv), 0);
        assert_eq!(offset_of!(pam_conv, appdata_ptr), 8);
    }

    #[test]
    fn constants_match_linux_pam() {
        assert_eq!(PAM_SUCCESS, 0);
        assert_eq!(PAM_AUTH_ERR, 7);
        assert_eq!(PAM_AUTHINFO_UNAVAIL, 9);
        assert_eq!(PAM_USER_UNKNOWN, 10);
        assert_eq!(PAM_IGNORE, 25);
        assert_eq!(PAM_ABORT, 26);
        assert_eq!(PAM_SILENT, 0x8000);
        assert_eq!(PAM_SERVICE, 1);
        assert_eq!(PAM_USER, 2);
        assert_eq!(PAM_CONV, 5);
        assert_eq!(PAM_TEXT_INFO, 4);
        assert_eq!(PAM_ERROR_MSG, 3);
        assert_eq!(LOG_AUTHPRIV, 80);
        assert_eq!(LOG_PID, 1);
        assert_eq!(LOG_CRIT, 2);
        assert_eq!(LOG_ERR, 3);
        assert_eq!(LOG_WARNING, 4);
        assert_eq!(LOG_NOTICE, 5);
        assert_eq!(LOG_INFO, 6);
        assert_eq!(LOG_DEBUG, 7);
    }
}
