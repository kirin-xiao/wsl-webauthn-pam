//! The seam between the real PAM FFI and the authentication logic.
//!
//! [`PamSeam`] abstracts the handful of libpam calls the module makes (user name,
//! service name, conversation, fail delay). Production uses [`RealPamSeam`], a thin
//! wrapper over libpam. The unit tests implement the same trait with a fake, so the
//! entire authentication state machine is exercised without a live PAM application
//! and without the global system state the real store/runner would touch.
//!
//! A `pam_start` harness would need a real PAM service, a real store under
//! `/etc/wsl_webauthn`, and a real interop child — none of which belong in a
//! hermetic unit test.

#![allow(unsafe_code)]

use std::ffi::{CString, c_int, c_void};

use crate::bindings::{
    self, PAM_CONV, PAM_SERVICE, pam_conv, pam_handle_t, pam_message, pam_response,
};

/// A failure from a seam operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeamError {
    /// `pam_get_user` returned a non-success code.
    GetUser(c_int),
    /// `pam_get_user` succeeded but reported a null/absent user name.
    NullUser,
    /// `pam_get_item(PAM_CONV)` failed, the item was null, or no callback is set.
    NoConv,
    /// A conversation callback returned a non-success code.
    Conv(c_int),
    /// The message text could not be represented as a C string (interior NUL).
    InteriorNul,
}

/// The libpam operations the module needs.
///
/// Methods take `&mut self` so the fake can record calls (fail delay, messages).
pub trait PamSeam {
    /// Return the login name for the PAM handle.
    fn get_user_name(&mut self) -> Result<String, SeamError>;

    /// Return the PAM service name (`sudo`, `su`, …), if available.
    fn get_service(&mut self) -> Option<String>;

    /// Whether a usable conversation callback is installed.
    fn conv_available(&mut self) -> bool;

    /// Send an info/error message to the application, if a conversation exists.
    ///
    /// A missing conversation is [`SeamError::NoConv`]; the caller treats that as a
    /// non-fatal "cannot prompt" (never fail on conv failure).
    fn conv_text(&mut self, style: c_int, text: &str) -> Result<(), SeamError>;

    /// Request a failure delay via `pam_fail_delay`.
    fn fail_delay(&mut self, usec: u32);
}

/// The production seam: thin wrappers over libpam for one `pam_handle_t`.
pub struct RealPamSeam {
    pamh: *mut pam_handle_t,
}

impl RealPamSeam {
    /// Wrap a live `pam_handle_t` pointer.
    ///
    /// # Safety
    ///
    /// `pamh` must be a valid handle for the duration of the seam's use.
    pub unsafe fn new(pamh: *mut pam_handle_t) -> RealPamSeam {
        RealPamSeam { pamh }
    }

    /// Fetch a `PAM_*` item as a raw pointer, or `None` on failure/null.
    fn get_item_ptr(&self, item_type: c_int) -> Option<*const c_void> {
        let mut item: *const c_void = std::ptr::null();
        // SAFETY: `pamh` is valid per the constructor contract; `item` is writable.
        let rc = unsafe { bindings::pam_get_item(self.pamh, item_type, &mut item) };
        if rc != bindings::PAM_SUCCESS || item.is_null() {
            None
        } else {
            Some(item)
        }
    }
}

impl PamSeam for RealPamSeam {
    fn get_user_name(&mut self) -> Result<String, SeamError> {
        let mut ptr: *const std::ffi::c_char = std::ptr::null();
        // SAFETY: `pamh` is valid; `ptr` is writable; a null prompt selects libpam's
        // default.
        let rc = unsafe { bindings::pam_get_user(self.pamh, &mut ptr, std::ptr::null()) };
        if rc != bindings::PAM_SUCCESS {
            return Err(SeamError::GetUser(rc));
        }
        // SAFETY: libpam owns the returned string for the handle's lifetime.
        match unsafe { bindings::cstr_to_str(ptr) } {
            Some(s) if !s.is_empty() => Ok(s.to_string()),
            _ => Err(SeamError::NullUser),
        }
    }

    fn get_service(&mut self) -> Option<String> {
        let item = self.get_item_ptr(PAM_SERVICE)?;
        // SAFETY: PAM_SERVICE is a C string.
        unsafe { bindings::cstr_to_str(item as *const std::ffi::c_char) }.map(str::to_string)
    }

    fn conv_available(&mut self) -> bool {
        let Some(item) = self.get_item_ptr(PAM_CONV) else {
            return false;
        };
        // SAFETY: PAM_CONV points at a `struct pam_conv` owned by libpam.
        let conv = unsafe { &*(item as *const pam_conv) };
        conv.conv.is_some()
    }

    fn conv_text(&mut self, style: c_int, text: &str) -> Result<(), SeamError> {
        let Some(item) = self.get_item_ptr(PAM_CONV) else {
            return Err(SeamError::NoConv);
        };
        // SAFETY: PAM_CONV points at a `struct pam_conv` owned by libpam.
        let conv_struct = unsafe { &*(item as *const pam_conv) };
        let Some(conv) = conv_struct.conv else {
            return Err(SeamError::NoConv);
        };
        let c_text = CString::new(text).map_err(|_| SeamError::InteriorNul)?;

        let msg = pam_message {
            msg_style: style,
            msg: c_text.as_ptr(),
        };
        // The C prototype takes `const struct pam_message **`: a pointer to an array
        // of message pointers. One message here.
        let msg_ptrs: [*const pam_message; 1] = [&msg];
        let mut resp: *mut pam_response = std::ptr::null_mut();

        // SAFETY: one message, matching libpam's `conv` prototype. The message and
        // its backing CString outlive the call.
        let rc = unsafe {
            conv(
                1,
                msg_ptrs.as_ptr() as *mut *const pam_message,
                &mut resp,
                conv_struct.appdata_ptr,
            )
        };
        if rc != bindings::PAM_SUCCESS {
            return Err(SeamError::Conv(rc));
        }

        // An info/error message needs no reply. If the application allocated one
        // anyway, free it the way libpam itself would (`_pam_drop_reply`).
        if !resp.is_null() {
            // SAFETY: `resp` is a one-element malloc'd array per the PAM contract.
            let first = unsafe { std::ptr::read(resp) };
            if !first.resp.is_null() {
                // SAFETY: allocated by the conversation function with malloc.
                unsafe { libc::free(first.resp as *mut c_void) };
            }
            // SAFETY: as above.
            unsafe { libc::free(resp as *mut c_void) };
        }
        Ok(())
    }

    fn fail_delay(&mut self, usec: u32) {
        // SAFETY: `pamh` is valid per the constructor contract.
        unsafe {
            bindings::pam_fail_delay(self.pamh, usec);
        }
    }
}
