//! Hand-written Win32 FFI for `webauthn.dll` (plan §5, D5).
//!
//! The workspace deliberately does **not** depend on the `windows`/
//! `windows-sys` crates; every declaration here is transcribed from
//! `microsoft/webauthn` `webauthn.h` (MIT) and the Win32 headers. All `unsafe`
//! in the crate is confined to this module.
//!
//! # Design notes
//!
//! * **Full-size structs, low `dwVersion`.** `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS`
//!   is declared at its v9 size and `WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS`
//!   at v9, but we fill `dwVersion = 3` / `4` respectively and leave the later
//!   fields zero. This is exactly what libfido2's `winhello.c` does: the DLL
//!   only reads fields covered by the declared version, so an over-sized,
//!   zero-initialised struct is forward-compatible and avoids both
//!   under-allocation and version-conditional layouts. (The task brief's
//!   "full v9 size, `dwVersion=3` filled" is taken literally.)
//! * **Out-params over-allocated.** `WEBAUTHN_ASSERTION` is declared at its v6
//!   size (`dwVersion >= 6` exposes `pbClientDataJSON`); `WEBAUTHN_CREDENTIAL_ATTESTATION`
//!   at its v8 size. The DLL may write them at any version.
//! * **Hidden window.** A dedicated thread registers a class and creates a
//!   hidden top-level window, then runs a `GetMessageW` pump for the bridge's
//!   whole lifetime. The blocking ceremony executes on the *calling* thread
//!   using that HWND. This is deliberate: if the pump and the blocking
//!   ceremony shared a thread, no messages would be dispatched during the
//!   ceremony, defeating the purpose. If window creation fails, the bridge
//!   falls back to `GetForegroundWindow()` (then `GetDesktopWindow()`).
//! * **Hardened load.** `webauthn.dll` is loaded with
//!   `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_SYSTEM32)` rather than the
//!   brief's `LoadLibraryW`, so the bridge's Windows mount-root working
//!   directory (plan D11) cannot plant a DLL.

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use wsl_webauthn_protocol::BridgeError;

use crate::api::{
    AssertionOptions, AssertionResult, CancellationId, CredentialAttestation, Hresult,
    MakeCredentialOptions, ProbeInfo, S_OK, WebAuthnApi, map_hresult,
};

/// Win32 `HWND` / `HMODULE` / generic handle.
type Handle = *mut c_void;
/// Win32 `HWND`.
type Hwnd = *mut c_void;

const WS_POPUP: u32 = 0x8000_0000;
const WM_QUIT: u32 = 0x0012;

const WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY: &str = "public-key";
const WEBAUTHN_HASH_ALGORITHM_SHA_256: &str = "SHA-256";

// ---------------------------------------------------------------------------
// Imported Win32 functions
// ---------------------------------------------------------------------------

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(lpModuleName: *const u16) -> Handle;
    fn LoadLibraryExW(lpLibFileName: *const u16, hFile: Handle, dwFlags: u32) -> Handle;
    fn FreeLibrary(hLibModule: Handle) -> i32;
    fn GetProcAddress(hModule: Handle, lpProcName: *const u8) -> *mut c_void;
    pub fn GetCurrentProcessId() -> u32;
}

#[link(name = "user32")]
unsafe extern "system" {
    fn RegisterClassW(lpWndClass: *const WndClassW) -> u16;
    fn UnregisterClassW(lpClassName: *const u16, hInstance: Handle) -> i32;
    fn CreateWindowExW(
        dwExStyle: u32,
        lpClassName: *const u16,
        lpWindowName: *const u16,
        dwStyle: u32,
        x: i32,
        y: i32,
        nWidth: i32,
        nHeight: i32,
        hWndParent: Hwnd,
        hMenu: Handle,
        hInstance: Handle,
        lpParam: *mut c_void,
    ) -> Hwnd;
    fn DefWindowProcW(hWnd: Hwnd, msg: u32, wParam: usize, lParam: isize) -> isize;
    fn GetMessageW(lpMsg: *mut Msg, hWnd: Hwnd, wMsgFilterMin: u32, wMsgFilterMax: u32) -> i32;
    fn TranslateMessage(lpMsg: *const Msg) -> i32;
    fn DispatchMessageW(lpMsg: *const Msg) -> isize;
    fn PostMessageW(hWnd: Hwnd, msg: u32, wParam: usize, lParam: isize) -> i32;
    fn GetForegroundWindow() -> Hwnd;
    fn GetDesktopWindow() -> Hwnd;
}

// ---------------------------------------------------------------------------
// webauthn.dll function pointer types
// ---------------------------------------------------------------------------

type FnGetApiVersionNumber = unsafe extern "system" fn() -> u32;
type FnIsUvPlatformAvailable = unsafe extern "system" fn(*mut i32) -> Hresult;
type FnMakeCredential = unsafe extern "system" fn(
    Hwnd,
    *const RpEntityInformation,
    *const UserEntityInformation,
    *const CoseCredentialParameters,
    *const ClientData,
    *const MakeCredentialOptionsRaw,
    *mut *mut CredentialAttestationRaw,
) -> Hresult;
type FnGetAssertion = unsafe extern "system" fn(
    Hwnd,
    *const u16,
    *const ClientData,
    *const GetAssertionOptionsRaw,
    *mut *mut AssertionRaw,
) -> Hresult;
type FnCancelCurrentOperation = unsafe extern "system" fn(*const Guid) -> Hresult;
type FnGetCancellationId = unsafe extern "system" fn(*mut Guid) -> Hresult;
type FnFreeAssertion = unsafe extern "system" fn(*mut AssertionRaw);
type FnFreeCredentialAttestation = unsafe extern "system" fn(*mut CredentialAttestationRaw);
type FnGetErrorName = unsafe extern "system" fn(Hresult) -> *const u16;

// ---------------------------------------------------------------------------
// Structs (transcribed from webauthn.h; field names snake_cased)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct RpEntityInformation {
    dw_version: u32,
    pwsz_id: *const u16,
    pwsz_name: *const u16,
    pwsz_icon: *const u16,
}

#[repr(C)]
struct UserEntityInformation {
    dw_version: u32,
    cb_id: u32,
    pb_id: *mut u8,
    pwsz_name: *const u16,
    pwsz_icon: *const u16,
    pwsz_display_name: *const u16,
}

#[repr(C)]
struct ClientData {
    dw_version: u32,
    cb_client_data_json: u32,
    pb_client_data_json: *mut u8,
    pwsz_hash_alg_id: *const u16,
}

#[repr(C)]
struct CoseCredentialParameter {
    dw_version: u32,
    pwsz_credential_type: *const u16,
    l_alg: i32,
}

#[repr(C)]
struct CoseCredentialParameters {
    c_credential_parameters: u32,
    p_credential_parameters: *mut CoseCredentialParameter,
}

#[repr(C)]
struct Credential {
    dw_version: u32,
    cb_id: u32,
    pb_id: *mut u8,
    pwsz_credential_type: *const u16,
}

#[repr(C)]
struct Credentials {
    c_credentials: u32,
    p_credentials: *mut Credential,
}

#[repr(C)]
struct CredentialEx {
    dw_version: u32,
    cb_id: u32,
    pb_id: *mut u8,
    pwsz_credential_type: *const u16,
    dw_transports: u32,
}

#[repr(C)]
struct CredentialList {
    c_credentials: u32,
    pp_credentials: *mut *mut CredentialEx,
}

#[repr(C)]
struct Extension {
    pwsz_extension_identifier: *const u16,
    cb_extension: u32,
    pv_extension: *mut c_void,
}

#[repr(C)]
struct Extensions {
    c_extensions: u32,
    p_extensions: *mut Extension,
}

#[repr(C)]
struct HmacSecretSalt {
    cb_first: u32,
    pb_first: *mut u8,
    cb_second: u32,
    pb_second: *mut u8,
}

#[repr(C)]
struct CredWithHmacSecretSalt {
    cb_cred_id: u32,
    pb_cred_id: *mut u8,
    p_hmac_secret_salt: *mut HmacSecretSalt,
}

#[repr(C)]
struct HmacSecretSaltValues {
    p_global_hmac_salt: *mut HmacSecretSalt,
    c_cred_with_hmac_secret_salt_list: u32,
    p_cred_with_hmac_secret_salt_list: *mut CredWithHmacSecretSalt,
}

/// `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS` at its v9 size.
#[repr(C)]
struct MakeCredentialOptionsRaw {
    dw_version: u32,
    dw_timeout_milliseconds: u32,
    credential_list: Credentials,
    extensions: Extensions,
    dw_authenticator_attachment: u32,
    b_require_resident_key: i32,
    dw_user_verification_requirement: u32,
    dw_attestation_conveyance_preference: u32,
    dw_flags: u32,
    p_cancellation_id: *mut Guid,
    p_exclude_credential_list: *mut CredentialList,
    dw_enterprise_attestation: u32,
    dw_large_blob_support: u32,
    b_prefer_resident_key: i32,
    b_browser_in_private_mode: i32,
    b_enable_prf: i32,
    p_linked_device: *mut c_void,
    cb_json_ext: u32,
    pb_json_ext: *mut u8,
    p_prf_global_eval: *mut HmacSecretSalt,
    c_credential_hints: u32,
    ppwsz_credential_hints: *mut *const u16,
    b_third_party_payment: i32,
    pwsz_remote_web_origin: *const u16,
    cb_public_key_credential_creation_options_json: u32,
    pb_public_key_credential_creation_options_json: *mut u8,
    cb_authenticator_id: u32,
    pb_authenticator_id: *mut u8,
}

/// `WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS` at its v9 size.
#[repr(C)]
struct GetAssertionOptionsRaw {
    dw_version: u32,
    dw_timeout_milliseconds: u32,
    credential_list: Credentials,
    extensions: Extensions,
    dw_authenticator_attachment: u32,
    dw_user_verification_requirement: u32,
    dw_flags: u32,
    pwsz_u2f_app_id: *const u16,
    pb_u2f_app_id: *mut i32,
    p_cancellation_id: *mut Guid,
    p_allow_credential_list: *mut CredentialList,
    dw_cred_large_blob_operation: u32,
    cb_cred_large_blob: u32,
    pb_cred_large_blob: *mut u8,
    p_hmac_secret_salt_values: *mut HmacSecretSaltValues,
    b_browser_in_private_mode: i32,
    p_linked_device: *mut c_void,
    b_auto_fill: i32,
    cb_json_ext: u32,
    pb_json_ext: *mut u8,
    c_credential_hints: u32,
    ppwsz_credential_hints: *mut *const u16,
    pwsz_remote_web_origin: *const u16,
    cb_public_key_credential_request_options_json: u32,
    pb_public_key_credential_request_options_json: *mut u8,
    cb_authenticator_id: u32,
    pb_authenticator_id: *mut u8,
}

/// `WEBAUTHN_CREDENTIAL_ATTESTATION` at its v8 size (out-param).
#[repr(C)]
struct CredentialAttestationRaw {
    dw_version: u32,
    pwsz_format_type: *const u16,
    cb_authenticator_data: u32,
    pb_authenticator_data: *mut u8,
    cb_attestation: u32,
    pb_attestation: *mut u8,
    dw_attestation_decode_type: u32,
    pv_attestation_decode: *mut c_void,
    cb_attestation_object: u32,
    pb_attestation_object: *mut u8,
    cb_credential_id: u32,
    pb_credential_id: *mut u8,
    extensions: Extensions,
    dw_used_transport: u32,
    b_ep_att: i32,
    b_large_blob_supported: i32,
    b_resident_key: i32,
    b_prf_enabled: i32,
    cb_unsigned_extension_outputs: u32,
    pb_unsigned_extension_outputs: *mut u8,
    p_hmac_secret: *mut HmacSecretSalt,
    b_third_party_payment: i32,
    dw_transports: u32,
    cb_client_data_json: u32,
    pb_client_data_json: *mut u8,
    cb_registration_response_json: u32,
    pb_registration_response_json: *mut u8,
}

/// `WEBAUTHN_ASSERTION` at its v6 size (out-param; `dwVersion >= 6` exposes
/// `pbClientDataJSON`).
#[repr(C)]
struct AssertionRaw {
    dw_version: u32,
    cb_authenticator_data: u32,
    pb_authenticator_data: *mut u8,
    cb_signature: u32,
    pb_signature: *mut u8,
    credential: Credential,
    cb_user_id: u32,
    pb_user_id: *mut u8,
    extensions: Extensions,
    cb_cred_large_blob: u32,
    pb_cred_large_blob: *mut u8,
    dw_cred_large_blob_status: u32,
    p_hmac_secret: *mut HmacSecretSalt,
    dw_used_transport: u32,
    cb_unsigned_extension_outputs: u32,
    pb_unsigned_extension_outputs: *mut u8,
    cb_client_data_json: u32,
    pb_client_data_json: *mut u8,
    cb_authentication_response_json: u32,
    pb_authentication_response_json: *mut u8,
}

// ---------------------------------------------------------------------------
// user32 windowing structs
// ---------------------------------------------------------------------------

type WndProc = unsafe extern "system" fn(Hwnd, u32, usize, isize) -> isize;

#[repr(C)]
struct WndClassW {
    style: u32,
    lpfn_wnd_proc: Option<WndProc>,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: Handle,
    h_icon: Handle,
    h_cursor: Handle,
    hbr_background: Handle,
    lpsz_menu_name: *const u16,
    lpsz_class_name: *const u16,
}

/// `MSG`; includes the post-Win7 `lPrivate` field so the DLL never writes past
/// our buffer.
#[repr(C)]
struct Msg {
    hwnd: Hwnd,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt_x: i32,
    pt_y: i32,
    l_private: u32,
}

// ---------------------------------------------------------------------------
// String helpers (leaked for the process lifetime so raw pointers stay valid)
// ---------------------------------------------------------------------------

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn module_name() -> *const u16 {
    static NAME: OnceLock<Vec<u16>> = OnceLock::new();
    NAME.get_or_init(|| wide("webauthn.dll")).as_ptr()
}

fn class_name() -> *const u16 {
    static NAME: OnceLock<Vec<u16>> = OnceLock::new();
    NAME.get_or_init(|| wide("WSLWebAuthnBridgeHidden"))
        .as_ptr()
}

fn window_name() -> *const u16 {
    static NAME: OnceLock<Vec<u16>> = OnceLock::new();
    NAME.get_or_init(|| wide("WSLWebAuthnBridge")).as_ptr()
}

/// Read a NUL-terminated UTF-16 string with a bounded scan (never panics).
///
/// # Safety
/// `p` is either null or points to a NUL-terminated UTF-16 buffer (or at least
/// the scan stops after [`WIDE_SCAN_LIMIT`] code units).
unsafe fn wide_ptr_to_string(p: *const u16) -> Option<String> {
    const WIDE_SCAN_LIMIT: usize = 4096;
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < WIDE_SCAN_LIMIT && unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(p, len)
    }))
}

/// Copy a raw byte buffer (null-safe, zero-length safe).
///
/// # Safety
/// `p` is null or valid for `len` bytes.
unsafe fn raw_bytes(p: *mut u8, len: u32) -> Vec<u8> {
    if p.is_null() || len == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(p, len as usize).to_vec() }
}

fn guid_from_bytes(b: [u8; 16]) -> Guid {
    // `Guid` is `#[repr(C)]` and exactly 16 bytes with no padding.
    unsafe { mem::transmute::<[u8; 16], Guid>(b) }
}

fn bytes_from_guid(g: Guid) -> [u8; 16] {
    unsafe { mem::transmute::<Guid, [u8; 16]>(g) }
}

// ---------------------------------------------------------------------------
// Hidden window (dedicated thread + message pump)
// ---------------------------------------------------------------------------

struct HwndSend(Hwnd);
// SAFETY: the handle value is only ever used by the owning/pumping thread and
// as an opaque argument to the webauthn API.
unsafe impl Send for HwndSend {}

struct HiddenWindow {
    hwnd: Hwnd,
    thread: Option<JoinHandle<()>>,
}

// SAFETY: `hwnd` is an opaque handle used read-only across threads; the thread
// handle is Send by construction.
unsafe impl Send for HiddenWindow {}
unsafe impl Sync for HiddenWindow {}

impl HiddenWindow {
    /// Best-effort creation; returns `None` if the class/window cannot be
    /// created (caller then falls back to the foreground window).
    fn create() -> Option<HiddenWindow> {
        let (tx, rx) = mpsc::channel::<HwndSend>();
        let thread = thread::Builder::new()
            .name("win-message-pump".to_string())
            .spawn(move || pump_thread(tx))
            .ok()?;

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(HwndSend(h)) if !h.is_null() => Some(HiddenWindow {
                hwnd: h,
                thread: Some(thread),
            }),
            // Window creation failed, or the pump thread vanished: detach it
            // (process is short-lived) and report failure.
            _ => None,
        }
    }
}

impl Drop for HiddenWindow {
    fn drop(&mut self) {
        // WM_QUIT makes GetMessageW return 0, ending the pump.
        unsafe {
            PostMessageW(self.hwnd, WM_QUIT, 0, 0);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn pump_thread(tx: mpsc::Sender<HwndSend>) {
    let hinstance = unsafe { GetModuleHandleW(ptr::null()) };
    let class = class_name();

    let wc = WndClassW {
        style: 0,
        lpfn_wnd_proc: Some(DefWindowProcW),
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        h_instance: hinstance,
        h_icon: ptr::null_mut(),
        h_cursor: ptr::null_mut(),
        hbr_background: ptr::null_mut(),
        lpsz_menu_name: ptr::null(),
        lpsz_class_name: class,
    };
    // Ignore a failure from RegisterClassW (e.g. already registered); a failed
    // creation below is what matters.
    unsafe {
        RegisterClassW(&wc);
    }

    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class,
            window_name(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            hinstance,
            ptr::null_mut(),
        )
    };

    let created = !hwnd.is_null();
    let _ = tx.send(HwndSend(hwnd));
    if !created {
        return;
    }

    let mut msg: Msg = unsafe { mem::zeroed() };
    loop {
        let r = unsafe { GetMessageW(&mut msg, ptr::null_mut(), 0, 0) };
        if r <= 0 {
            break;
        }
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    unsafe {
        UnregisterClassW(class, hinstance);
    }
}

// ---------------------------------------------------------------------------
// DLL handle + function table
// ---------------------------------------------------------------------------

struct WebauthnDll {
    handle: Handle,
    is_uv_platform_available: FnIsUvPlatformAvailable,
    make_credential: FnMakeCredential,
    get_assertion: FnGetAssertion,
    cancel_current_operation: FnCancelCurrentOperation,
    get_cancellation_id: FnGetCancellationId,
    free_assertion: FnFreeAssertion,
    free_credential_attestation: FnFreeCredentialAttestation,
    /// Optional (pre-1903 DLLs); `None` ⇒ treat as API version 0.
    get_api_version_number: Option<FnGetApiVersionNumber>,
    /// Optional (logging only).
    get_error_name: Option<FnGetErrorName>,
}

// SAFETY: after `load()` the function pointers and module handle are
// immutable, and the Win32 WebAuthN API is safe to call concurrently.
unsafe impl Send for WebauthnDll {}
unsafe impl Sync for WebauthnDll {}

impl Drop for WebauthnDll {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                FreeLibrary(self.handle);
            }
        }
    }
}

/// Fetch and transmute one exported symbol.
///
/// # Safety
/// `handle` must be a valid module handle; `name` a NUL-terminated ASCII name.
unsafe fn proc<T>(handle: Handle, name: &[u8]) -> Option<T> {
    let p = unsafe { GetProcAddress(handle, name.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { mem::transmute_copy::<*mut c_void, T>(&p) })
    }
}

/// The real [`WebAuthnApi`] backed by `webauthn.dll`.
pub struct Win32Api {
    dll: WebauthnDll,
    window: Option<HiddenWindow>,
}

// SAFETY: see `WebauthnDll` / `HiddenWindow`.
unsafe impl Send for Win32Api {}
unsafe impl Sync for Win32Api {}

impl Win32Api {
    /// Load `webauthn.dll` and resolve the required exports.
    ///
    /// Returns [`BridgeError::NotSupported`] if the DLL is missing or any
    /// required export is absent. `WebAuthNGetApiVersionNumber` and
    /// `WebAuthNGetErrorName` are optional.
    ///
    /// Loading is restricted to `%SystemRoot%\System32`
    /// (`LOAD_LIBRARY_SEARCH_SYSTEM32`) so the bridge's Windows mount-root
    /// working directory cannot be used to plant a rogue `webauthn.dll`
    /// (plan D11/§5).
    pub fn load() -> Result<Win32Api, BridgeError> {
        const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
        let handle =
            unsafe { LoadLibraryExW(module_name(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if handle.is_null() {
            return Err(BridgeError::NotSupported);
        }

        // SAFETY: `handle` is a freshly loaded module.
        let is_uv_platform_available = unsafe {
            proc::<FnIsUvPlatformAvailable>(
                handle,
                b"WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable\0",
            )
        };
        let make_credential =
            unsafe { proc::<FnMakeCredential>(handle, b"WebAuthNAuthenticatorMakeCredential\0") };
        let get_assertion =
            unsafe { proc::<FnGetAssertion>(handle, b"WebAuthNAuthenticatorGetAssertion\0") };
        let cancel_current_operation = unsafe {
            proc::<FnCancelCurrentOperation>(handle, b"WebAuthNCancelCurrentOperation\0")
        };
        let get_cancellation_id =
            unsafe { proc::<FnGetCancellationId>(handle, b"WebAuthNGetCancellationId\0") };
        let free_assertion = unsafe { proc::<FnFreeAssertion>(handle, b"WebAuthNFreeAssertion\0") };
        let free_credential_attestation = unsafe {
            proc::<FnFreeCredentialAttestation>(handle, b"WebAuthNFreeCredentialAttestation\0")
        };
        let get_api_version_number =
            unsafe { proc::<FnGetApiVersionNumber>(handle, b"WebAuthNGetApiVersionNumber\0") };
        let get_error_name = unsafe { proc::<FnGetErrorName>(handle, b"WebAuthNGetErrorName\0") };

        let (
            Some(is_uv_platform_available),
            Some(make_credential),
            Some(get_assertion),
            Some(cancel_current_operation),
            Some(get_cancellation_id),
            Some(free_assertion),
            Some(free_credential_attestation),
        ) = (
            is_uv_platform_available,
            make_credential,
            get_assertion,
            cancel_current_operation,
            get_cancellation_id,
            free_assertion,
            free_credential_attestation,
        )
        else {
            // `WebauthnDll` owns `handle`; dropping it via this early return
            // requires moving the handle first.
            unsafe {
                FreeLibrary(handle);
            }
            return Err(BridgeError::NotSupported);
        };

        let dll = WebauthnDll {
            handle,
            is_uv_platform_available,
            make_credential,
            get_assertion,
            cancel_current_operation,
            get_cancellation_id,
            free_assertion,
            free_credential_attestation,
            get_api_version_number,
            get_error_name,
        };

        Ok(Win32Api {
            dll,
            window: HiddenWindow::create(),
        })
    }

    /// The HWND handed to the ceremony: the hidden window when available,
    /// otherwise the foreground/desktop window (documented fallback).
    fn hwnd(&self) -> Hwnd {
        if let Some(w) = &self.window {
            return w.hwnd;
        }
        let fg = unsafe { GetForegroundWindow() };
        if !fg.is_null() {
            fg
        } else {
            unsafe { GetDesktopWindow() }
        }
    }

    fn api_version(&self) -> u32 {
        match self.dll.get_api_version_number {
            Some(f) => unsafe { f() },
            None => 0,
        }
    }

    fn log_error(&self, context: &str, hr: Hresult) {
        if let Some(f) = self.dll.get_error_name {
            let name =
                unsafe { wide_ptr_to_string(f(hr)) }.unwrap_or_else(|| "UnknownError".into());
            eprintln!("{context}: hr=0x{:08X} {name}", hr as u32);
        } else {
            eprintln!("{context}: hr=0x{:08X}", hr as u32);
        }
    }
}

impl WebAuthnApi for Win32Api {
    fn probe(&self) -> Result<ProbeInfo, BridgeError> {
        let mut available: i32 = 0;
        let hr = unsafe { (self.dll.is_uv_platform_available)(&mut available) };
        if hr != S_OK {
            self.log_error("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable", hr);
            return Err(map_hresult(hr));
        }
        Ok(ProbeInfo {
            uv_platform_available: available != 0,
            api_version: self.api_version(),
        })
    }

    fn get_cancellation_id(&self) -> Result<CancellationId, BridgeError> {
        let mut guid = Guid {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };
        let hr = unsafe { (self.dll.get_cancellation_id)(&mut guid) };
        if hr != S_OK {
            self.log_error("WebAuthNGetCancellationId", hr);
            return Err(map_hresult(hr));
        }
        Ok(CancellationId(bytes_from_guid(guid)))
    }

    fn make_credential(
        &self,
        o: &MakeCredentialOptions,
    ) -> Result<CredentialAttestation, BridgeError> {
        // Keep every pointer target alive until the call returns.
        let rp_id = wide(&o.rp_id);
        let rp_name = wide(&o.rp_name);
        let user_name = wide(&o.user_name);
        let user_display = wide(&o.user_display_name);
        let cred_type = wide(WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY);
        let hash_alg = wide(WEBAUTHN_HASH_ALGORITHM_SHA_256);

        let mut user_id = o.user_id.clone();
        let mut client_data_json = o.client_data_json.clone();
        let mut cose: Vec<CoseCredentialParameter> = o
            .cose_algorithms
            .iter()
            .map(|alg| CoseCredentialParameter {
                dw_version: 1,
                pwsz_credential_type: cred_type.as_ptr(),
                l_alg: *alg,
            })
            .collect();
        let mut guid = guid_from_bytes(o.cancellation_id.0);

        let rp = RpEntityInformation {
            dw_version: 1,
            pwsz_id: rp_id.as_ptr(),
            pwsz_name: rp_name.as_ptr(),
            pwsz_icon: ptr::null(),
        };
        let user = UserEntityInformation {
            dw_version: 1,
            cb_id: user_id.len() as u32,
            pb_id: user_id.as_mut_ptr(),
            pwsz_name: user_name.as_ptr(),
            pwsz_icon: ptr::null(),
            pwsz_display_name: user_display.as_ptr(),
        };
        let cd = ClientData {
            dw_version: 1,
            cb_client_data_json: client_data_json.len() as u32,
            pb_client_data_json: client_data_json.as_mut_ptr(),
            pwsz_hash_alg_id: hash_alg.as_ptr(),
        };
        let cose_params = CoseCredentialParameters {
            c_credential_parameters: cose.len() as u32,
            p_credential_parameters: cose.as_mut_ptr(),
        };

        // Full v9 size, zero-init, dwVersion = 3 (D5): the v1..v3 fields we set
        // are timeout/attachment/resident/UV/attestation + pCancellationId.
        let mut options: MakeCredentialOptionsRaw = unsafe { mem::zeroed() };
        options.dw_version = 3;
        options.dw_timeout_milliseconds = o.timeout_ms;
        options.dw_authenticator_attachment = o.attachment as u32;
        options.b_require_resident_key = i32::from(o.require_resident_key);
        options.dw_user_verification_requirement = o.uv_requirement as u32;
        options.dw_attestation_conveyance_preference = o.attestation as u32;
        options.p_cancellation_id = &mut guid;
        // `p_exclude_credential_list` stays NULL (v3 field; we want a
        // non-resident credential and discovery via the assertion allow-list).

        let mut out: *mut CredentialAttestationRaw = ptr::null_mut();
        let hr = unsafe {
            (self.dll.make_credential)(
                self.hwnd(),
                &rp,
                &user,
                &cose_params,
                &cd,
                &options,
                &mut out,
            )
        };

        if hr != S_OK {
            self.log_error("WebAuthNAuthenticatorMakeCredential", hr);
            if !out.is_null() {
                unsafe { (self.dll.free_credential_attestation)(out) };
            }
            return Err(map_hresult(hr));
        }
        if out.is_null() {
            eprintln!("WebAuthNAuthenticatorMakeCredential: S_OK but null attestation");
            return Err(BridgeError::Internal);
        }

        // SAFETY: on S_OK the API filled `out`.
        let result = unsafe {
            let format = wide_ptr_to_string((*out).pwsz_format_type)
                .unwrap_or_else(|| String::from("unknown"));
            let attestation_object =
                raw_bytes((*out).pb_attestation_object, (*out).cb_attestation_object);
            let credential_id = raw_bytes((*out).pb_credential_id, (*out).cb_credential_id);
            // Free on every path, before the value is returned.
            (self.dll.free_credential_attestation)(out);
            CredentialAttestation {
                format,
                attestation_object,
                credential_id,
            }
        };
        Ok(result)
    }

    fn get_assertion(&self, o: &AssertionOptions) -> Result<AssertionResult, BridgeError> {
        let rp_id = wide(&o.rp_id);
        let cred_type = wide(WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY);
        let hash_alg = wide(WEBAUTHN_HASH_ALGORITHM_SHA_256);
        let mut client_data_json = o.client_data_json.clone();
        let mut guid = guid_from_bytes(o.cancellation_id.0);

        // Deep-copied credential IDs + a CredentialEx per id. `ids` and `exs`
        // stay alive for the duration of the call.
        let mut ids: Vec<Vec<u8>> = o.allow_credential_ids.clone();
        let mut exs: Vec<CredentialEx> = ids
            .iter_mut()
            .map(|id| CredentialEx {
                dw_version: 1,
                cb_id: id.len() as u32,
                pb_id: id.as_mut_ptr(),
                pwsz_credential_type: cred_type.as_ptr(),
                dw_transports: 0,
            })
            .collect();
        let mut ex_ptrs: Vec<*mut CredentialEx> = exs.iter_mut().map(|e| e as *mut _).collect();
        let mut allow_list = CredentialList {
            c_credentials: ex_ptrs.len() as u32,
            pp_credentials: ex_ptrs.as_mut_ptr(),
        };

        let cd = ClientData {
            dw_version: 1,
            cb_client_data_json: client_data_json.len() as u32,
            pb_client_data_json: client_data_json.as_mut_ptr(),
            pwsz_hash_alg_id: hash_alg.as_ptr(),
        };

        // Full v9 size, zero-init, dwVersion = 4 (D5): pAllowCredentialList is a
        // v4 field, pCancellationId a v3 field, both required here.
        let mut options: GetAssertionOptionsRaw = unsafe { mem::zeroed() };
        options.dw_version = 4;
        options.dw_timeout_milliseconds = o.timeout_ms;
        options.dw_authenticator_attachment = o.attachment as u32;
        options.dw_user_verification_requirement = o.uv_requirement as u32;
        options.p_cancellation_id = &mut guid;
        options.p_allow_credential_list = &mut allow_list;

        let mut out: *mut AssertionRaw = ptr::null_mut();
        let hr = unsafe {
            (self.dll.get_assertion)(self.hwnd(), rp_id.as_ptr(), &cd, &options, &mut out)
        };

        if hr != S_OK {
            self.log_error("WebAuthNAuthenticatorGetAssertion", hr);
            if !out.is_null() {
                unsafe { (self.dll.free_assertion)(out) };
            }
            return Err(map_hresult(hr));
        }
        if out.is_null() {
            eprintln!("WebAuthNAuthenticatorGetAssertion: S_OK but null assertion");
            return Err(BridgeError::Internal);
        }

        // SAFETY: on S_OK the API filled `out`.
        let result = unsafe {
            let authenticator_data =
                raw_bytes((*out).pb_authenticator_data, (*out).cb_authenticator_data);
            let signature = raw_bytes((*out).pb_signature, (*out).cb_signature);
            let credential_id = raw_bytes((*out).credential.pb_id, (*out).credential.cb_id);
            // The clientDataJSON echo only exists from ASSERTION v6 on.
            let echo = if (*out).dw_version >= 6 && (*out).cb_client_data_json > 0 {
                Some(raw_bytes(
                    (*out).pb_client_data_json,
                    (*out).cb_client_data_json,
                ))
            } else {
                None
            };
            (self.dll.free_assertion)(out);
            AssertionResult {
                authenticator_data,
                signature,
                credential_id,
                client_data_json_echo: echo,
            }
        };
        Ok(result)
    }

    fn cancel(&self, id: &CancellationId) {
        let guid = guid_from_bytes(id.0);
        // Best effort: the watchdog ignores the result.
        let hr = unsafe { (self.dll.cancel_current_operation)(&guid) };
        if hr != S_OK {
            self.log_error("WebAuthNCancelCurrentOperation", hr);
        }
    }
}

/// The process id as reported on the first stderr line.
pub fn current_process_id() -> u32 {
    unsafe { GetCurrentProcessId() }
}

/// Load the Win32 API, wrapped in an `Arc` ready for the ceremony layer.
pub fn load() -> Result<Arc<dyn WebAuthnApi>, BridgeError> {
    Win32Api::load().map(|api| Arc::new(api) as Arc<dyn WebAuthnApi>)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ABI layout guards. These run on the Windows CI job (the module only
    // compiles on Windows) and pin the sizes we derived from the public
    // `webauthn.h`. The structs are declared at a *newer* version than we fill,
    // exactly like libfido2's `winhello.c`, so under-allocation is the only
    // failure mode; the guard makes that a compile-time-independent test.
    #[test]
    fn guid_is_16_bytes() {
        assert_eq!(mem::size_of::<Guid>(), 16);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn struct_sizes_match_public_header() {
        // MAKE_CREDENTIAL_OPTIONS v9.
        assert_eq!(mem::size_of::<MakeCredentialOptionsRaw>(), 200);
        // GET_ASSERTION_OPTIONS v9.
        assert_eq!(mem::size_of::<GetAssertionOptionsRaw>(), 200);
        // CREDENTIAL_ATTESTATION v8.
        assert_eq!(mem::size_of::<CredentialAttestationRaw>(), 192);
        // ASSERTION v6.
        assert_eq!(mem::size_of::<AssertionRaw>(), 168);
        // MSG.
        assert_eq!(mem::size_of::<Msg>(), 48);
        // Sub-structs.
        assert_eq!(mem::size_of::<Credential>(), 24);
        assert_eq!(mem::size_of::<CredentialEx>(), 32);
        assert_eq!(mem::size_of::<Extensions>(), 16);
        assert_eq!(mem::size_of::<ClientData>(), 24);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn earlier_version_prefixes_have_expected_offsets() {
        // `pCancellationId` (MK v2) and `pExcludeCredentialList` (MK v3) must
        // land where the DLL expects them.
        let base = mem::align_of::<MakeCredentialOptionsRaw>();
        assert_eq!(base, 8);
        assert_eq!(
            mem::offset_of!(MakeCredentialOptionsRaw, p_cancellation_id),
            64
        );
        assert_eq!(
            mem::offset_of!(MakeCredentialOptionsRaw, p_exclude_credential_list),
            72
        );
        // GET_ASSERTION pAllowCredentialList is a v4 field.
        assert_eq!(
            mem::offset_of!(GetAssertionOptionsRaw, p_allow_credential_list),
            80
        );
        assert_eq!(
            mem::offset_of!(GetAssertionOptionsRaw, p_cancellation_id),
            72
        );
        // ASSERTION v6 clientDataJSON echo fields.
        assert_eq!(mem::offset_of!(AssertionRaw, cb_client_data_json), 136);
        assert_eq!(mem::offset_of!(AssertionRaw, pb_client_data_json), 144);
    }
}
