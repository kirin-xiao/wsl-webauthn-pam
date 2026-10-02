//! Hand-written Win32 FFI for `webauthn.dll`.
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
//!   fields zero, as libfido2's `winhello.c` does: the DLL
//!   only reads fields covered by the declared version, so an over-sized,
//!   zero-initialised struct is forward-compatible and avoids both
//!   under-allocation and version-conditional layouts.
//! * **Out-params over-allocated.** `WEBAUTHN_ASSERTION` is declared at its v6
//!   size (`dwVersion >= 6` exposes `pbClientDataJSON`); `WEBAUTHN_CREDENTIAL_ATTESTATION`
//!   at its v8 size. The DLL may write them at any version.
//! * **Hidden window.** A dedicated thread registers a class and creates a
//!   hidden top-level window, then runs a `GetMessageW` pump for the bridge's
//!   whole lifetime. The blocking ceremony executes on the *calling* thread
//!   using the handle chosen by [`Win32Api::hwnd`] (the foreground window is
//!   preferred; see the next bullet). This is deliberate: if the pump and the
//!   blocking ceremony shared a thread, no messages would be dispatched during
//!   the ceremony, defeating the purpose. The pump is stopped with a `WM_CLOSE`
//!   window message — the window proc answers by draining the thread queue
//!   (`PostQuitMessage(0)`) — and with a `WM_QUIT` posted to
//!   the pump *thread*'s queue. It is **not** stopped by posting `WM_QUIT` to
//!   the HWND: `WM_QUIT` is a thread (queue) message and a window-filtered pump
//!   does not observe it. If window creation fails, the bridge falls
//!   back to `GetForegroundWindow()` (then `GetTopWindow(NULL)`, then
//!   `GetDesktopWindow()`), so the API never receives a NULL window.
//! * **Foreground owner.** The WebAuthn `hWnd` is the *owner* of the Hello
//!   dialog. A dialog owned by the window the user is looking at is created in
//!   front of it; one owned by our hidden `WS_POPUP` window is created behind.
//!   `Win32Api::hwnd()` therefore prefers `GetForegroundWindow()` and only
//!   falls back to the hidden window — matching libfido2's `winhello.c`, which
//!   passes `GetForegroundWindow()`.
//! * **Focus watcher.** While a blocking `make_credential`/`get_assertion` call
//!   runs, a separate best-effort thread polls for the
//!   `Credential Dialog Xaml Host` window by class (never by its localized
//!   title) and escalates `SetForegroundWindow` → input-queue attach → taskbar
//!   `FlashWindowEx`, emitting `PROGRESS prompt_open`/`PROGRESS prompt_closed`
//!   on stderr. It is advisory only: every failure is ignored, it never runs on
//!   the blocked ceremony thread, and its guard stops it without joining (the
//!   process is short-lived, so a leaked watcher is harmless).
//! * **Hardened load.** `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`
//!   is applied process-wide before the first load, and `webauthn.dll`
//!   is then loaded with `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_SYSTEM32)`,
//!   so the bridge's Windows mount-root
//!   working directory cannot plant a DLL — not the named module,
//!   nor any dependency it pulls in (`LoadLibraryExW`'s flag only pins the
//!   direct load; the process default search order governs dependencies).

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::mem;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use wsl_webauthn_protocol::{BridgeError, PROGRESS_LINE_PREFIX};

use crate::api::{
    AssertionOptions, AssertionResult, CancellationId, CredentialAttestation, Hresult,
    MakeCredentialOptions, ProbeInfo, S_OK, WebAuthnApi, map_hresult,
};

/// Win32 `HWND` / `HMODULE` / generic handle.
type Handle = *mut c_void;
/// Win32 `HWND`.
type Hwnd = *mut c_void;

const WS_POPUP: u32 = 0x8000_0000;
const WM_CLOSE: u32 = 0x0010;
const WM_QUIT: u32 = 0x0012;

/// `WM_USER` — start of the application-private message range. Used to prime
/// the focus watcher thread's message queue (see [`FocusWatcher::arm`]).
const WM_USER: u32 = 0x0400;
/// `PM_NOREMOVE` — `PeekMessageW` leaves the message in the queue.
const PM_NOREMOVE: u32 = 0x0000;
/// `SW_RESTORE` — un-minimize a window before foregrounding it.
const SW_RESTORE: i32 = 9;
/// `FLASHW_ALL` — flash both the caption and the taskbar button.
const FLASHW_ALL: u32 = 0x0000_0003;
/// `FLASHW_TIMERNOFG` — keep flashing until the window comes to the foreground.
const FLASHW_TIMERNOFG: u32 = 0x0000_000C;
/// `GW_OWNER` — `GetWindow` flag returning a window's owner.
const GW_OWNER: u32 = 0x0004;
/// `TRUE`/`FALSE` for the `AttachThreadInput` `fAttach` parameter.
const ATTACH_TRUE: i32 = 1;
const ATTACH_FALSE: i32 = 0;

/// `LOAD_LIBRARY_SEARCH_SYSTEM32` — pin module resolution to
/// `%SystemRoot%\System32`. Applied both process-wide (so a dependency of
/// `webauthn.dll` cannot be planted either) and on the explicit load.
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

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
    fn SetDefaultDllDirectories(directoryFlags: u32) -> i32;
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
    fn DestroyWindow(hWnd: Hwnd) -> i32;
    fn DefWindowProcW(hWnd: Hwnd, msg: u32, wParam: usize, lParam: isize) -> isize;
    fn GetMessageW(lpMsg: *mut Msg, hWnd: Hwnd, wMsgFilterMin: u32, wMsgFilterMax: u32) -> i32;
    fn TranslateMessage(lpMsg: *const Msg) -> i32;
    fn DispatchMessageW(lpMsg: *const Msg) -> isize;
    fn PostMessageW(hWnd: Hwnd, msg: u32, wParam: usize, lParam: isize) -> i32;
    fn PostQuitMessage(nExitCode: i32);
    fn PostThreadMessageW(idThread: u32, msg: u32, wParam: usize, lParam: isize) -> i32;
    fn GetWindowThreadProcessId(hWnd: Hwnd, lpdwProcessId: *mut u32) -> u32;
    fn GetForegroundWindow() -> Hwnd;
    fn GetTopWindow(hWnd: Hwnd) -> Hwnd;
    fn GetDesktopWindow() -> Hwnd;
    fn GetWindow(hWnd: Hwnd, uCmd: u32) -> Hwnd;
    fn GetCurrentThreadId() -> u32;
    fn GetClassNameW(hWnd: Hwnd, lpClassName: *mut u16, nMaxCount: i32) -> i32;
    fn IsWindowVisible(hWnd: Hwnd) -> i32;
    fn EnumWindows(lpEnumFunc: Option<EnumWindowsProc>, lParam: isize) -> i32;
    fn SetForegroundWindow(hWnd: Hwnd) -> i32;
    fn AttachThreadInput(idAttach: u32, idAttachTo: u32, fAttach: i32) -> i32;
    fn SetFocus(hWnd: Hwnd) -> Hwnd;
    fn BringWindowToTop(hWnd: Hwnd) -> i32;
    fn ShowWindow(hWnd: Hwnd, nCmdShow: i32) -> i32;
    fn IsIconic(hWnd: Hwnd) -> i32;
    fn PeekMessageW(
        lpMsg: *mut Msg,
        hWnd: Hwnd,
        wMsgFilterMin: u32,
        wMsgFilterMax: u32,
        wRemoveMsg: u32,
    ) -> i32;
    fn FlashWindowEx(pfwi: *mut FlashWInfo) -> i32;
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
type EnumWindowsProc = unsafe extern "system" fn(Hwnd, isize) -> i32;

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

/// `FLASHWINFO`. `#[repr(C)]` with a 64-bit pointer, so the layout is:
/// `cbSize` (4) + 4 bytes padding + `hwnd` (8) + `dwFlags` (4) + `uCount` (4) +
/// `dwTimeout` (4) + 4 bytes tail padding = 32 bytes. The padding is asserted
/// by `flashwinfo_layout_matches_public_header`.
#[repr(C)]
struct FlashWInfo {
    cb_size: u32,
    hwnd: Hwnd,
    dw_flags: u32,
    u_count: u32,
    dw_timeout: u32,
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

/// Window class used by the hidden window pump. Kept as a string so the
/// test-only failure seam can hand `create_inner` a class that was never
/// registered.
const HIDDEN_CLASS_NAME: &str = "WSLWebAuthnBridgeHidden";

/// Class name of the Windows Hello / Windows Security credential dialog.
///
/// Matched **class-only**: the window title ("Windows Security" and friends) is
/// localized, so matching it would silently stop working on non-English
/// installs. Chromium made the same switch in M142.
const CREDENTIAL_DIALOG_CLASS: &str = "Credential Dialog Xaml Host";

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

/// Resolve the human-readable name for an `HRESULT`, tolerating a missing
/// `WebAuthNGetErrorName` export.
///
/// `get_error_name` is documented optional; when it is `None` (or the
/// DLL returns a null string) the stable placeholder `UnknownError` is used, so
/// the stderr diagnostic still carries a name field.
fn error_name(get_error_name: Option<FnGetErrorName>, hr: Hresult) -> String {
    match get_error_name {
        Some(f) => unsafe { wide_ptr_to_string(f(hr)) }.unwrap_or_else(|| "UnknownError".into()),
        None => "UnknownError".into(),
    }
}

/// Build a [`Guid`] from its 16 raw bytes.
///
/// The layout is a plain field-by-field copy (no `unsafe`, no `transmute`): a
/// Win32 `GUID` is `{ u32, u16, u16, [u8; 8] }` with no padding, and the raw
/// byte image is the same on the wire because `data1`..`data3` already carry
/// little-endian values as returned by the platform.
fn guid_from_bytes(b: [u8; 16]) -> Guid {
    Guid {
        data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        data2: u16::from_le_bytes([b[4], b[5]]),
        data3: u16::from_le_bytes([b[6], b[7]]),
        data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
    }
}

/// The raw 16-byte image of a [`Guid`] (inverse of [`guid_from_bytes`]).
fn bytes_from_guid(g: Guid) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&g.data1.to_le_bytes());
    out[4..6].copy_from_slice(&g.data2.to_le_bytes());
    out[6..8].copy_from_slice(&g.data3.to_le_bytes());
    out[8..16].copy_from_slice(&g.data4);
    out
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
    /// Pump-thread id, captured from `GetWindowThreadProcessId`. Used to post
    /// `WM_QUIT` to the *thread* queue, which a NULL-filtered pump observes
    /// (unlike an HWND-filtered one).
    pump_thread_id: u32,
    thread: Option<JoinHandle<()>>,
}

// SAFETY: `hwnd` is an opaque handle used read-only across threads; the thread
// handle is Send by construction.
unsafe impl Send for HiddenWindow {}
unsafe impl Sync for HiddenWindow {}

impl HiddenWindow {
    /// Best-effort creation; returns `None` if the class/window cannot be
    /// created (caller then falls back to the foreground window).
    ///
    /// On failure the pump thread is **not joined** — it runs its message loop
    /// with no owner until the process exits. The process is short-lived, so a
    /// leaked pump is harmless. Joining a possibly-stuck thread here would
    /// reintroduce the hang this path avoids.
    fn create() -> Option<HiddenWindow> {
        create_inner(wide(HIDDEN_CLASS_NAME), true)
    }
}

/// Create the hidden window using `class` as the window class.
///
/// `register_class = false` is a test-only seam: leaving the class
/// unregistered makes `CreateWindowExW` fail deterministically, which is how
/// the Windows-gated `create_failure_is_observable_as_none` test exercises the
/// `None` path. Production always passes `true`.
fn create_inner(class: Vec<u16>, register_class: bool) -> Option<HiddenWindow> {
    let (tx, rx) = mpsc::channel::<HwndSend>();
    let thread = thread::Builder::new()
        .name("win-message-pump".to_string())
        .spawn(move || pump_thread(tx, class, register_class))
        .ok()?;

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(HwndSend(h)) if !h.is_null() => {
            // The window belongs to the pump thread; the thread id is what
            // `PostThreadMessageW` needs.
            let pump_thread_id = unsafe { GetWindowThreadProcessId(h, ptr::null_mut()) };
            Some(HiddenWindow {
                hwnd: h,
                pump_thread_id,
                thread: Some(thread),
            })
        }
        // Window creation failed, or the pump thread vanished: do not join —
        // join could hang if the pump is wedged. Log it (the ceremony then uses
        // the foreground-window fallback) so a silent failure is observable,
        // then report failure. The process is short-lived, so an unjoined pump
        // is harmless.
        other => {
            let hwnd = match other {
                Ok(HwndSend(h)) => h,
                Err(_) => ptr::null_mut(),
            };
            eprintln!(
                "wsl-webauthn-bridge: hidden window creation failed (hwnd={hwnd:p}); \
                 falling back to the foreground window"
            );
            None
        }
    }
}

impl Drop for HiddenWindow {
    fn drop(&mut self) {
        // Stop the pump deterministically. `WM_QUIT` is a *thread* message: a
        // window-filtered `GetMessageW` never sees it, so post it to the pump
        // thread's queue. Also ask the window to close; the
        // window proc answers `WM_CLOSE` with `PostQuitMessage(0)`, which posts
        // `WM_QUIT` to the pumping thread's queue. Either message ends the
        // NULL-filtered pump. Both posts are guarded on a non-NULL HWND/
        // non-zero thread id so we never post into the *dropping* thread's
        // queue.
        if !self.hwnd.is_null() {
            unsafe {
                PostMessageW(self.hwnd, WM_CLOSE, 0, 0);
            }
        }
        if self.pump_thread_id != 0 {
            unsafe {
                PostThreadMessageW(self.pump_thread_id, WM_QUIT, 0, 0);
            }
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Hidden window's window procedure: on `WM_CLOSE`, post a quit to the owning
/// thread's queue and destroy the window. Everything else is default handling.
unsafe extern "system" fn hidden_wnd_proc(
    hwnd: Hwnd,
    msg: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    if msg == WM_CLOSE {
        unsafe {
            PostQuitMessage(0);
            DestroyWindow(hwnd);
        }
        0
    } else {
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }
}

fn pump_thread(tx: mpsc::Sender<HwndSend>, class: Vec<u16>, register_class: bool) {
    let hinstance = unsafe { GetModuleHandleW(ptr::null()) };
    let class = class.as_ptr();

    if register_class {
        let wc = WndClassW {
            style: 0,
            lpfn_wnd_proc: Some(hidden_wnd_proc),
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: hinstance,
            h_icon: ptr::null_mut(),
            h_cursor: ptr::null_mut(),
            hbr_background: ptr::null_mut(),
            lpsz_menu_name: ptr::null(),
            lpsz_class_name: class,
        };
        // Ignore a failure from RegisterClassW (e.g. already registered); a
        // failed creation below is what matters.
        unsafe {
            RegisterClassW(&wc);
        }
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

    // NULL hWnd filter: retrieve *every* message for this thread, including the
    // thread-targeted `WM_QUIT` (which a window-filtered pump would miss).
    // `GetMessageW` returns 0 on `WM_QUIT`, -1 on error; both end the loop.
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
// Focus watcher (best-effort foregrounding of the Windows Hello dialog)
// ---------------------------------------------------------------------------

/// RAII keep-alive for the focus watcher. It is armed around a blocking
/// ceremony; dropping it signals the watcher thread to stop and returns
/// immediately.
///
/// The thread is deliberately **not** joined: the process is short-lived and
/// the watcher may be wedged inside `AttachThreadInput`, so joining it could
/// hang the bridge. This follows the same precedent as
/// [`HiddenWindow::create`].
struct FocusWatcher {
    /// Flip to `true` to ask the thread to return promptly.
    stop: Arc<AtomicBool>,
    // The `JoinHandle` is intentionally dropped: see the struct doc.
}

/// The owner HWND the Hello dialog is expected to be parented to (the window
/// passed to the WebAuthn API), plus the out-parameter for a completed search.
struct DialogSearch {
    /// Expected owner; only windows owned by it are considered.
    owner: Hwnd,
    /// Set to the found dialog handle, or left null.
    found: Hwnd,
}

// SAFETY: the handles are opaque values only read/compared on the watcher
// thread (and used as read-only arguments to Win32). Nothing here dereferences
// them in Rust.
unsafe impl Send for DialogSearch {}

impl FocusWatcher {
    /// Arm a watcher for the duration of the current blocking Win32 call.
    ///
    /// `owner` is the HWND handed to the WebAuthn API (the dialog's expected
    /// owner); only windows owned by it are considered.
    fn arm(owner: Hwnd) -> FocusWatcher {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        // Wrap the owner before spawning so the closure captures `DialogSearch`
        // (Send) rather than a bare raw pointer.
        let search = DialogSearch {
            owner,
            found: ptr::null_mut(),
        };
        let spawned = thread::Builder::new()
            .name("hello-focus-watcher".to_string())
            .spawn(move || watcher_thread(thread_stop, search));
        if spawned.is_err() {
            // Best-effort: without the thread the ceremony still runs; it just
            // cannot raise the dialog. Use a non-panicking write so a broken
            // stderr cannot abort the bridge.
            use std::io::Write as _;
            let _ = writeln!(
                std::io::stderr(),
                "wsl-webauthn-bridge: focus watcher thread could not start"
            );
        }
        FocusWatcher { stop }
    }
}

impl Drop for FocusWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // No join — a possibly-stuck attaching thread must not hang the bridge.
    }
}

/// Write one progress line, ignoring a broken stderr.
///
/// The watcher runs on a detached thread and must never panic: `eprintln!`
/// panics if the write fails (e.g. the Linux runner already exited and closed
/// the pipe), so use a best-effort `writeln!`.
fn emit_progress(phase: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{PROGRESS_LINE_PREFIX}{phase}");
}

/// `EnumWindows` callback: record the first visible `Credential Dialog Xaml
/// Host` top-level window owned by `search.owner`, then stop enumerating.
///
/// The class match alone is spoofable (any process can register that class
/// name), so an owner match is required: the dialog is created as an owned
/// window of the HWND we passed to the WebAuthn API.
unsafe extern "system" fn find_dialog_proc(hwnd: Hwnd, lparam: isize) -> i32 {
    let search = unsafe { &mut *(lparam as *mut DialogSearch) };
    if unsafe { IsWindowVisible(hwnd) } == 0 {
        return 1; // continue
    }
    if unsafe { GetWindow(hwnd, GW_OWNER) } != search.owner {
        return 1; // continue
    }
    let mut buf = [0u16; 64];
    let n = unsafe { GetClassNameW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    if n <= 0 {
        return 1;
    }
    if String::from_utf16_lossy(&buf[..n as usize]) == CREDENTIAL_DIALOG_CLASS {
        search.found = hwnd;
        0 // stop
    } else {
        1
    }
}

/// Find the credential dialog owned by `owner`.
///
/// Enumerates top-level windows and matches class **and** owner, so a foreign
/// process cannot spoof the class name to steal focus. Returns null when no
/// owned, visible dialog exists.
fn find_owned_dialog(owner: Hwnd) -> Hwnd {
    let mut search = DialogSearch {
        owner,
        found: ptr::null_mut(),
    };
    unsafe {
        EnumWindows(
            Some(find_dialog_proc),
            &mut search as *mut DialogSearch as isize,
        );
    }
    search.found
}

/// Poll for the credential dialog and try to foreground it.
///
/// Cadence mirrors Chromium's `HelloDialogForegrounder`: a fast poll (~100 ms)
/// for the first ~40 iterations, then a slow poll (~500 ms) so a PIN-retry
/// dialog that reappears is caught too. It returns promptly once `stop` is set.
///
/// Each distinct dialog handle is escalated **once** (direct request, then the
/// input-queue attach, then a taskbar flash); subsequent polls only re-check
/// whether it reached the foreground, so the attach rung cannot spin and risk
/// an input-queue deadlock for the whole ceremony.
fn watcher_thread(stop: Arc<AtomicBool>, search: DialogSearch) {
    let owner = search.owner;
    // Prime this thread's message queue. `AttachThreadInput` can only attach a
    // thread that has a message queue, and a thread gets one on its first call
    // to a message function; `PM_NOREMOVE` leaves anything found in place. The
    // filter is a private `WM_USER` range so no unrelated posted message is
    // consumed.
    let mut msg: Msg = unsafe { mem::zeroed() };
    unsafe {
        PeekMessageW(&mut msg, ptr::null_mut(), WM_USER, WM_USER, PM_NOREMOVE);
    }

    let mut iteration: u32 = 0;
    let mut seen: Hwnd = ptr::null_mut();
    let mut escalated = false;

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let dialog = find_owned_dialog(owner);
        if dialog.is_null() {
            if !seen.is_null() {
                emit_progress("prompt_closed");
                seen = ptr::null_mut();
                escalated = false;
            }
        } else {
            if !seen.is_null() && dialog != seen {
                // The old dialog disappeared and a new one took its place
                // between polls (the save → PIN transition can swap handles
                // without an intervening null). Keep the stream paired so the
                // Linux side sees the step change, and reset escalation for the
                // new handle.
                emit_progress("prompt_closed");
                escalated = false;
            }
            if dialog != seen {
                emit_progress("prompt_open");
                seen = dialog;
            }
            if !escalated {
                // Rung 1 (direct) and rung 2 (attach) are attempted once per
                // handle; the flash timer is left running until it is
                // foregrounded or the handle disappears.
                try_foreground(dialog);
                escalated = true;
            } else if unsafe { GetForegroundWindow() } != dialog {
                // Still behind after the one-shot escalation: keep the taskbar
                // button flashing without re-attaching input queues.
                flash(dialog);
            }
        }

        iteration += 1;
        let delay = if iteration <= 40 {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(500)
        };
        thread::sleep(delay);
    }

    // The ceremony ended while a dialog was still known to be up; report the
    // close so the Linux side does not keep waiting on a prompt that is gone.
    if !seen.is_null() {
        emit_progress("prompt_closed");
    }
}

/// Attempt to raise `dialog`, cheapest rung first. Called **once per dialog**.
///
/// Success is decided by **observing** `GetForegroundWindow()`, never by the
/// `SetForegroundWindow` return value, which is documented as unreliable and
/// partly asynchronous.
fn try_foreground(dialog: Hwnd) {
    if unsafe { GetForegroundWindow() } == dialog {
        return;
    }

    // Rung 1: the cheap direct request. Usually denied for a WSL-interop child,
    // but free when it is not.
    unsafe {
        SetForegroundWindow(dialog);
    }
    if unsafe { GetForegroundWindow() } == dialog {
        return;
    }

    // Rung 2: share this thread's input queue with the foreground thread for
    // the duration of the raise. Skipped when there is no distinct foreground
    // thread (or its id is unknown).
    let fg = unsafe { GetForegroundWindow() };
    if !fg.is_null() {
        let my_tid = unsafe { GetCurrentThreadId() };
        let fg_tid = unsafe { GetWindowThreadProcessId(fg, ptr::null_mut()) };
        if fg_tid != 0 && my_tid != 0 && fg_tid != my_tid {
            if unsafe { IsIconic(dialog) } != 0 {
                unsafe {
                    ShowWindow(dialog, SW_RESTORE);
                }
            }
            // The guard detaches even if a call below panics or returns early.
            let attached = AttachedInput::attach(my_tid, fg_tid);
            unsafe {
                SetForegroundWindow(dialog);
                BringWindowToTop(dialog);
                SetFocus(dialog);
            }
            drop(attached);
            if unsafe { GetForegroundWindow() } == dialog {
                return;
            }
        }
    }

    // Rung 3: non-intrusive taskbar flash. Windows itself does this when it
    // denies `SetForegroundWindow`.
    flash(dialog);
}

/// Start/continue a taskbar flash that stops once `dialog` is foregrounded.
fn flash(dialog: Hwnd) {
    let mut info = FlashWInfo {
        cb_size: mem::size_of::<FlashWInfo>() as u32,
        hwnd: dialog,
        dw_flags: FLASHW_ALL | FLASHW_TIMERNOFG,
        u_count: 0,
        dw_timeout: 0,
    };
    unsafe {
        FlashWindowEx(&mut info);
    }
}

/// RAII guard for `AttachThreadInput(..., TRUE)`.
///
/// The input queues are detached in `Drop` on every path, so the watcher thread
/// can never leave itself attached to the foreground thread. The `attached`
/// flag records whether the attach actually succeeded, so a failed attach is
/// not paired with a spurious detach.
struct AttachedInput {
    attached: bool,
    from: u32,
    to: u32,
}

impl AttachedInput {
    fn attach(from: u32, to: u32) -> AttachedInput {
        let attached = unsafe { AttachThreadInput(from, to, ATTACH_TRUE) } != 0;
        AttachedInput { attached, from, to }
    }
}

impl Drop for AttachedInput {
    fn drop(&mut self) {
        if self.attached {
            unsafe {
                AttachThreadInput(self.from, self.to, ATTACH_FALSE);
            }
        }
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
    /// Optional: some pre-1903 DLLs do not export `WebAuthNGetErrorName`.
    /// Used for bounded stderr diagnostics only; when absent,
    /// [`Win32Api::log_error`] falls back to the literal `UnknownError`. It is
    /// deliberately **not** a load gate.
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
    /// Hardening: `SetDefaultDllDirectories` narrows the **process**
    /// default DLL search order to `%SystemRoot%\System32` before the first
    /// load, and the explicit `LoadLibraryExW` is additionally passed
    /// `LOAD_LIBRARY_SEARCH_SYSTEM32`. The process-wide call matters because
    /// `LoadLibraryExW`'s flag pins only the named module: the dependencies
    /// `webauthn.dll` pulls in are resolved against the process default order,
    /// which otherwise includes the bridge's Windows mount-root working
    /// directory. The call is idempotent; `load()` is called once
    /// per process here, but repeating it is harmless.
    pub fn load() -> Result<Win32Api, BridgeError> {
        // SAFETY: no pointers; returns a BOOL we intentionally ignore. Narrowing
        // the default search path is best-effort: if it fails (e.g. a very old
        // OS) the explicit per-load flag below still applies to `webauthn.dll`
        // itself. Off-Windows this is unverified.
        unsafe {
            SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
        }
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

        // `get_error_name` is intentionally *not* in this required set: it is
        // documented optional and only feeds stderr diagnostics. A
        // missing export is represented by `None` and handled by `log_error`.
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
            // requires moving the handle first. Freeing the handle here is the
            // observable "load failed" side effect.
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

    /// The HWND handed to the ceremony: the current **foreground** window when
    /// it is a foreign window, otherwise the hidden window, then the
    /// top-level window, then the desktop window.
    ///
    /// The WebAuthN `hWnd` is the *owner* of the Hello dialog. Passing the
    /// window the user is looking at makes Windows create the dialog in front
    /// of it, whereas passing our hidden `WS_POPUP` window owns the dialog to a
    /// background window, placing it behind the terminal. This matches
    /// libfido2's `winhello.c`, which passes `GetForegroundWindow()`; our own
    /// hidden window is excluded so the fallback chain
    /// (`GetTopWindow(NULL)`, then `GetDesktopWindow()` as a last resort so the
    /// parameter is never NULL) still applies. The API only requires *a* window
    /// handle — it is not used as a parent for a child window — so cross-thread
    /// use of a foreign top-level HWND is sound.
    fn hwnd(&self) -> Hwnd {
        let fg_raw = unsafe { GetForegroundWindow() };
        // Only trust a *visible* foreground window; a hidden/minimized one is no
        // better an owner than our own hidden window.
        let fg = if !fg_raw.is_null() && unsafe { IsWindowVisible(fg_raw) } != 0 {
            fg_raw
        } else {
            ptr::null_mut()
        };
        let own_hidden = self
            .window
            .as_ref()
            .map(|w| w.hwnd)
            .unwrap_or(ptr::null_mut());
        let top = unsafe { GetTopWindow(ptr::null_mut()) };
        let desktop = unsafe { GetDesktopWindow() };
        crate::api::choose_owner(fg, own_hidden, top, desktop)
    }

    fn api_version(&self) -> u32 {
        match self.dll.get_api_version_number {
            Some(f) => unsafe { f() },
            None => 0,
        }
    }

    fn log_error(&self, context: &str, hr: Hresult) {
        let name = error_name(self.dll.get_error_name, hr);
        eprintln!("{context}: hr=0x{:08X} {name}", hr as u32);
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

        // Full v9 size, zero-init, dwVersion = 3: the v1..v3 fields we set
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
        // Resolve the owner **before** arming the watcher, so the watcher's own
        // best-effort foreground attempts cannot change which window the dialog
        // is parented to.
        let owner = self.hwnd();
        // Best-effort focus watcher for the duration of the blocking call; it
        // never affects `hr` and is dropped (stop-signalled, not joined) as soon
        // as the ceremony returns.
        let _focus = FocusWatcher::arm(owner);
        let hr = unsafe {
            (self.dll.make_credential)(owner, &rp, &user, &cose_params, &cd, &options, &mut out)
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

        // Full v9 size, zero-init, dwVersion = 4: pAllowCredentialList is a
        // v4 field, pCancellationId a v3 field, both required here.
        let mut options: GetAssertionOptionsRaw = unsafe { mem::zeroed() };
        options.dw_version = 4;
        options.dw_timeout_milliseconds = o.timeout_ms;
        options.dw_authenticator_attachment = o.attachment as u32;
        options.dw_user_verification_requirement = o.uv_requirement as u32;
        options.p_cancellation_id = &mut guid;
        options.p_allow_credential_list = &mut allow_list;

        let mut out: *mut AssertionRaw = ptr::null_mut();
        // Resolve the owner before arming the watcher (see `make_credential`).
        let owner = self.hwnd();
        // Best-effort focus watcher for the duration of the blocking call; see
        // `make_credential`.
        let _focus = FocusWatcher::arm(owner);
        let hr =
            unsafe { (self.dll.get_assertion)(owner, rp_id.as_ptr(), &cd, &options, &mut out) };

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
    #[cfg(windows)]
    use std::time::Instant;

    // ABI layout guards. These run on the Windows CI job (the module only
    // compiles on Windows) and pin the sizes we derived from the public
    // `webauthn.h`. The structs are declared at a *newer* version than we fill,
    // so under-allocation is the only failure mode; the guard makes that a
    // compile-time-independent test.
    #[test]
    fn guid_is_16_bytes() {
        assert_eq!(mem::size_of::<Guid>(), 16);
    }

    // A missing/optional `WebAuthNGetErrorName` export must still produce a
    // stable name, not a load failure or a panic.
    #[test]
    fn error_name_falls_back_when_export_is_absent() {
        assert_eq!(error_name(None, 0x8009_0036u32 as Hresult), "UnknownError");
        assert_eq!(error_name(None, 0), "UnknownError");
    }

    #[test]
    fn guid_explicit_round_trip_matches_byte_image() {
        // Field-wise construction pins the little-endian byte image the
        // platform's `GUID` uses.
        let patterns: [[u8; 16]; 3] = [
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ],
            [0x00; 16],
            [0xFF; 16],
        ];
        for bytes in patterns {
            let g = guid_from_bytes(bytes);
            assert_eq!(
                g.data1,
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            );
            assert_eq!(g.data2, u16::from_le_bytes([bytes[4], bytes[5]]));
            assert_eq!(g.data3, u16::from_le_bytes([bytes[6], bytes[7]]));
            assert_eq!(g.data4, bytes[8..16]);
            assert_eq!(bytes_from_guid(g), bytes);
        }
    }

    // ---- hidden-window lifecycle (Windows-gated) -------------------------

    /// Creating the hidden window and dropping it must join the pump thread
    /// promptly. This proves the current pattern terminates, so it must run on
    /// a real Windows host (it does compile here under the gnu target).
    #[cfg(windows)]
    #[test]
    fn hidden_window_create_and_drop_returns_promptly() {
        let start = Instant::now();
        if let Some(w) = HiddenWindow::create() {
            assert!(
                !w.hwnd.is_null(),
                "created window must have a non-null HWND"
            );
            assert_ne!(w.pump_thread_id, 0, "pump thread id must be known");
            drop(w);
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "create+drop took {:?}",
            start.elapsed()
        );
    }

    /// A `CreateWindowExW` failure must be observable as `None` (the caller
    /// falls back to the foreground window) and must not block on the pump.
    /// The unregistered class guarantees the failure without touching system
    /// state.
    #[cfg(windows)]
    #[test]
    fn hidden_window_create_failure_is_observable_as_none() {
        let start = Instant::now();
        let w = create_inner(wide("WSLWebAuthnBridgeNeverRegistered"), false);
        assert!(w.is_none());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "failed create took {:?}",
            start.elapsed()
        );
    }

    /// Arming and dropping the focus watcher must return promptly even when no
    /// credential dialog exists: the drop only sets a stop flag and never joins
    /// the (possibly stuck) watcher thread. Mirrors
    /// `hidden_window_create_and_drop_returns_promptly`.
    #[cfg(windows)]
    #[test]
    fn focus_watcher_arm_and_drop_returns_promptly() {
        let start = Instant::now();
        let guard = FocusWatcher::arm(ptr::null_mut());
        drop(guard);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "arm+drop took {:?}",
            start.elapsed()
        );
    }

    /// `try_foreground` on a non-existent handle must return promptly (the
    /// Win32 calls fail fast, and nothing blocks).
    #[cfg(windows)]
    #[test]
    fn try_foreground_on_bogus_handle_returns_promptly() {
        let start = Instant::now();
        try_foreground(0xdead_beefusize as Hwnd);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "try_foreground took {:?}",
            start.elapsed()
        );
    }

    /// `FLASHWINFO` layout guard: `#[repr(C)]` on x86_64 gives
    /// `cbSize` (4) + pad (4) + `hwnd` (8) + `dwFlags` (4) + `uCount` (4) +
    /// `dwTimeout` (4) + tail pad (4) = 32 bytes. This is the buffer
    /// `FlashWindowEx` reads, so an under-allocation would be a real bug.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn flashwinfo_layout_matches_public_header() {
        assert_eq!(mem::size_of::<FlashWInfo>(), 32);
        assert_eq!(mem::offset_of!(FlashWInfo, cb_size), 0);
        assert_eq!(mem::offset_of!(FlashWInfo, hwnd), 8);
        assert_eq!(mem::offset_of!(FlashWInfo, dw_flags), 16);
        assert_eq!(mem::offset_of!(FlashWInfo, u_count), 20);
        assert_eq!(mem::offset_of!(FlashWInfo, dw_timeout), 24);
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
        assert_eq!(mem::size_of::<HmacSecretSalt>(), 32);
        assert_eq!(mem::size_of::<HmacSecretSaltValues>(), 24);
        assert_eq!(mem::size_of::<RpEntityInformation>(), 32);
        assert_eq!(mem::size_of::<UserEntityInformation>(), 40);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn critical_field_offsets_match_public_header() {
        // Independently recomputed from `webauthn.h` with a C `offsetof` program;
        // these pin the exact byte positions the DLL reads/writes.
        assert_eq!(mem::offset_of!(CredentialEx, cb_id), 4);
        assert_eq!(mem::offset_of!(CredentialEx, pb_id), 8);
        assert_eq!(mem::offset_of!(CredentialEx, dw_transports), 24);
        assert_eq!(
            mem::offset_of!(CredentialAttestationRaw, pwsz_format_type),
            8
        );
        assert_eq!(
            mem::offset_of!(CredentialAttestationRaw, pb_attestation_object),
            72
        );
        assert_eq!(
            mem::offset_of!(CredentialAttestationRaw, pb_credential_id),
            88
        );
        assert_eq!(
            mem::offset_of!(CredentialAttestationRaw, pb_client_data_json),
            168
        );
        assert_eq!(
            mem::offset_of!(CredentialAttestationRaw, pb_registration_response_json),
            184
        );
        assert_eq!(mem::offset_of!(AssertionRaw, cb_authenticator_data), 4);
        assert_eq!(mem::offset_of!(AssertionRaw, pb_authenticator_data), 8);
        assert_eq!(mem::offset_of!(AssertionRaw, pb_signature), 24);
        assert_eq!(mem::offset_of!(AssertionRaw, credential), 32);
        assert_eq!(mem::offset_of!(AssertionRaw, pb_user_id), 64);
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
