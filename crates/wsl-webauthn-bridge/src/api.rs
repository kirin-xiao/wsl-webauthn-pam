//! Platform-independent WebAuthn ceremony vocabulary and the [`WebAuthnApi`]
//! abstraction.
//!
//! Everything in this module compiles on Linux *and* Windows and contains no
//! `unsafe`. The ceremony logic in [`crate::ceremony`] is written against the
//! [`WebAuthnApi`] trait, so the exact option values the bridge derives from a
//! wire request are unit-testable without `webauthn.dll` and without a GUI.
//!
//! The real Win32 implementation lives in [`crate::ffi`] (`#[cfg(windows)]`);
//! tests supply a hand-written stub.

// All `unsafe` lives in `crate::ffi`.
#![forbid(unsafe_code)]
// This module mirrors the Win32 vocabulary in full. Variants that the
// bridge does not currently select are still a faithful transcription of
// `webauthn.h`; they carry a narrowly-scoped `#[allow(dead_code)]` each rather
// than a module-wide allow, so a genuinely orphaned item is still reported.

use std::fmt;

use wsl_webauthn_protocol::BridgeError;

/// Win32 `HRESULT` (`LONG` is `i32` on Windows).
pub type Hresult = i32;

/// `S_OK`.
#[allow(dead_code)] // consumed only by the `#[cfg(windows)]` FFI layer
pub const S_OK: Hresult = 0;

// ---------------------------------------------------------------------------
// HRESULT constants (winerror.h / ntsecapi.h)
// ---------------------------------------------------------------------------

/// `NTE_EXISTS` — a credential with the same identity already exists.
pub const NTE_EXISTS: Hresult = 0x8009_000Fu32 as Hresult;
/// `NTE_NOT_FOUND` — the requested credential was not found.
pub const NTE_NOT_FOUND: Hresult = 0x8009_0011u32 as Hresult;
/// `NTE_INVALID_PARAMETER` — the platform rejected a parameter.
pub const NTE_INVALID_PARAMETER: Hresult = 0x8009_0027u32 as Hresult;
/// `NTE_NOT_SUPPORTED` — the requested capability is not supported.
pub const NTE_NOT_SUPPORTED: Hresult = 0x8009_0029u32 as Hresult;
/// `NTE_DEVICE_NOT_FOUND` — no suitable authenticator/device.
pub const NTE_DEVICE_NOT_FOUND: Hresult = 0x8009_0035u32 as Hresult;
/// `NTE_USER_CANCELLED` — the user dismissed the prompt.
pub const NTE_USER_CANCELLED: Hresult = 0x8009_0036u32 as Hresult;

/// Win32 `ERROR_NOT_SUPPORTED`.
pub const ERROR_NOT_SUPPORTED: u32 = 50;
/// Win32 `ERROR_CANCELLED`.
pub const ERROR_CANCELLED: u32 = 1223;
/// Win32 `ERROR_TIMEOUT`.
pub const ERROR_TIMEOUT: u32 = 1460;

/// `HRESULT_FROM_WIN32(code)`.
///
/// Win32 error codes are positive, so this always sets the `FACILITY_WIN32`
/// bit; the `<= 0` short circuit of the C macro is preserved for completeness.
pub const fn hresult_from_win32(code: u32) -> Hresult {
    if code as Hresult <= 0 {
        code as Hresult
    } else {
        ((code & 0xFFFF) | 0x8007_0000) as Hresult
    }
}

/// Map a `webauthn.dll` HRESULT to the wire error taxonomy.
///
/// `S_OK` is not an error and maps to [`BridgeError::Internal`] only as a
/// defensive fallback (callers must not invoke this with `S_OK`).
pub const fn map_hresult(hr: Hresult) -> BridgeError {
    if hr == NTE_USER_CANCELLED || hr == hresult_from_win32(ERROR_CANCELLED) {
        BridgeError::UserCancelled
    } else if hr == hresult_from_win32(ERROR_TIMEOUT) {
        BridgeError::Timeout
    } else if hr == NTE_EXISTS {
        BridgeError::Busy
    } else if hr == NTE_NOT_SUPPORTED || hr == hresult_from_win32(ERROR_NOT_SUPPORTED) {
        BridgeError::NotSupported
    } else if hr == NTE_DEVICE_NOT_FOUND || hr == NTE_NOT_FOUND {
        BridgeError::NotAvailable
    } else if hr == NTE_INVALID_PARAMETER {
        BridgeError::InvalidParameter
    } else {
        BridgeError::Internal
    }
}

// ---------------------------------------------------------------------------
// Platform-independent option vocabulary
// ---------------------------------------------------------------------------

/// `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum UvRequirement {
    /// `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY`.
    #[allow(dead_code)] // faithful transcription; bridge pins `Required`
    Any = 0,
    /// `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED`.
    Required = 1,
    /// `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED`.
    #[allow(dead_code)] // faithful transcription; bridge pins `Required`
    Preferred = 2,
    /// `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED`.
    #[allow(dead_code)] // faithful transcription; bridge pins `Required`
    Discouraged = 3,
}

/// `WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AttestationConveyance {
    /// `WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY`.
    #[allow(dead_code)] // faithful transcription; bridge pins `Direct`
    Any = 0,
    /// `WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE`.
    #[allow(dead_code)] // faithful transcription; bridge pins `Direct`
    None = 1,
    /// `WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT`.
    #[allow(dead_code)] // faithful transcription; bridge pins `Direct`
    Indirect = 2,
    /// `WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT`.
    Direct = 3,
}

/// `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthenticatorAttachment {
    /// `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY`.
    #[allow(dead_code)] // faithful transcription; bridge pins `Platform`
    Any = 0,
    /// `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM`.
    Platform = 1,
    /// `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM`.
    #[allow(dead_code)] // faithful transcription; bridge pins `Platform`
    CrossPlatform = 2,
    /// `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2`.
    #[allow(dead_code)] // faithful transcription; bridge pins `Platform`
    CrossPlatformU2fV2 = 3,
}

/// A WebAuthn cancellation identifier (`GUID`, 16 opaque bytes).
///
/// The bytes are the raw `GUID` image returned by
/// `WebAuthNGetCancellationId`; they are only ever round-tripped back into
/// `WebAuthNCancelCurrentOperation`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CancellationId(pub [u8; 16]);

impl fmt::Debug for CancellationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CancellationId(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Result of a probe of the platform authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeInfo {
    /// `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable`.
    pub uv_platform_available: bool,
    /// `WebAuthNGetApiVersionNumber` (0 when the export is absent).
    pub api_version: u32,
}

/// Options handed to [`WebAuthnApi::make_credential`].
///
/// These are the semantic, wire-independent values the bridge derives from a
/// [`wsl_webauthn_protocol::Request::Enroll`] plus the compile-time RP
/// constants. The Windows FFI layer translates them 1:1 into
/// `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialOptions {
    /// RP ID (always [`wsl_webauthn_protocol::RP_ID`]).
    pub rp_id: String,
    /// RP name (always [`wsl_webauthn_protocol::RP_NAME`]).
    pub rp_name: String,
    /// WebAuthn user handle, ≤ 64 bytes.
    pub user_id: Vec<u8>,
    /// WebAuthn user name.
    pub user_name: String,
    /// WebAuthn user display name.
    pub user_display_name: String,
    /// Exact `clientDataJSON` bytes built by the Linux side.
    pub client_data_json: Vec<u8>,
    /// COSE algorithm identifiers (e.g. `[-7, -257]`).
    pub cose_algorithms: Vec<i32>,
    /// Advisory platform timeout in milliseconds.
    pub timeout_ms: u32,
    /// User-verification requirement (`REQUIRED` for enrollment).
    pub uv_requirement: UvRequirement,
    /// Attestation conveyance preference (`DIRECT` for enrollment).
    pub attestation: AttestationConveyance,
    /// Authenticator attachment (`PLATFORM`).
    pub attachment: AuthenticatorAttachment,
    /// `bRequireResidentKey` (`false`: non-resident credential).
    pub require_resident_key: bool,
    /// Cancellation id wired into `pCancellationId`.
    pub cancellation_id: CancellationId,
}

/// Options handed to [`WebAuthnApi::get_assertion`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionOptions {
    /// RP ID (always [`wsl_webauthn_protocol::RP_ID`]).
    pub rp_id: String,
    /// Exact `clientDataJSON` bytes built by the Linux side.
    pub client_data_json: Vec<u8>,
    /// Credential IDs the authenticator may use.
    pub allow_credential_ids: Vec<Vec<u8>>,
    /// Advisory platform timeout in milliseconds.
    pub timeout_ms: u32,
    /// User-verification requirement (`REQUIRED` for authentication).
    pub uv_requirement: UvRequirement,
    /// Authenticator attachment (`PLATFORM`).
    pub attachment: AuthenticatorAttachment,
    /// Cancellation id wired into `pCancellationId`.
    pub cancellation_id: CancellationId,
}

/// Successful enrollment result returned by the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialAttestation {
    /// `pwszFormatType` (e.g. `packed`, `none`).
    pub format: String,
    /// Full CBOR attestation object (`pbAttestationObject`).
    pub attestation_object: Vec<u8>,
    /// Credential ID (`pbCredentialId`).
    pub credential_id: Vec<u8>,
}

/// Successful assertion result returned by the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionResult {
    /// `pbAuthenticatorData`.
    pub authenticator_data: Vec<u8>,
    /// `pbSignature`.
    pub signature: Vec<u8>,
    /// `Credential.pbId`.
    pub credential_id: Vec<u8>,
    /// `pbClientDataJSON` echo, present only when the returned
    /// `WEBAUTHN_ASSERTION.dwVersion >= 6`.
    pub client_data_json_echo: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// The API abstraction
// ---------------------------------------------------------------------------

/// The subset of `webauthn.dll` the bridge drives.
///
/// Implementations must be cheap to share across threads: the ceremony layer
/// calls [`WebAuthnApi::cancel`] from a watchdog thread while the calling
/// thread is blocked inside [`WebAuthnApi::make_credential`] /
/// [`WebAuthnApi::get_assertion`].
pub trait WebAuthnApi: Send + Sync {
    /// Probe for a user-verifying platform authenticator.
    fn probe(&self) -> Result<ProbeInfo, BridgeError>;

    /// Fetch a cancellation id for the next ceremony.
    fn get_cancellation_id(&self) -> Result<CancellationId, BridgeError>;

    /// Create a credential (Windows Hello enrollment).
    fn make_credential(
        &self,
        options: &MakeCredentialOptions,
    ) -> Result<CredentialAttestation, BridgeError>;

    /// Produce an assertion using one of the allowed credentials.
    fn get_assertion(&self, options: &AssertionOptions) -> Result<AssertionResult, BridgeError>;

    /// Cancel the operation identified by `id` (best effort, watchdog only).
    fn cancel(&self, id: &CancellationId);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hresult_from_win32_matches_c_macro() {
        assert_eq!(
            hresult_from_win32(ERROR_NOT_SUPPORTED),
            0x8007_0032u32 as i32
        );
        assert_eq!(hresult_from_win32(ERROR_CANCELLED), 0x8007_04C7u32 as i32);
        assert_eq!(hresult_from_win32(ERROR_TIMEOUT), 0x8007_05B4u32 as i32);
    }

    #[test]
    fn ntstatus_constants_are_as_documented() {
        assert_eq!(NTE_EXISTS, 0x8009_000Fu32 as i32);
        assert_eq!(NTE_NOT_FOUND, 0x8009_0011u32 as i32);
        assert_eq!(NTE_INVALID_PARAMETER, 0x8009_0027u32 as i32);
        assert_eq!(NTE_NOT_SUPPORTED, 0x8009_0029u32 as i32);
        assert_eq!(NTE_DEVICE_NOT_FOUND, 0x8009_0035u32 as i32);
        assert_eq!(NTE_USER_CANCELLED, 0x8009_0036u32 as i32);
    }

    #[test]
    fn map_hresult_full_table() {
        let cases = [
            (NTE_USER_CANCELLED, BridgeError::UserCancelled),
            (
                hresult_from_win32(ERROR_CANCELLED),
                BridgeError::UserCancelled,
            ),
            (hresult_from_win32(ERROR_TIMEOUT), BridgeError::Timeout),
            (NTE_EXISTS, BridgeError::Busy),
            (NTE_NOT_SUPPORTED, BridgeError::NotSupported),
            (
                hresult_from_win32(ERROR_NOT_SUPPORTED),
                BridgeError::NotSupported,
            ),
            (NTE_DEVICE_NOT_FOUND, BridgeError::NotAvailable),
            (NTE_NOT_FOUND, BridgeError::NotAvailable),
            (NTE_INVALID_PARAMETER, BridgeError::InvalidParameter),
            (0x8000_4005u32 as i32, BridgeError::Internal),
            (0x8009_0037u32 as i32, BridgeError::Internal),
            (0, BridgeError::Internal),
        ];
        for (hr, expected) in cases {
            assert_eq!(map_hresult(hr), expected, "hr = 0x{:08X}", hr as u32);
        }
    }

    #[test]
    fn cancellation_id_is_display_safe() {
        let id = CancellationId([0xab; 16]);
        assert_eq!(
            format!("{id:?}"),
            "CancellationId(abababababababababababababababab)"
        );
    }
}
