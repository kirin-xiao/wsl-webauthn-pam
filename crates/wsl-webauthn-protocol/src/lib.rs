//! Wire protocol shared by the Linux side and the Windows bridge.
//!
//! Everything in this crate is OS-agnostic: it compiles identically on
//! Linux and Windows and contains no `unsafe`, no filesystem, and no OS calls. It is
//! the cross-crate contract for `wsl-webauthn-runner`, `wsl-webauthn-bridge`, and
//! (transitively) the verifier/PAM/CLI crates.
//!
//! # Wire contract
//!
//! * [`RP_ID`] and [`ORIGIN`] are pinned at compile time. The wire format
//!   never carries them; both sides derive their parameters from these constants. The
//!   origin is the RP ID itself because this is a native client with no browser origin.
//!   Changing either value requires a rebuild *and* re-enrollment.
//! * Framing is a 4-byte little-endian length prefix followed by a UTF-8 JSON payload.
//!   Requests are capped at [`MAX_REQUEST_BYTES`], responses at
//!   [`MAX_RESPONSE_BYTES`]; all reads are bounded.
//! * All binary fields on the wire are `base64url` (RFC 4648 §5) **without** padding.
//! * `clientDataJSON` is built on the Linux side (which owns the challenge) and passed
//!   verbatim; see [`build_client_data`].
//!
//! # Crate layout
//!
//! The two-sided wire contract (requests, responses, framing, `RP_ID`/`ORIGIN`, size
//! caps) lives in the crate root. Linux/client-only members — [`build_client_data`],
//! [`ClientDataKind`], the [`ProtocolError`] it returns, and the process-deadline /
//! bridge-`timeout_ms` defaults — are grouped in the [`client`] module and re-exported
//! here. The Windows bridge does not use them: it treats `client_data_json` as an opaque
//! base64url string and does not rebuild the Linux-side timing defaults.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// `Response`'s variant fields are necessarily public (Rust gives enum-variant fields the
// enum's visibility), so the opaque `OkFlag` used to pin `ok` trips the
// `private_interfaces` lint. The field is intentionally reachable-but-not-constructible:
// callers can read it by `..`-pattern/shadow-matching but cannot `use` its type or build it.
#![allow(private_interfaces)]

use std::io::Read;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod client;

// Linux/client-only helpers, re-exported from [`client`].
pub use client::{
    BRIDGE_AUTH_TIMEOUT_MS, BRIDGE_ENROLL_TIMEOUT_MS, ClientDataKind, DEFAULT_AUTH_TIMEOUT_SECS,
    DEFAULT_ENROLL_TIMEOUT_SECS, MIN_CHALLENGE_BYTES, ProtocolError, build_client_data,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Relying Party ID, pinned at compile time.
///
/// This value is hashed into `rpIdHash` inside `authenticatorData` and is part of the
/// WebAuthn ceremony. It must never be transmitted on the wire.
pub const RP_ID: &str = "io.github.kirin-xiao.wsl-webauthn-pam";

/// Human-readable Relying Party name shown by the platform UI during enrollment.
pub const RP_NAME: &str = "sudo on WSL (wsl-webauthn-pam)";

/// WebAuthn origin, pinned equal to [`RP_ID`].
///
/// This is a native client with no browser origin. The value is a pinned constant, not
/// an origin *guarantee*; it is placed verbatim in `clientDataJSON` and checked byte for
/// byte on the Linux side.
pub const ORIGIN: &str = RP_ID;

/// Maximum accepted framed request size (8 KiB).
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Maximum accepted framed response size (64 KiB).
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from framing and base64url decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    /// The stream ended before or during a frame (clean EOF or short read).
    #[error("unexpected end of frame stream")]
    Eof,
    /// A frame declared/contained more bytes than the supplied cap allows.
    #[error("frame exceeds size cap of {cap} bytes (declared {declared})")]
    TooLarge {
        /// The enforced cap.
        cap: usize,
        /// The size declared by the length prefix (or the remaining payload).
        declared: usize,
    },
    /// An underlying IO error occurred.
    #[error("i/o error while reading frame: {0}")]
    Io(String),
    /// A base64url field was not valid `base64url` (no padding) input.
    #[error("invalid base64url value")]
    Base64,
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// Encode `payload` as a length-prefixed frame: 4-byte little-endian length + bytes.
///
/// No length cap is enforced here; callers are responsible for choosing a payload that
/// fits the relevant [`MAX_REQUEST_BYTES`] / [`MAX_RESPONSE_BYTES`] budget.
#[must_use]
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Read exactly one frame from `r`, enforcing `cap` on the declared length.
///
/// Returns:
/// * [`FrameError::Eof`] if the stream is empty before the length prefix, or if it ends
///   before the declared payload is complete (short read).
/// * [`FrameError::TooLarge`] if the declared length exceeds `cap`. In that case the
///   payload is **not** read, so the stream is left positioned after the prefix.
/// * [`FrameError::Io`] for underlying IO errors.
///
/// Reads are always bounded by `min(declared, cap)`; this never allocates more than the
/// cap.
pub fn read_frame<R: Read>(r: &mut R, cap: usize) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    read_exact_or_eof(r, &mut len_buf)?;
    let declared = u32::from_le_bytes(len_buf) as usize;

    if declared > cap {
        return Err(FrameError::TooLarge { cap, declared });
    }

    let mut payload = vec![0u8; declared];
    read_exact_or_eof(r, &mut payload)?;
    Ok(payload)
}

/// Fill `buf` completely, mapping a clean EOF (zero bytes read so far) to
/// [`FrameError::Eof`] and a mid-read EOF to [`FrameError::Eof`] as well.
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => return Err(FrameError::Eof),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e.to_string())),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// base64url helpers
// ---------------------------------------------------------------------------

/// Encode bytes as unpadded `base64url` (RFC 4648 §5).
#[must_use]
pub fn b64u_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode unpadded `base64url` (RFC 4648 §5).
///
/// Padded input is rejected (we always emit unpadded); malformed input yields
/// [`FrameError::Base64`] rather than panicking.
pub fn b64u_decode(s: &str) -> Result<Vec<u8>, FrameError> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|_| FrameError::Base64)
}

// ---------------------------------------------------------------------------
// Wire types: Request
// ---------------------------------------------------------------------------

/// A request from the Linux side to the Windows bridge.
///
/// Serialized as a single JSON object tagged by `"op"`. All binary fields are unpadded
/// `base64url` strings. Unknown fields are rejected (`deny_unknown_fields`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Ask whether a user-verifying platform authenticator is available.
    Probe {
        /// Per-ceremony timeout in milliseconds.
        timeout_ms: u32,
    },
    /// Create a credential bound to the given Linux user.
    Enroll {
        /// `clientDataJSON` built on the Linux side (b64url), passed verbatim.
        client_data_json: String,
        /// WebAuthn user handle, ≤ 64 bytes, b64url.
        user_id: String,
        /// WebAuthn user name (e.g. the Linux login name).
        user_name: String,
        /// WebAuthn user display name.
        user_display_name: String,
        /// Allowed COSE algorithm identifiers in preference order.
        algs: Vec<i32>,
        /// Per-ceremony timeout in milliseconds.
        timeout_ms: u32,
    },
    /// Produce an assertion for one of the supplied credentials.
    Assert {
        /// `clientDataJSON` built on the Linux side (b64url), passed verbatim.
        client_data_json: String,
        /// Credential IDs the authenticator may use (b64url each).
        allow_credentials: Vec<String>,
        /// Per-ceremony timeout in milliseconds.
        timeout_ms: u32,
    },
}

impl Request {
    /// Encode this request as a framed JSON payload.
    pub fn to_frame(&self) -> Result<Vec<u8>, serde_json::Error> {
        Ok(encode_frame(&serde_json::to_vec(self)?))
    }
}

// ---------------------------------------------------------------------------
// Wire types: Response + BridgeError
// ---------------------------------------------------------------------------

/// Error taxonomy reported by the bridge.
///
/// A `Response::Error` is a *ceremony* failure delivered on an otherwise well-formed
/// transport; the Linux side maps it to PAM codes. A non-zero exit or a
/// malformed frame is a separate *transport* failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeError {
    /// No user-verifying platform authenticator is available.
    NotAvailable,
    /// `webauthn.dll` missing or too old to support the required API.
    NotSupported,
    /// The user dismissed/cancelled the Windows Hello prompt.
    UserCancelled,
    /// The ceremony exceeded its timeout.
    Timeout,
    /// Another ceremony is already in progress.
    Busy,
    /// A parameter was rejected (malformed request, bad size, …).
    InvalidParameter,
    /// Any other unexpected failure.
    Internal,
}

/// The `ok` discriminant of a [`Response`].
///
/// A variant's `ok` is **fixed by the variant**: `true` for the three success replies,
/// `false` for [`Response::Error`]. It is opaque and crate-private so a caller in another
/// crate cannot construct a well-formed frame with a contradictory `ok`
/// (e.g. `Response::Probe { ok: false, .. }`), which the peer would reject as a transport
/// failure. Serde serializes it as the plain boolean on the wire, byte-identically, and
/// deserialization is validated by [`expect_true`]/[`expect_false`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct OkFlag(bool);

/// A response from the Windows bridge to the Linux side.
///
/// Serialized as a single JSON object tagged by `"op"`, mirroring [`Request`]. The `ok`
/// field is **fixed per variant**: the three success variants always serialize
/// `"ok":true`, and [`Response::Error`] always serializes `"ok":false`. Deserialization
/// validates that `ok` matches the variant, so a mismatched `ok` is a parse error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// Reply to [`Request::Probe`].
    Probe {
        /// Always `true` for this variant; fixed by construction, checked on deserialize.
        #[serde(deserialize_with = "expect_true")]
        ok: OkFlag,
        /// Whether a user-verifying platform authenticator is available.
        uv_platform_available: bool,
        /// `WebAuthNGetApiVersionNumber()` as seen by the bridge.
        api_version: u32,
    },
    /// Reply to [`Request::Enroll`].
    Enroll {
        /// Always `true` for this variant; fixed by construction, checked on deserialize.
        #[serde(deserialize_with = "expect_true")]
        ok: OkFlag,
        /// Attestation statement format (e.g. `packed`, `none`).
        format: String,
        /// Full CBOR attestation object (b64url).
        attestation_object: String,
        /// Credential ID (b64url); cross-checked against `authData`.
        credential_id: String,
    },
    /// Reply to [`Request::Assert`].
    Assert {
        /// Always `true` for this variant; fixed by construction, checked on deserialize.
        #[serde(deserialize_with = "expect_true")]
        ok: OkFlag,
        /// Authenticator data (b64url).
        authenticator_data: String,
        /// Signature over `authenticatorData || SHA-256(clientDataJSON)` (b64url).
        signature: String,
        /// Credential ID used (b64url).
        credential_id: String,
        /// Echo of the request `clientDataJSON` when ASSERTION v6 is available; else null.
        client_data_json_echo: Option<String>,
    },
    /// A ceremony failure (transport itself succeeded).
    #[serde(rename = "*")]
    Error {
        /// Always `false` for this variant; fixed by construction, checked on deserialize.
        #[serde(deserialize_with = "expect_false")]
        ok: OkFlag,
        /// Which failure occurred.
        error: BridgeError,
    },
}

// The `op` tag for `Response::Error` is literally `"*"` on the wire.

/// Deserialize helper enforcing `ok == true` for success variants.
fn expect_true<'de, D>(d: D) -> Result<OkFlag, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = bool::deserialize(d)?;
    if v {
        Ok(OkFlag(true))
    } else {
        Err(serde::de::Error::custom("expected `ok` to be true"))
    }
}

/// Deserialize helper enforcing `ok == false` for the error variant.
fn expect_false<'de, D>(d: D) -> Result<OkFlag, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = bool::deserialize(d)?;
    if v {
        Err(serde::de::Error::custom("expected `ok` to be false"))
    } else {
        Ok(OkFlag(false))
    }
}

impl Response {
    /// Build a probe success response.
    pub fn probe(uv_platform_available: bool, api_version: u32) -> Self {
        Response::Probe {
            ok: OkFlag(true),
            uv_platform_available,
            api_version,
        }
    }

    /// Build an enroll success response.
    pub fn enroll(
        format: impl Into<String>,
        attestation_object: impl Into<String>,
        credential_id: impl Into<String>,
    ) -> Self {
        Response::Enroll {
            ok: OkFlag(true),
            format: format.into(),
            attestation_object: attestation_object.into(),
            credential_id: credential_id.into(),
        }
    }

    /// Build an assert success response.
    pub fn assertion(
        authenticator_data: impl Into<String>,
        signature: impl Into<String>,
        credential_id: impl Into<String>,
        client_data_json_echo: Option<String>,
    ) -> Self {
        Response::Assert {
            ok: OkFlag(true),
            authenticator_data: authenticator_data.into(),
            signature: signature.into(),
            credential_id: credential_id.into(),
            client_data_json_echo,
        }
    }

    /// Build a ceremony-failure response.
    pub fn error(error: BridgeError) -> Self {
        Response::Error {
            ok: OkFlag(false),
            error,
        }
    }

    /// Encode this response as a framed JSON payload.
    pub fn to_frame(&self) -> Result<Vec<u8>, serde_json::Error> {
        Ok(encode_frame(&serde_json::to_vec(self)?))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ---- framing ----

    #[test]
    fn frame_round_trip() {
        for payload in [&b""[..], b"hello", &[0u8; 300][..]] {
            let framed = encode_frame(payload);
            assert_eq!(&framed[..4], &(payload.len() as u32).to_le_bytes());
            let mut cur = Cursor::new(&framed);
            let got = read_frame(&mut cur, MAX_REQUEST_BYTES).unwrap();
            assert_eq!(got, payload);
        }
    }

    #[test]
    fn frame_length_prefix_is_little_endian() {
        let framed = encode_frame(b"abc");
        assert_eq!(framed, vec![3, 0, 0, 0, b'a', b'b', b'c']);
    }

    #[test]
    fn frame_cap_enforced_without_reading_payload() {
        // 1000-byte payload, cap 10 -> TooLarge, payload not consumed.
        let framed = encode_frame(&[0u8; 1000]);
        let mut cur = Cursor::new(&framed);
        let err = read_frame(&mut cur, 10).unwrap_err();
        assert_eq!(
            err,
            FrameError::TooLarge {
                cap: 10,
                declared: 1000
            }
        );
        // Stream positioned right after the 4-byte prefix.
        assert_eq!(cur.position(), 4);
    }

    #[test]
    fn frame_eof_on_empty_stream() {
        let mut cur = Cursor::new(&[][..]);
        assert_eq!(read_frame(&mut cur, 100).unwrap_err(), FrameError::Eof);
    }

    #[test]
    fn frame_eof_on_truncated_prefix() {
        let mut cur = Cursor::new(&[1u8, 2][..]);
        assert_eq!(read_frame(&mut cur, 100).unwrap_err(), FrameError::Eof);
    }

    #[test]
    fn frame_eof_on_truncated_payload() {
        // Prefix says 10 bytes but only 3 are present.
        let mut bytes = vec![10, 0, 0, 0];
        bytes.extend_from_slice(b"abc");
        let mut cur = Cursor::new(&bytes);
        assert_eq!(read_frame(&mut cur, 100).unwrap_err(), FrameError::Eof);
    }

    #[test]
    fn frame_accepts_exact_cap() {
        let framed = encode_frame(&[7u8; 16]);
        let mut cur = Cursor::new(&framed);
        assert_eq!(read_frame(&mut cur, 16).unwrap(), vec![7u8; 16]);
    }

    // ---- base64url ----

    #[test]
    fn b64u_round_trip() {
        for bytes in [&b""[..], b"hello", &[0xff, 0x00, 0xab][..]] {
            let encoded = b64u_encode(bytes);
            assert!(!encoded.contains('='), "output must be unpadded");
            assert_eq!(b64u_decode(&encoded).unwrap(), bytes);
        }
    }

    #[test]
    fn b64u_known_vector_matches_rfc4648() {
        // RFC 4648 §10: "foobar" -> "Zm9vYmFy"; urlsafe differs at bytes 0xfb/0xff.
        assert_eq!(b64u_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64u_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64u_encode(&[0xfb]), "-w");
    }

    #[test]
    fn b64u_rejects_bad_input_without_panic() {
        for bad in ["!!!!", "a", "ab=c", "a+b/", "AAAA===="] {
            assert!(
                matches!(b64u_decode(bad), Err(FrameError::Base64)),
                "expected Base64 error for {bad:?}"
            );
        }
    }

    // ---- wire JSON: golden conformance samples ----

    #[test]
    fn request_probe_golden() {
        let req = Request::Probe { timeout_ms: 3000 };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"op":"probe","timeout_ms":3000}"#
        );
        let round: Request = serde_json::from_str(r#"{"op":"probe","timeout_ms":3000}"#).unwrap();
        assert_eq!(round, req);
    }

    #[test]
    fn request_enroll_golden() {
        let req = Request::Enroll {
            client_data_json: "AAAA".into(),
            user_id: "YWxpY2U".into(),
            user_name: "alice".into(),
            user_display_name: "alice (Linux sudo)".into(),
            algs: vec![-7, -257],
            timeout_ms: 55_000,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"op":"enroll","client_data_json":"AAAA","user_id":"YWxpY2U","user_name":"alice","user_display_name":"alice (Linux sudo)","algs":[-7,-257],"timeout_ms":55000}"#
        );
        let round: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(round, req);
    }

    #[test]
    fn request_assert_golden() {
        let req = Request::Assert {
            client_data_json: "AAAA".into(),
            allow_credentials: vec!["YWJjMTIz".into()],
            timeout_ms: 55_000,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"op":"assert","client_data_json":"AAAA","allow_credentials":["YWJjMTIz"],"timeout_ms":55000}"#
        );
        let round: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(round, req);
    }

    #[test]
    fn request_rejects_unknown_field() {
        let err = serde_json::from_str::<Request>(r#"{"op":"probe","timeout_ms":1,"x":2}"#);
        assert!(err.is_err());
    }

    #[test]
    fn request_rejects_missing_field() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"probe"}"#).is_err());
    }

    #[test]
    fn request_rejects_unknown_op() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"bogus"}"#).is_err());
    }

    #[test]
    fn response_probe_golden() {
        let resp = Response::probe(true, 7);
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"op":"probe","ok":true,"uv_platform_available":true,"api_version":7}"#
        );
        assert_eq!(
            serde_json::from_str::<Response>(
                r#"{"op":"probe","ok":true,"uv_platform_available":true,"api_version":7}"#
            )
            .unwrap(),
            resp
        );
    }

    #[test]
    fn response_enroll_golden() {
        let resp = Response::enroll("packed", "AAAA", "YWJj");
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"op":"enroll","ok":true,"format":"packed","attestation_object":"AAAA","credential_id":"YWJj"}"#
        );
        assert_eq!(
            serde_json::from_str::<Response>(
                r#"{"op":"enroll","ok":true,"format":"packed","attestation_object":"AAAA","credential_id":"YWJj"}"#
            )
            .unwrap(),
            resp
        );
    }

    #[test]
    fn response_assert_golden_with_and_without_echo() {
        let echoed = Response::assertion("AAAA", "BBBB", "YWJj", Some("AAAA".into()));
        assert_eq!(
            serde_json::to_string(&echoed).unwrap(),
            r#"{"op":"assert","ok":true,"authenticator_data":"AAAA","signature":"BBBB","credential_id":"YWJj","client_data_json_echo":"AAAA"}"#
        );

        let no_echo = Response::assertion("AAAA", "BBBB", "YWJj", None);
        assert_eq!(
            serde_json::to_string(&no_echo).unwrap(),
            r#"{"op":"assert","ok":true,"authenticator_data":"AAAA","signature":"BBBB","credential_id":"YWJj","client_data_json_echo":null}"#
        );
        assert_eq!(
            serde_json::from_str::<Response>(
                r#"{"op":"assert","ok":true,"authenticator_data":"AAAA","signature":"BBBB","credential_id":"YWJj","client_data_json_echo":null}"#
            )
            .unwrap(),
            no_echo
        );
    }

    #[test]
    fn response_error_golden_all_variants() {
        for (err, wire) in [
            (BridgeError::NotAvailable, "not_available"),
            (BridgeError::NotSupported, "not_supported"),
            (BridgeError::UserCancelled, "user_cancelled"),
            (BridgeError::Timeout, "timeout"),
            (BridgeError::Busy, "busy"),
            (BridgeError::InvalidParameter, "invalid_parameter"),
            (BridgeError::Internal, "internal"),
        ] {
            let resp = Response::error(err);
            let expected = format!(r#"{{"op":"*","ok":false,"error":"{wire}"}}"#);
            assert_eq!(serde_json::to_string(&resp).unwrap(), expected);
            assert_eq!(serde_json::from_str::<Response>(&expected).unwrap(), resp);
        }
    }

    #[test]
    fn response_ok_flag_is_validated() {
        // Success variant with ok:false is a parse error.
        assert!(
            serde_json::from_str::<Response>(
                r#"{"op":"probe","ok":false,"uv_platform_available":true,"api_version":7}"#
            )
            .is_err()
        );
        // Error variant with ok:true is a parse error.
        assert!(
            serde_json::from_str::<Response>(r#"{"op":"*","ok":true,"error":"timeout"}"#).is_err()
        );
    }

    /// `ok` is pinned by the variant (the opaque [`OkFlag`] type cannot be named or
    /// constructed outside this crate), and the wire bytes for every valid case are
    /// unchanged — a deserialize→serialize round trip is byte-identical.
    #[test]
    fn response_ok_flag_wire_bytes_are_pinned() {
        let cases: [(Response, bool); 4] = [
            (Response::probe(true, 7), true),
            (Response::enroll("packed", "AAAA", "YWJj"), true),
            (Response::assertion("AAAA", "BBBB", "YWJj", None), true),
            (Response::error(BridgeError::Timeout), false),
        ];
        for (resp, ok) in cases {
            let json = serde_json::to_string(&resp).unwrap();
            let token = format!(r#""ok":{ok}"#);
            assert!(
                json.contains(&token),
                "expected {token} for {resp:?}: {json}"
            );
        }

        // Two-sided wire: the exact bytes the peer produces must survive a round trip.
        for wire in [
            r#"{"op":"probe","ok":true,"uv_platform_available":true,"api_version":7}"#,
            r#"{"op":"enroll","ok":true,"format":"packed","attestation_object":"AAAA","credential_id":"YWJj"}"#,
            r#"{"op":"assert","ok":true,"authenticator_data":"AAAA","signature":"BBBB","credential_id":"YWJj","client_data_json_echo":null}"#,
            r#"{"op":"*","ok":false,"error":"timeout"}"#,
        ] {
            let resp: Response = serde_json::from_str(wire).unwrap();
            assert_eq!(serde_json::to_string(&resp).unwrap(), wire);
        }
    }

    #[test]
    fn request_to_frame_round_trips_through_read_frame() {
        let req = Request::Assert {
            client_data_json: "AAAA".into(),
            allow_credentials: vec![],
            timeout_ms: 1,
        };
        let frame = req.to_frame().unwrap();
        assert!(frame.len() <= MAX_REQUEST_BYTES);
        let mut cur = Cursor::new(&frame);
        let payload = read_frame(&mut cur, MAX_REQUEST_BYTES).unwrap();
        let decoded: Request = serde_json::from_slice(&payload).unwrap();
        assert_eq!(decoded, req);

        let resp = Response::error(BridgeError::Busy);
        let frame = resp.to_frame().unwrap();
        let mut cur = Cursor::new(&frame);
        let payload = read_frame(&mut cur, MAX_RESPONSE_BYTES).unwrap();
        assert_eq!(serde_json::from_slice::<Response>(&payload).unwrap(), resp);
    }

    // ---- clientDataJSON ----

    /// The Linux-only client helpers are grouped under [`client`] and re-exported
    /// at the crate root; both paths name the same items.
    #[test]
    fn client_helpers_are_reachable_via_module_and_root() {
        let via_root = build_client_data(ClientDataKind::Get, &[0u8; 16]).unwrap();
        let via_mod = crate::client::build_client_data(ClientDataKind::Get, &[0u8; 16]).unwrap();
        assert_eq!(via_root, via_mod);
        assert_eq!(crate::client::ClientDataKind::Get, ClientDataKind::Get);
        assert_eq!(crate::client::MIN_CHALLENGE_BYTES, MIN_CHALLENGE_BYTES);
        assert_eq!(
            crate::client::BRIDGE_AUTH_TIMEOUT_MS,
            BRIDGE_AUTH_TIMEOUT_MS
        );
        assert_eq!(
            crate::client::DEFAULT_ENROLL_TIMEOUT_SECS,
            DEFAULT_ENROLL_TIMEOUT_SECS
        );
    }

    #[test]
    fn client_data_get_golden_bytes() {
        let challenge = [0u8; 32];
        let got = build_client_data(ClientDataKind::Get, &challenge).unwrap();
        let expected = format!(
            r#"{{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"{ORIGIN}"}}"#
        );
        assert_eq!(got, expected.as_bytes());
    }

    #[test]
    fn client_data_create_golden_bytes() {
        // bytes 0..=15 -> "AAECAwQFBgcICQoLDA0ODw"
        let challenge: Vec<u8> = (0u8..16).collect();
        let got = build_client_data(ClientDataKind::Create, &challenge).unwrap();
        let expected = format!(
            r#"{{"type":"webauthn.create","challenge":"AAECAwQFBgcICQoLDA0ODw","origin":"{ORIGIN}"}}"#
        );
        assert_eq!(got, expected.as_bytes());
    }

    #[test]
    fn client_data_field_order_is_type_challenge_origin() {
        let got = build_client_data(ClientDataKind::Get, &[0u8; 16]).unwrap();
        let s = std::str::from_utf8(&got).unwrap();
        let t = s.find("\"type\"").unwrap();
        let c = s.find("\"challenge\"").unwrap();
        let o = s.find("\"origin\"").unwrap();
        assert!(
            t < c && c < o,
            "field order must be type, challenge, origin"
        );
    }

    #[test]
    fn client_data_rejects_short_challenge() {
        let err = build_client_data(ClientDataKind::Get, &[0u8; 15]).unwrap_err();
        assert_eq!(err, ProtocolError::ChallengeTooShort { len: 15 });
        assert!(build_client_data(ClientDataKind::Get, &[]).is_err());
    }

    #[test]
    fn client_data_accepts_min_challenge() {
        assert!(build_client_data(ClientDataKind::Get, &[0u8; MIN_CHALLENGE_BYTES]).is_ok());
    }

    #[test]
    fn origin_pinned_to_rp_id() {
        assert_eq!(ORIGIN, RP_ID);
        assert_eq!(RP_ID, "io.github.kirin-xiao.wsl-webauthn-pam");
    }

    #[test]
    fn timeout_constants_have_headroom() {
        assert!(BRIDGE_AUTH_TIMEOUT_MS < (DEFAULT_AUTH_TIMEOUT_SECS * 1000) as u32);
        assert!(BRIDGE_ENROLL_TIMEOUT_MS < (DEFAULT_ENROLL_TIMEOUT_SECS * 1000) as u32);
        assert_eq!(MAX_REQUEST_BYTES, 8 * 1024);
        assert_eq!(MAX_RESPONSE_BYTES, 64 * 1024);
    }
}
