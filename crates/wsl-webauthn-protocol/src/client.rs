//! Linux/client-side helpers layered on the wire contract.
//!
//! Everything in this module is used **only by the Linux side** (`wsl-webauthn-runner`,
//! `wsl-webauthn-pam`, `wsl-webauthn-cli`): the [`build_client_data`] serializer that
//! mints the exact `clientDataJSON` bytes, its [`ClientDataKind`]/[`ProtocolError`]
//! types, and the Linux process-deadline / bridge-`timeout_ms` defaults.
//!
//! The Windows bridge (`wsl-webauthn-bridge`) **must not use anything from this
//! module**. It receives `client_data_json` as an opaque base64url string on the wire
//! and does not rebuild it or second-guess the Linux-side deadline. These
//! items are separated here so the two audiences are visible; the cross-OS contract
//! itself (requests/responses/framing/`RP_ID`/`ORIGIN`/size caps) stays in the crate
//! root. The items are re-exported from the crate root for the Linux callers written
//! against the flat layout.

use serde::Serialize;
use thiserror::Error;

use crate::{ORIGIN, b64u_encode};

/// Minimum challenge length in bytes accepted by [`build_client_data`].
pub const MIN_CHALLENGE_BYTES: usize = 16;

/// Default Linux hard deadline for the whole authentication child process.
pub const DEFAULT_AUTH_TIMEOUT_SECS: u64 = 60;

/// `timeout_ms` sent to the bridge for authentication (advisory platform timeout + watchdog).
pub const BRIDGE_AUTH_TIMEOUT_MS: u32 = 55_000;

/// Default Linux hard deadline for the whole enrollment child process (CLI).
pub const DEFAULT_ENROLL_TIMEOUT_SECS: u64 = 180;

/// `timeout_ms` sent to the bridge for enrollment.
pub const BRIDGE_ENROLL_TIMEOUT_MS: u32 = 175_000;

/// Errors from [`build_client_data`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    /// The supplied challenge was shorter than [`MIN_CHALLENGE_BYTES`].
    #[error("challenge too short: {len} bytes (minimum {MIN_CHALLENGE_BYTES})")]
    ChallengeTooShort {
        /// Length of the offending challenge.
        len: usize,
    },
}

/// Which WebAuthn ceremony a `clientDataJSON` is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDataKind {
    /// Assertion (`webauthn.get`).
    Get,
    /// Registration (`webauthn.create`).
    Create,
}

impl ClientDataKind {
    /// The WebAuthn `type` string for this ceremony.
    pub fn as_str(self) -> &'static str {
        match self {
            ClientDataKind::Get => "webauthn.get",
            ClientDataKind::Create => "webauthn.create",
        }
    }
}

/// The exact JSON object shape of a `clientDataJSON`, in field order
/// `type`, `challenge`, `origin`.
///
/// Serialized via `serde_json`, which emits struct fields in declaration order. Keeping
/// this a typed struct (rather than `json!`) guarantees byte-stable output.
#[derive(Debug, Serialize)]
struct ClientData<'a> {
    r#type: &'a str,
    challenge: String,
    origin: &'a str,
}

/// Build the exact `clientDataJSON` bytes for a ceremony.
///
/// Produces `{"type":"webauthn.get"|"webauthn.create","challenge":"<b64url>","origin":"<ORIGIN>"}`
/// with that fixed field order. The challenge must be at least
/// [`MIN_CHALLENGE_BYTES`] bytes; a shorter challenge yields
/// [`ProtocolError::ChallengeTooShort`].
pub fn build_client_data(kind: ClientDataKind, challenge: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if challenge.len() < MIN_CHALLENGE_BYTES {
        return Err(ProtocolError::ChallengeTooShort {
            len: challenge.len(),
        });
    }
    let data = ClientData {
        r#type: kind.as_str(),
        challenge: b64u_encode(challenge),
        origin: ORIGIN,
    };
    // Serializing this fixed, all-`String`/`&str` struct cannot fail; fall back to a
    // hand-built object rather than panicking if serde_json ever surprises us.
    Ok(serde_json::to_vec(&data).unwrap_or_else(|_| {
        let mut out = Vec::new();
        out.extend_from_slice(br#"{"type":""#);
        out.extend_from_slice(kind.as_str().as_bytes());
        out.extend_from_slice(br#"","challenge":""#);
        out.extend_from_slice(b64u_encode(challenge).as_bytes());
        out.extend_from_slice(br#"","origin":""#);
        out.extend_from_slice(ORIGIN.as_bytes());
        out.extend_from_slice(br#""}"#);
        out
    }))
}
