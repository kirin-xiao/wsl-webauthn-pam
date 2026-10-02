//! `dyn_assert_bridge` — test helper (not installed, not part of the module or
//! its public API). It reads an Assert request frame from stdin, extracts
//! `clientDataJSON`, signs `authenticatorData || SHA-256(clientDataJSON)` with an
//! ephemeral P-256 key, and writes the framed [`Response::Assert`] to stdout.
//!
//! The key and credential id are passed via the environment because the runner
//! supplies no argv to a production bridge:
//!
//! * `WSLWT_TEST_SIGNING_KEY` — the P-256 private scalar as 64 lowercase hex chars.
//! * `WSLWT_TEST_CRED_ID` — the credential id as unpadded base64url.
//! * `WSLWT_TEST_ECHO` — when `1`, echo the request `clientDataJSON` back.
//!
//! `examples/` lets it use the crate's dev-dependencies (`p256`) without appearing
//! on the production dependency graph; `tests/c_host.rs` exercises it.

use std::io::Write as _;

use p256::ecdsa::SigningKey as P256SigningKey;
use p256::ecdsa::signature::Signer as _;
use sha2::{Digest as _, Sha256};

use wsl_webauthn_protocol::{MAX_REQUEST_BYTES, Request, Response, b64u_encode, read_frame};

fn hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (b[2 * i] as char).to_digit(16)?;
        let lo = (b[2 * i + 1] as char).to_digit(16)?;
        *byte = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn main() -> std::process::ExitCode {
    let key_hex = match std::env::var("WSLWT_TEST_SIGNING_KEY") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("dyn_assert_bridge: WSLWT_TEST_SIGNING_KEY is not set");
            return std::process::ExitCode::from(2);
        }
    };
    let Some(secret) = hex32(&key_hex) else {
        eprintln!("dyn_assert_bridge: WSLWT_TEST_SIGNING_KEY must be 64 hex chars");
        return std::process::ExitCode::from(2);
    };
    let cred_id = match std::env::var("WSLWT_TEST_CRED_ID") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("dyn_assert_bridge: WSLWT_TEST_CRED_ID is not set");
            return std::process::ExitCode::from(2);
        }
    };
    let echo = std::env::var("WSLWT_TEST_ECHO").as_deref() == Ok("1");

    // Read exactly one framed request.
    let mut stdin = std::io::stdin().lock();
    let payload = match read_frame(&mut stdin, MAX_REQUEST_BYTES) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("dyn_assert_bridge: reading request frame: {e}");
            return std::process::ExitCode::from(3);
        }
    };
    let request: Request = match serde_json::from_slice(&payload) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dyn_assert_bridge: parsing request: {e}");
            return std::process::ExitCode::from(3);
        }
    };
    let client_data_json_b64 = match request {
        Request::Assert {
            client_data_json, ..
        } => client_data_json,
        _ => {
            eprintln!("dyn_assert_bridge: expected an Assert request");
            return std::process::ExitCode::from(3);
        }
    };
    let client_data_json = match wsl_webauthn_protocol::b64u_decode(&client_data_json_b64) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("dyn_assert_bridge: clientDataJSON is not base64url: {e}");
            return std::process::ExitCode::from(3);
        }
    };

    // authenticatorData: rpIdHash || flags(UP|UV) || counter(0), no attested cred data.
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(wsl_webauthn_protocol::RP_ID.as_bytes()));
    auth_data.push(0x01 | 0x04);
    auth_data.extend_from_slice(&0u32.to_be_bytes());

    let mut message = auth_data.clone();
    message.extend_from_slice(&Sha256::digest(&client_data_json));

    let signing = match P256SigningKey::from_slice(&secret) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("dyn_assert_bridge: bad P-256 scalar: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let signature: p256::ecdsa::DerSignature = signing.sign(&message);

    let response = Response::assertion(
        b64u_encode(&auth_data),
        b64u_encode(signature.as_bytes()),
        cred_id,
        echo.then_some(client_data_json_b64.clone()),
    );
    let frame = match response.to_frame() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("dyn_assert_bridge: framing response: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(&frame).is_err() || stdout.flush().is_err() {
        return std::process::ExitCode::from(2);
    }
    std::process::ExitCode::SUCCESS
}
