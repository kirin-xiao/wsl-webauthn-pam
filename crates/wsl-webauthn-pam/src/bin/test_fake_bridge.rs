//! `pam-test-fake-bridge` — test support only (not installed, not linked into the
//! `.so`).
//!
//! It is a minimal, protocol-speaking stand-in for `WSLWebAuthnBridge.exe` whose
//! output is *scripted by the test*. The PAM integration tests build the exact
//! response bytes (including a real, verifiable ES256 signature) and hand them to
//! this binary, which reproduces the process contract: read one framed request,
//! write one framed response, exit `0`.
//!
//! Usage:
//!
//! ```text
//! pam-test-fake-bridge [response=<b64url framed bytes>] [err=<taxonomy>] \
//!     [sleep=<ms>] [exit=<code>] [garbage=1] [empty=1] [noread=1] [pidline=1]
//! ```
//!
//! * `response=<b64url>` — write these already-framed bytes to stdout (the primary
//!   scripting mechanism; the test builds and signs them).
//! * `err=<taxonomy>` — write `{"op":"*","ok":false,"error":"<taxonomy>"}` framed.
//! * `sleep=<ms>` — read the request, then sleep before writing anything.
//! * `exit=<code>` — exit with the given status without a well-formed response.
//! * `garbage=1` / `empty=1` — transport-failure stand-ins.
//! * `noread=1` — do not read stdin.
//! * `pidline=1` — emit `PID <n>` as the first stderr line.

use std::io::{Read as _, Write as _};

use wsl_webauthn_protocol::{MAX_REQUEST_BYTES, Response, b64u_decode};

struct Opts {
    response: Option<String>,
    err: Option<String>,
    sleep_ms: u64,
    exit_code: Option<i32>,
    garbage: bool,
    empty: bool,
    noread: bool,
    pidline: bool,
}

fn parse_args() -> Opts {
    let mut opts = Opts {
        response: None,
        err: None,
        sleep_ms: 0,
        exit_code: None,
        garbage: false,
        empty: false,
        noread: false,
        pidline: false,
    };
    for arg in std::env::args().skip(1) {
        let Some((key, value)) = arg.split_once('=') else {
            continue;
        };
        match key {
            "response" => opts.response = Some(value.to_string()),
            "err" => opts.err = Some(value.to_string()),
            "sleep" => opts.sleep_ms = value.parse().unwrap_or(0),
            "exit" => opts.exit_code = value.parse().ok(),
            "garbage" => opts.garbage = value == "1",
            "empty" => opts.empty = value == "1",
            "noread" => opts.noread = value == "1",
            "pidline" => opts.pidline = value == "1",
            _ => {}
        }
    }
    opts
}

fn read_request() {
    let mut buf = [0u8; MAX_REQUEST_BYTES + 4];
    let mut stdin = std::io::stdin();
    // Read whatever the caller wrote; the content is irrelevant to this double.
    let _ = stdin.read(&mut buf);
}

fn main() -> std::process::ExitCode {
    let opts = parse_args();

    if opts.pidline {
        eprintln!("PID {}", std::process::id());
    }
    if !opts.noread {
        read_request();
    }
    if opts.sleep_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(opts.sleep_ms));
    }
    if let Some(code) = opts.exit_code {
        return std::process::ExitCode::from(code as u8);
    }
    if opts.empty {
        return std::process::ExitCode::SUCCESS;
    }

    let mut stdout = std::io::stdout();
    if opts.garbage {
        let _ = stdout.write_all(b"not a frame");
        let _ = stdout.flush();
        return std::process::ExitCode::SUCCESS;
    }

    let frame = if let Some(taxonomy) = &opts.err {
        let parsed = serde_json::from_str::<Response>(&format!(
            "{{\"op\":\"*\",\"ok\":false,\"error\":\"{taxonomy}\"}}"
        ))
        .unwrap_or(Response::error(
            wsl_webauthn_protocol::BridgeError::Internal,
        ));
        parsed.to_frame().expect("response serializes")
    } else if let Some(encoded) = &opts.response {
        match b64u_decode(encoded) {
            Ok(bytes) => bytes,
            Err(_) => return std::process::ExitCode::from(3),
        }
    } else {
        // No script: behave like a clean empty exit.
        return std::process::ExitCode::SUCCESS;
    };

    if stdout.write_all(&frame).is_err() || stdout.flush().is_err() {
        return std::process::ExitCode::from(2);
    }
    std::process::ExitCode::SUCCESS
}
