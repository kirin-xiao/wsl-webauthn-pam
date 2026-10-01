//! `fake-bridge` — a test double speaking the §3 wire protocol.
//!
//! This binary is test support only; it is built as an extra target of the runner
//! package so integration tests can locate it via
//! `env!("CARGO_BIN_EXE_fake-bridge")`. It never performs any real ceremony.
//!
//! Usage:
//!
//! ```text
//! fake-bridge [MODE] [key=value ...]
//! ```
//!
//! Modes / options:
//!
//! * `ok` (default) — read the framed request and answer with a well-formed success
//!   response for that op. Enroll fields are deterministic b64url placeholders.
//! * `err=<taxonomy>` — answer `{"op":"*","ok":false,"error":"<taxonomy>"}` with exit 0.
//! * `echo=1` — when the op is `assert`, echo the request `client_data_json`.
//! * `pidline=1` — print `PID <pid>\n` as the first stderr line before responding.
//! * `sleep=<ms>` — read the request, then sleep before responding (`sleep=0` + no
//!   response exercises the timeout path). Combine with `pidline=1` to test escalation.
//! * `noread=1` — do not read the request (write path only).
//! * `closestdin=1` — close fd 0 before the runner writes, so the write hits `EPIPE`
//!   (SIGPIPE-driver test); still answers a synthesized `probe`.
//! * `stderrflood=<n>` — write `n` bytes of filler to stderr (over-cap drain test).
//! * `exit=<code>` — exit with the given code without writing a response.
//! * `garbage=1` — write non-framed bytes, then exit 0.
//! * `badframe=1` — write a plausible length prefix followed by *too few* bytes, then
//!   exit 0 (truncated frame).
//! * `oversize=1` — write a valid prefix declaring > 64 KiB and then that many bytes.
//! * `oversize_declared=1` — write only a prefix declaring > 64 KiB, then exit.
//! * `empty=1` — exit 0 with no output at all.
//! * `noisy=1` — emit extra stderr chatter after the PID line.
//! * `payload=<n>` — number of filler bytes in a valid enroll/assert success response.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use wsl_webauthn_protocol::{
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Request, Response, b64u_encode, encode_frame, read_frame,
};

struct Opts {
    mode: String,
    err: Option<String>,
    echo: bool,
    pidline: bool,
    sleep_ms: u64,
    noread: bool,
    closestdin: bool,
    stderr_flood: Option<usize>,
    exit_code: Option<i32>,
    garbage: bool,
    badframe: bool,
    oversize: bool,
    oversize_declared: bool,
    empty: bool,
    noisy: bool,
    payload: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            mode: "ok".into(),
            err: None,
            echo: false,
            pidline: false,
            sleep_ms: 0,
            noread: false,
            closestdin: false,
            stderr_flood: None,
            exit_code: None,
            garbage: false,
            badframe: false,
            oversize: false,
            oversize_declared: false,
            empty: false,
            noisy: false,
            payload: 0,
        }
    }
}

fn parse_args() -> Opts {
    let mut opts = Opts::default();
    for (i, arg) in std::env::args().skip(1).enumerate() {
        let Some((key, value)) = arg.split_once('=') else {
            if i == 0 {
                opts.mode = arg;
            }
            continue;
        };
        match key {
            "err" => opts.err = Some(value.to_string()),
            "echo" => opts.echo = value == "1",
            "pidline" => opts.pidline = value == "1",
            "sleep" => opts.sleep_ms = value.parse().unwrap_or(0),
            "noread" => opts.noread = value == "1",
            "closestdin" => opts.closestdin = value == "1",
            "stderrflood" => opts.stderr_flood = value.parse().ok(),
            "exit" => opts.exit_code = value.parse().ok(),
            "garbage" => opts.garbage = value == "1",
            "badframe" => opts.badframe = value == "1",
            "oversize" => opts.oversize = value == "1",
            "oversize_declared" => opts.oversize_declared = value == "1",
            "empty" => opts.empty = value == "1",
            "noisy" => opts.noisy = value == "1",
            "payload" => opts.payload = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    opts
}

fn read_request() -> Option<Request> {
    let mut stdin = std::io::stdin();
    match read_frame(&mut stdin, MAX_REQUEST_BYTES) {
        Ok(bytes) => serde_json::from_slice(&bytes).ok(),
        Err(_) => None,
    }
}

fn filler(n: usize) -> Vec<u8> {
    // Deterministic, non-trivial bytes.
    (0..n).map(|i| (i % 251) as u8 + 1).collect()
}

fn success_response(opts: &Opts, req: &Request) -> Response {
    // A little extra filler keeps the frame length deterministic per `payload=`.
    let extra = b64u_encode(&filler(opts.payload));
    match req {
        Request::Probe { .. } => Response::probe(true, 7),
        Request::Enroll { .. } => Response::enroll("packed", extra, "YWJjZGVm"),
        Request::Assert {
            client_data_json, ..
        } => {
            let echo = if opts.echo {
                Some(client_data_json.clone())
            } else {
                None
            };
            Response::assertion(extra, "c2ln", "YWJjZGVm", echo)
        }
    }
}

fn write_frame(response: &Response) -> std::io::Result<()> {
    let frame = response.to_frame().expect("response serializes");
    let mut stdout = std::io::stdout();
    stdout.write_all(&frame)?;
    stdout.flush()
}

fn main() -> ExitCode {
    let opts = parse_args();

    if opts.closestdin {
        // Close the read end of the runner's stdin pipe before it writes, so the parent's
        // write observes EPIPE (the SIGPIPE-driver path). SAFETY: closing an owned fd.
        unsafe {
            libc::close(0);
        }
    }

    if opts.pidline {
        // Mimic the bridge's `PID <n>\n` first stderr line; there is no Windows side
        // here so the Linux pid stands in.
        eprintln!("PID {}", std::process::id());
    }
    if opts.noisy {
        eprintln!("fake-bridge mode={} (log line)", opts.mode);
        eprintln!("another log line that is not the PID line");
    }

    if let Some(n) = opts.stderr_flood {
        // Flood stderr past the runner's `MAX_STDERR_BYTES` cap to exercise the bounded
        // drain (an over-cap fd must be dropped from poll, not busy-drained).
        let mut stderr = std::io::stderr();
        let _ = stderr.write_all(&filler(n));
        let _ = stderr.flush();
    }

    let request = if opts.noread || opts.closestdin {
        None
    } else {
        read_request()
    };

    if opts.sleep_ms > 0 {
        std::thread::sleep(Duration::from_millis(opts.sleep_ms));
    }

    if let Some(code) = opts.exit_code {
        return ExitCode::from(code as u8);
    }
    if opts.garbage {
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(b"this is not a frame at all, no length prefix");
        let _ = stdout.flush();
        return ExitCode::SUCCESS;
    }
    if opts.oversize_declared {
        let mut stdout = std::io::stdout();
        let declared = (MAX_RESPONSE_BYTES + 1024) as u32;
        let _ = stdout.write_all(&declared.to_le_bytes());
        let _ = stdout.flush();
        return ExitCode::SUCCESS;
    }
    if opts.oversize {
        let mut stdout = std::io::stdout();
        let declared = (MAX_RESPONSE_BYTES + 4096) as u32;
        let _ = stdout.write_all(&declared.to_le_bytes());
        let _ = stdout.write_all(&vec![b'x'; declared as usize]);
        let _ = stdout.flush();
        return ExitCode::SUCCESS;
    }
    if opts.badframe {
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(&encode_frame(b"{\"op\":\"probe\"}")[..6]); // truncated
        let _ = stdout.flush();
        return ExitCode::SUCCESS;
    }
    if opts.empty {
        return ExitCode::SUCCESS;
    }

    let req = match request {
        Some(req) => req,
        // `noread`/`closestdin` answer a synthesized probe without ever reading stdin, so
        // the runner's deadline-bounded stdin write can be exercised against a
        // non-reading (or early-closed) child.
        None if opts.noread || opts.closestdin => Request::Probe { timeout_ms: 1 },
        // No request to answer; behave like a clean empty exit.
        None => return ExitCode::SUCCESS,
    };

    let response = match &opts.err {
        Some(taxonomy) => {
            // Build the error JSON by round-tripping through serde to reuse the tested
            // taxonomy mapping: unknown strings become `internal`.
            let parsed = serde_json::from_str::<Response>(&format!(
                "{{\"op\":\"*\",\"ok\":false,\"error\":\"{taxonomy}\"}}"
            ));
            parsed.unwrap_or(Response::error(
                wsl_webauthn_protocol::BridgeError::Internal,
            ))
        }
        None => success_response(&opts, &req),
    };

    if let Err(e) = write_frame(&response) {
        eprintln!("fake-bridge: write failed: {e}");
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}
