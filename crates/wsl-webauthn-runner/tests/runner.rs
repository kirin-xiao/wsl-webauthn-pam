//! Runner integration tests against the `fake-bridge` test double (plan §7).
//!
//! The fake bridge is a normal binary built from this package; its path is provided by
//! Cargo as `CARGO_BIN_EXE_fake-bridge`. Environment-global concerns (the WSL interop
//! binfmt entry does not exist on GitHub's non-WSL runners) are handled by pointing the
//! runner's injectable interop check at a temp file, or by disabling it.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use wsl_webauthn_protocol::{BridgeError, MAX_RESPONSE_BYTES};
use wsl_webauthn_runner::{
    AssertParams, EnrollParams, Runner, RunnerError, RunnerResponse, decode_probe,
};

const FAKE: &str = env!("CARGO_BIN_EXE_fake-bridge");
const SIGPIPE_PROBE: &str = env!("CARGO_BIN_EXE_sigpipe-probe");

/// A directory to use as the child's `current_dir` (the Linux-FS cwd trap only affects
/// real interop; any directory works for the fake bridge).
fn cwd_dir() -> TempDir {
    TempDir::new().expect("tempdir")
}

/// A runner that skips the environment-global interop pre-flight.
///
/// The taskkill escalation is pointed at `/bin/true` so tests never invoke a real
/// `taskkill.exe` (which exists on WSL hosts and could otherwise be aimed at an
/// unrelated Windows PID).
fn build_runner(dir: &Path, args: &[&str]) -> Runner {
    Runner::without_interop_check(FAKE, dir)
        .taskkill_program("/bin/true")
        .args(args.to_vec())
}

fn enroll_params() -> EnrollParams {
    EnrollParams::new(
        "eyJ0eXBlIjoid2VibGF1dGhuLmNyZWF0ZSJ9",
        "YWxpY2U",
        "alice",
        "alice",
    )
}

fn assert_params() -> AssertParams {
    AssertParams::new("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0", vec!["YWJjZGVm".into()])
}

/// Write an `enabled` binfmt file and return its path.
fn enabled_interop_file(dir: &Path) -> PathBuf {
    let path = dir.join("WSLInterop");
    fs::write(&path, "enabled\ninterpreter /init\nflags: P\n").unwrap();
    path
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn probe_happy_path() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok"]);
    let resp = r.probe(Duration::from_secs(5)).expect("probe");
    match resp {
        RunnerResponse::Probe {
            uv_platform_available,
            api_version,
        } => {
            assert!(uv_platform_available);
            assert_eq!(api_version, 7);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn enroll_happy_path() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "payload=64"]);
    let resp = r
        .enroll(enroll_params(), Duration::from_secs(5))
        .expect("enroll");
    match &resp {
        RunnerResponse::Enroll {
            format,
            attestation_object,
            credential_id,
        } => {
            assert_eq!(format, "packed");
            assert!(!attestation_object.is_empty());
            assert_eq!(credential_id, "YWJjZGVm");
            assert_eq!(
                resp.decode_attestation_object().unwrap().len(),
                64,
                "payload filler length"
            );
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn assert_happy_path_with_echo() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "echo=1"]);
    let resp = r
        .authenticate(assert_params(), Duration::from_secs(5))
        .expect("assert");
    match &resp {
        RunnerResponse::Assert {
            client_data_json_echo,
            ..
        } => {
            assert_eq!(
                client_data_json_echo.as_deref(),
                Some("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0")
            );
            let echo = resp.decode_client_data_json_echo().unwrap().unwrap();
            assert_eq!(echo, b"{\"type\":\"webauthn.get\"}");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn assert_without_echo_returns_none() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok"]);
    let resp = r
        .authenticate(assert_params(), Duration::from_secs(5))
        .expect("assert");
    match &resp {
        RunnerResponse::Assert {
            client_data_json_echo,
            ..
        } => assert!(client_data_json_echo.is_none()),
        other => panic!("unexpected: {other:?}"),
    }
    assert!(resp.decode_client_data_json_echo().unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Ceremony errors pass through as RunnerResponse::Error (never RunnerError)
// ---------------------------------------------------------------------------

#[test]
fn every_bridge_error_passes_through() {
    for (wire, expected) in [
        ("not_available", BridgeError::NotAvailable),
        ("not_supported", BridgeError::NotSupported),
        ("user_cancelled", BridgeError::UserCancelled),
        ("timeout", BridgeError::Timeout),
        ("busy", BridgeError::Busy),
        ("invalid_parameter", BridgeError::InvalidParameter),
        ("internal", BridgeError::Internal),
    ] {
        let dir = cwd_dir();
        let r = build_runner(dir.path(), &["ok", &format!("err={wire}")]);
        let resp = r.probe(Duration::from_secs(5)).expect("transport ok");
        assert_eq!(
            resp,
            RunnerResponse::Error(expected),
            "taxonomy {wire} must round-trip"
        );
    }
}

// ---------------------------------------------------------------------------
// Timeout + kill
// ---------------------------------------------------------------------------

#[test]
fn timeout_fires_and_child_is_reaped() {
    let dir = cwd_dir();
    // Sleep far past the deadline; no response is ever written.
    let r = build_runner(dir.path(), &["ok", "sleep=5000"]);
    let start = Instant::now();
    let err = r
        .probe(Duration::from_millis(150))
        .expect_err("must time out");
    let elapsed = start.elapsed();
    match err {
        RunnerError::Timeout {
            deadline_ms,
            windows_pid,
            taskkill_attempted,
        } => {
            assert_eq!(deadline_ms, 150);
            assert!(windows_pid.is_none(), "fake emitted no PID line");
            assert!(!taskkill_attempted);
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
    // Must not wait the full 5 s sleep; allow generous slack for CI.
    assert!(
        elapsed < Duration::from_secs(3),
        "timeout should fire promptly, took {elapsed:?}"
    );
}

#[test]
fn timeout_parses_pid_line_and_attempts_taskkill() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "sleep=5000", "pidline=1", "noisy=1"]);
    let err = r
        .probe(Duration::from_millis(120))
        .expect_err("must time out");
    match err {
        RunnerError::Timeout {
            windows_pid,
            taskkill_attempted,
            ..
        } => {
            assert!(windows_pid.is_some(), "PID line should be parsed");
            // The escalation program is `/bin/true` in tests, so this succeeds quickly;
            // the flag records that a PID was seen and cancellation was attempted.
            assert!(taskkill_attempted);
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
}

#[test]
fn noisy_stderr_does_not_break_pid_parsing() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "sleep=5000", "pidline=1", "noisy=1"]);
    match r.probe(Duration::from_millis(100)).unwrap_err() {
        RunnerError::Timeout { windows_pid, .. } => {
            assert!(windows_pid.unwrap() > 0);
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Transport failures
// ---------------------------------------------------------------------------

#[test]
fn missing_bridge_is_bridge_missing() {
    let dir = cwd_dir();
    let r = Runner::without_interop_check(dir.path().join("nope.exe"), dir.path());
    assert!(matches!(
        r.probe(Duration::from_secs(1)),
        Err(RunnerError::BridgeMissing { .. })
    ));
}

#[test]
fn bridge_inside_unreadable_dir_is_permission_error_not_missing() {
    // Root bypasses directory DAC, so this scenario is only observable as a normal user.
    // SAFETY: geteuid is always safe to call.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: root bypasses directory permissions");
        return;
    }
    let dir = cwd_dir();
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    let bridge = locked.join("bridge.exe");
    fs::write(&bridge, b"not a real bridge").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

    let r = Runner::without_interop_check(&bridge, dir.path());
    let result = r.probe(Duration::from_secs(1));

    // Restore permissions so the tempdir can be cleaned up.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();

    match result.unwrap_err() {
        RunnerError::Spawn { source, .. } => {
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::PermissionDenied,
                "the real EACCES must be surfaced, not disguised as BridgeMissing: {source}"
            );
        }
        other => panic!("expected a permission Spawn error, got {other:?}"),
    }
}

#[test]
fn trailing_bytes_after_frame_are_transport() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "trailing=1"]);
    match r.probe(Duration::from_secs(5)).unwrap_err() {
        RunnerError::Transport { message } => {
            assert!(message.contains("trailing"), "{message}");
        }
        other => panic!("expected Transport, got {other:?}"),
    }
}

#[test]
fn nonzero_exit_is_bridge_failed() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["exit=3"]);
    match r.probe(Duration::from_secs(5)).unwrap_err() {
        RunnerError::BridgeFailed { code } => assert_eq!(code, Some(3)),
        other => panic!("expected BridgeFailed, got {other:?}"),
    }
}

#[test]
fn garbage_output_is_transport() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["garbage=1"]);
    match r.probe(Duration::from_secs(5)).unwrap_err() {
        RunnerError::Transport { message } => {
            assert!(
                message.contains("frame") || message.contains("JSON"),
                "{message}"
            );
        }
        other => panic!("expected Transport, got {other:?}"),
    }
}

#[test]
fn truncated_frame_is_transport() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["badframe=1"]);
    assert!(matches!(
        r.probe(Duration::from_secs(5)),
        Err(RunnerError::Transport { .. })
    ));
}

#[test]
fn empty_output_is_transport() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["empty=1"]);
    assert!(matches!(
        r.probe(Duration::from_secs(5)),
        Err(RunnerError::Transport { .. })
    ));
}

#[test]
fn oversized_response_is_transport() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["oversize=1"]);
    match r.probe(Duration::from_secs(5)).unwrap_err() {
        RunnerError::Transport { message } => assert!(message.contains("exceeds"), "{message}"),
        other => panic!("expected Transport, got {other:?}"),
    }
}

#[test]
fn oversized_declared_is_transport() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["oversize_declared=1"]);
    assert!(matches!(
        r.probe(Duration::from_secs(5)),
        Err(RunnerError::Transport { .. })
    ));
}

// ---------------------------------------------------------------------------
// Interop pre-flight
// ---------------------------------------------------------------------------

#[test]
fn interop_missing_file_is_unavailable() {
    let dir = cwd_dir();
    let r = Runner::with_interop_path(FAKE, dir.path(), dir.path().join("does-not-exist"));
    match r.probe(Duration::from_secs(1)).unwrap_err() {
        RunnerError::InteropUnavailable { path, .. } => {
            assert!(path.ends_with("does-not-exist"));
        }
        other => panic!("expected InteropUnavailable, got {other:?}"),
    }
}

#[test]
fn interop_not_enabled_is_unavailable() {
    let dir = cwd_dir();
    let path = dir.path().join("WSLInterop");
    fs::write(&path, "interpreter /init\n").unwrap();
    let r = Runner::with_interop_path(FAKE, dir.path(), &path);
    match r.probe(Duration::from_secs(1)).unwrap_err() {
        RunnerError::InteropUnavailable { detail, .. } => assert!(detail.contains("enabled")),
        other => panic!("expected InteropUnavailable, got {other:?}"),
    }
}

#[test]
fn interop_enabled_file_allows_probe() {
    let dir = cwd_dir();
    let path = enabled_interop_file(dir.path());
    let r = Runner::with_interop_path(FAKE, dir.path(), &path).args(vec!["ok"]);
    assert!(r.probe(Duration::from_secs(5)).is_ok());
}

#[test]
fn interop_check_disabled_skips_file() {
    let dir = cwd_dir();
    let r = Runner::without_interop_check(FAKE, dir.path()).args(vec!["ok"]);
    assert!(r.probe(Duration::from_secs(5)).is_ok());
}

// ---------------------------------------------------------------------------
// stdin handling and the shared interop helper
// ---------------------------------------------------------------------------

#[test]
fn non_reading_child_is_still_served() {
    // The child never reads its stdin; the request still fits the pipe buffer and the
    // deadline-bounded write path completes without blocking.
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "noread=1"]);
    assert!(matches!(
        r.probe(Duration::from_secs(5)),
        Ok(RunnerResponse::Probe { .. })
    ));
}

#[test]
fn interop_command_run_captures_stdout_and_status() {
    let dir = cwd_dir();
    let out = wsl_webauthn_runner::InteropCommand::run(
        "/bin/echo",
        &["hello", "world"],
        dir.path(),
        Duration::from_secs(5),
    )
    .expect("echo must run");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"hello world\n");
}

#[test]
fn child_closing_stdin_early_is_still_served() {
    // The child closes fd 0 before the request is written, so the request write may hit
    // EPIPE; the framed response on stdout is authoritative and must still be honored.
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "closestdin=1"]);
    assert!(matches!(
        r.probe(Duration::from_secs(5)),
        Ok(RunnerResponse::Probe { .. })
    ));
}

// ---------------------------------------------------------------------------
// SIGPIPE (L9-1): a closed stdin must never kill a SIGPIPE=SIG_DFL host
// ---------------------------------------------------------------------------

#[test]
fn closed_stdin_write_cannot_sigpipe_kill_host() {
    // `sigpipe-probe` resets SIGPIPE to SIG_DFL (as sudo/su/sshd leave it), writes to a
    // closed pipe through the runner's write path, and drives a stdin-closing fake
    // bridge. With the fix it exits 0; without it, SIGPIPE terminates it (signal exit).
    let dir = cwd_dir();
    let out = std::process::Command::new(SIGPIPE_PROBE)
        .env("FAKE_BRIDGE", FAKE)
        .env("FAKE_BRIDGE_CWD", dir.path())
        .output()
        .expect("spawn sigpipe-probe");
    assert!(
        out.status.success(),
        "sigpipe-probe failed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Over-cap stderr (L2-1 = L9-2)
// ---------------------------------------------------------------------------

#[test]
fn stderr_flood_times_out_and_is_bounded() {
    // Flood stderr well past MAX_STDERR_BYTES, then sleep: the over-cap fd must be
    // dropped from poll, so we reach a Timeout near the deadline instead of spinning.
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "stderrflood=16384", "sleep=5000"]);
    let start = Instant::now();
    let err = r
        .probe(Duration::from_millis(300))
        .expect_err("must time out");
    let elapsed = start.elapsed();
    assert!(matches!(err, RunnerError::Timeout { .. }), "{err:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "flood should time out promptly, took {elapsed:?}"
    );
}

#[test]
fn interop_command_run_times_out_and_kills() {
    let dir = cwd_dir();
    let start = Instant::now();
    let err = wsl_webauthn_runner::InteropCommand::run(
        "/bin/sleep",
        &["5"],
        dir.path(),
        Duration::from_millis(120),
    )
    .expect_err("sleep must time out");
    assert!(matches!(err, RunnerError::Timeout { .. }), "{err:?}");
    assert!(start.elapsed() < Duration::from_secs(3));
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

#[test]
fn parse_pid_helper() {
    assert_eq!(
        wsl_webauthn_runner::parse_pid(b"PID 1234\nextra\n"),
        Some(1234)
    );
    assert_eq!(wsl_webauthn_runner::parse_pid(b"not a pid line\n"), None);
    assert_eq!(wsl_webauthn_runner::parse_pid(b""), None);
    assert_eq!(wsl_webauthn_runner::parse_pid(b"PID abc\n"), None);
}

#[test]
fn parse_pid_rejects_garbage_zero_and_out_of_range() {
    // The PID is untrusted; only an in-range, non-zero u32 is accepted as a hint.
    assert_eq!(wsl_webauthn_runner::parse_pid(b"PID 0\n"), None);
    assert_eq!(wsl_webauthn_runner::parse_pid(b"PID -1\n"), None);
    assert_eq!(wsl_webauthn_runner::parse_pid(b"PID \n"), None);
    // u32::MAX + 1 overflows.
    assert_eq!(wsl_webauthn_runner::parse_pid(b"PID 4294967296\n"), None);
    assert_eq!(
        wsl_webauthn_runner::parse_pid(b"PID 99999999999999999999\n"),
        None
    );
    // The largest representable PID is merely untrusted, not invalid.
    assert_eq!(
        wsl_webauthn_runner::parse_pid(b"PID 4294967295\n"),
        Some(u32::MAX)
    );
}

#[test]
fn decode_probe_helper() {
    let ok = RunnerResponse::Probe {
        uv_platform_available: true,
        api_version: 7,
    };
    assert_eq!(decode_probe(&ok), Some((true, 7)));
    let err = RunnerResponse::Error(BridgeError::Busy);
    assert_eq!(decode_probe(&err), None);
}

#[test]
fn response_cap_constant_matches_protocol() {
    assert_eq!(MAX_RESPONSE_BYTES, 64 * 1024);
}
