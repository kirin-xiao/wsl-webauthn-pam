//! Runner integration tests against the `fake-bridge` test double.
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

use wsl_webauthn_protocol::{BridgeError, MAX_RESPONSE_BYTES, Response};
use wsl_webauthn_runner::{
    AssertParams, EnrollParams, ExitReason, Runner, RunnerError, RunnerResponse, decode_probe,
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

/// Write a small executable shell bridge with the given body, returning its path.
///
/// Used by timing tests and the pin tests so a descriptor hash measures the loop, not the
/// multi-megabyte `fake-bridge` binary.
fn tiny_bridge(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write tiny bridge");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
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

/// On the EOF fast path (a child that writes a full response, closes its pipes, then
/// lingers before exiting) the runner must not add a whole poll tick after the response
/// is complete; the adaptive spin reaps the child promptly.
///
/// A tiny shell bridge is used rather than the multi-megabyte `fake-bridge` binary so the
/// measurement reflects the drain/reap loop, not the (unrelated) cost of hashing the
/// held descriptor before every exchange.
#[test]
fn eof_fast_path_does_not_wait_a_full_tick() {
    let dir = cwd_dir();
    let frame_path = dir.path().join("frame");
    fs::write(&frame_path, Response::probe(true, 7).to_frame().unwrap()).unwrap();
    // Answer immediately, close stdout/stderr, linger 15 ms, then exit.
    let bridge = tiny_bridge(
        dir.path(),
        "eof-bridge",
        &format!(
            "cat {frame:?}\nexec 1>&-\nexec 2>&-\nsleep 0.015\nexit 0",
            frame = frame_path
        ),
    );
    let r = Runner::without_interop_check(&bridge, dir.path()).taskkill_program("/bin/true");
    let start = Instant::now();
    let resp = r.probe(Duration::from_secs(5)).expect("probe succeeds");
    let elapsed = start.elapsed();
    assert!(matches!(resp, RunnerResponse::Probe { .. }));
    // Spawn overhead dominates; assert we did not compound it with a full coarse tick.
    assert!(
        elapsed < Duration::from_millis(200),
        "EOF fast path should reap promptly, took {elapsed:?}"
    );
}

/// `reap_bounded` must not overshoot the deadline by a full poll tick. A child that
/// ignores stdin and sleeps must be killed and its Timeout returned at ~deadline.
#[test]
fn timeout_does_not_overshoot_deadline_by_a_full_tick() {
    let dir = cwd_dir();
    // A tiny bridge so the measurement isolates the drain/reap loop from the up-front
    // descriptor hash of the large `fake-bridge` binary.
    let bridge = tiny_bridge(dir.path(), "sleep-bridge", "sleep 5\nexit 0");
    let r = Runner::without_interop_check(&bridge, dir.path()).taskkill_program("/bin/true");
    let deadline = Duration::from_millis(150);
    let start = Instant::now();
    let err = r.probe(deadline).expect_err("must time out");
    let elapsed = start.elapsed();
    assert!(matches!(err, RunnerError::Timeout { .. }), "{err:?}");
    // Allow for process spawn + scheduling + one SHA-256 pass of the tiny script, but
    // well under deadline + several ticks.
    assert!(
        elapsed < deadline + Duration::from_millis(100),
        "timeout overshot the deadline, took {elapsed:?} for {deadline:?}"
    );
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

/// The bridge is opened `O_NOFOLLOW`, so a symlinked bridge path is refused rather
/// than followed. The `ELOOP` is surfaced as a `Spawn` error (not disguised as missing).
#[test]
fn symlinked_bridge_is_rejected() {
    let dir = cwd_dir();
    let real = dir.path().join("real-bridge");
    fs::write(&real, b"not a real bridge").unwrap();
    let link = dir.path().join("bridge-link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let r = Runner::without_interop_check(&link, dir.path());
    match r.probe(Duration::from_secs(1)).unwrap_err() {
        RunnerError::Spawn { source, .. } => {
            assert_eq!(
                source.raw_os_error(),
                Some(libc::ELOOP),
                "O_NOFOLLOW must refuse the symlink: {source}"
            );
        }
        other => panic!("expected a symlink Spawn error, got {other:?}"),
    }
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
        RunnerError::BridgeFailed { reason, message } => {
            assert_eq!(reason, ExitReason::Code(3));
            // Exit code 3 is documented as a bad-frame request failure.
            assert!(
                message.contains("malformed") || message.contains("request frame"),
                "{message}"
            );
        }
        other => panic!("expected BridgeFailed, got {other:?}"),
    }
}

/// Each documented bridge exit code (3/4/5) is classified, not collapsed.
#[test]
fn bridge_exit_codes_map_to_documented_meaning() {
    for (code, needle) in [(3, "request frame"), (4, "`op`"), (5, "stdout write")] {
        let dir = cwd_dir();
        let r = build_runner(dir.path(), &[&format!("exit={code}")]);
        match r.probe(Duration::from_secs(5)).unwrap_err() {
            RunnerError::BridgeFailed { reason, message } => {
                assert_eq!(reason, ExitReason::Code(code));
                assert!(message.contains(needle), "exit {code}: {message}");
            }
            other => panic!("expected BridgeFailed for exit {code}, got {other:?}"),
        }
    }
}

/// A signal death is modeled distinctly (not an ambiguous `None` status) and the
/// rendered message names the signal.
#[test]
fn signal_death_reports_signal_reason_and_name() {
    let dir = cwd_dir();
    // `abort=1` makes the fake bridge raise SIGABRT (signal 6) without writing a frame.
    let r = build_runner(dir.path(), &["abort=1"]);
    let err = r.probe(Duration::from_secs(5)).unwrap_err();
    match &err {
        RunnerError::BridgeFailed { reason, message } => {
            assert_eq!(
                *reason,
                ExitReason::Signal(libc::SIGABRT),
                "signal death must be modeled as ExitReason::Signal: {err:?}"
            );
            assert!(
                message.contains("SIGABRT") && message.contains('6'),
                "message must name the signal: {message}"
            );
            assert!(
                !message.contains("status None"),
                "signal death must not render an ambiguous None status: {message}"
            );
        }
        other => panic!("expected BridgeFailed, got {other:?}"),
    }
    // `ExitReason` accessors agree with the variant.
    if let RunnerError::BridgeFailed { reason, .. } = err {
        assert_eq!(reason.code(), None);
        assert_eq!(reason.signal(), Some(libc::SIGABRT));
    }
}

/// A status with neither an exit code nor a terminating signal must not be
/// fabricated into `signal 0`; it is reported as [`ExitReason::Unknown`].
#[test]
fn unknown_termination_status_is_not_signal_zero() {
    use std::os::unix::process::ExitStatusExt;
    // WIFSTOPPED (`0x7f`): neither `WIFEXITED` nor `WIFSIGNALED`, so `code()` and
    // `signal()` are both `None`. `from_raw` does not validate the raw wait status.
    let status = std::process::ExitStatus::from_raw(0x7f);
    assert_eq!(status.code(), None);
    assert_eq!(status.signal(), None);

    let reason = ExitReason::from_status(&status);
    assert_eq!(reason, ExitReason::Unknown);
    assert_eq!(reason.code(), None);
    assert_eq!(reason.signal(), None);
    assert_eq!(reason.to_string(), "unknown termination status");
    assert_ne!(reason, ExitReason::Signal(0));
}

/// The bridge's stderr tail (its HRESULT/error line) is folded into the failure
/// diagnostic instead of being discarded.
#[test]
fn bridge_failed_carries_stderr_tail() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["hresult=0x80070005", "exit=3"]);
    match r.probe(Duration::from_secs(5)).unwrap_err() {
        RunnerError::BridgeFailed { message, .. } => {
            assert!(message.contains("0x80070005"), "{message}");
            assert!(message.contains("hr="), "{message}");
        }
        other => panic!("expected BridgeFailed, got {other:?}"),
    }
}

/// A ceremony error on a healthy transport (exit 0) still exposes the bridge's
/// HRESULT line via `RunnerExchange::bridge_stderr`.
#[test]
fn ceremony_error_exposes_bridge_stderr_diagnostic() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "err=internal", "hresult=0x80070005"]);
    let exchange = r
        .authenticate_with_diagnostics(assert_params(), Duration::from_secs(5))
        .expect("transport ok");
    assert_eq!(
        exchange.response,
        RunnerResponse::Error(BridgeError::Internal)
    );
    let diag = exchange.bridge_stderr.expect("stderr tail retained");
    assert!(diag.contains("0x80070005"), "{diag}");
}

/// The stderr tail is also attached to a malformed-frame transport failure.
#[test]
fn transport_failure_carries_stderr_tail() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["hresult=0x80070005", "garbage=1"]);
    match r.probe(Duration::from_secs(5)).unwrap_err() {
        RunnerError::Transport { message } => {
            assert!(
                message.contains("frame") || message.contains("JSON"),
                "{message}"
            );
            assert!(message.contains("0x80070005"), "{message}");
        }
        other => panic!("expected Transport, got {other:?}"),
    }
}

/// Hostile child output cannot smuggle NULs/newlines into the diagnostic string.
#[test]
fn stderr_diagnostic_escapes_control_bytes() {
    let dir = cwd_dir();
    // The filler bytes include NUL-adjacent controls and newlines; they must be escaped
    // or collapsed, never passed through raw.
    let r = build_runner(dir.path(), &["stderrflood=256", "exit=3"]);
    let err = r.probe(Duration::from_secs(5)).unwrap_err();
    let rendered = err.to_string();
    assert!(
        !rendered.contains('\0'),
        "diagnostic must never carry a raw NUL"
    );
    assert!(
        !rendered.contains('\n'),
        "diagnostic must be a single line: {rendered:?}"
    );
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
// SIGPIPE: a closed stdin must never kill a SIGPIPE=SIG_DFL host
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
// Over-cap stderr
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

// ---------------------------------------------------------------------------
// Concurrency (runner-side proxy for concurrent PAM calls)
// ---------------------------------------------------------------------------

/// Several runner instances driven from separate threads at once must all succeed. This
/// exercises the per-thread SIGPIPE mask and independent deadline/poll loops, the
/// runner-side half of the concurrent-PAM-call gap (a real multi-`pam_handle_t` test is
/// the PAM crate's).
#[test]
fn concurrent_probes_are_independent() {
    let dir = cwd_dir();
    let dir = dir.path().to_path_buf();
    let mut handles = Vec::new();
    for i in 0..8 {
        let dir = dir.clone();
        handles.push(std::thread::spawn(move || {
            let r = Runner::without_interop_check(FAKE, &dir)
                .taskkill_program("/bin/true")
                .args(["ok", "payload=32"]);
            let resp = r.probe(Duration::from_secs(5)).expect("probe");
            assert!(
                matches!(resp, RunnerResponse::Probe { .. }),
                "thread {i}: {resp:?}"
            );
        }));
    }
    for handle in handles {
        handle.join().expect("thread panicked");
    }
}

// ---------------------------------------------------------------------------
// Ceremony progress (PROGRESS lines on the bridge's stderr)
// ---------------------------------------------------------------------------

/// The progress sink must receive `prompt_open` then `prompt_closed`, in that order,
/// while the enroll response is still returned normally, so the CLI/module can announce
/// the save-then-PIN flow.
#[test]
fn enroll_reports_progress_events_in_order() {
    use std::sync::Mutex;
    use wsl_webauthn_runner::CeremonyProgress;

    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "progress=1", "progress_sleep=50"]);
    let seen: Mutex<Vec<CeremonyProgress>> = Mutex::new(Vec::new());
    let sink = |event: CeremonyProgress| {
        seen.lock().unwrap().push(event);
    };
    let resp = r
        .enroll_with_progress(enroll_params(), Duration::from_secs(5), Some(&sink))
        .expect("enroll");
    assert!(matches!(resp, RunnerResponse::Enroll { .. }), "{resp:?}");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            CeremonyProgress::Starting,
            CeremonyProgress::PromptOpen,
            CeremonyProgress::PromptClosed,
            CeremonyProgress::Finishing,
        ],
        "the save-then-PIN gap must be observable between the runner boundaries"
    );
}

/// `prompt_open` is delivered *before* the bridge has finished: with the fake pausing
/// between the two lines, the sink must observe `prompt_open` while the exchange is still
/// in flight, not only after exit. A recording sink that captures the elapsed time at
/// `PromptOpen` proves the event was emitted live.
#[test]
fn progress_prompt_open_is_emitted_live_not_buffered() {
    use std::sync::Mutex;
    use wsl_webauthn_runner::CeremonyProgress;

    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "progress=1", "progress_sleep=1000"]);
    let start = Instant::now();
    let open_at: Mutex<Option<Duration>> = Mutex::new(None);
    let sink = |event: CeremonyProgress| {
        if event == CeremonyProgress::PromptOpen {
            *open_at.lock().unwrap() = Some(start.elapsed());
        }
    };
    let resp = r
        .authenticate_with_progress(assert_params(), Duration::from_secs(5), Some(&sink))
        .expect("assert");
    assert!(matches!(resp, RunnerResponse::Assert { .. }), "{resp:?}");
    let open_at = open_at.lock().unwrap().expect("prompt_open observed");
    assert!(
        open_at < Duration::from_millis(500),
        "prompt_open must arrive before the 1 s pause ends, saw {open_at:?}"
    );
}

/// A bridge that emits no progress lines yields no callbacks and still succeeds.
#[test]
fn no_progress_lines_yields_no_events() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wsl_webauthn_runner::CeremonyProgress;
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok"]);
    let count = AtomicUsize::new(0);
    let sink = |_event: CeremonyProgress| {
        count.fetch_add(1, Ordering::SeqCst);
    };
    let resp = r
        .enroll_with_progress(enroll_params(), Duration::from_secs(5), Some(&sink))
        .expect("enroll");
    assert!(matches!(resp, RunnerResponse::Enroll { .. }), "{resp:?}");
    // No bridge PROGRESS lines, but the runner still emits its two boundaries.
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

/// Non-progress stderr (the `PID <n>` line, HRESULT diagnostics, noise) must never be
/// mistaken for a phase event.
#[test]
fn unrelated_stderr_is_not_reported_as_progress() {
    use wsl_webauthn_runner::{CeremonyProgress, parse_progress};
    let stderr = b"PID 4242\nWebAuthNGetAssertion: hr=0x80090036 FakeName\nsome log line\n";
    assert_eq!(parse_progress(stderr), Vec::<CeremonyProgress>::new());
    // A `PROGRESS` line with an unknown phase is dropped.
    assert_eq!(parse_progress(b"PROGRESS nonsense\n").len(), 0);
    // Known phases parse, and matching is exact to the prefix.
    assert_eq!(
        parse_progress(b"PROGRESS prompt_open\n"),
        vec![CeremonyProgress::PromptOpen]
    );
}

/// The default `enroll`/`authenticate` helpers (no sink) still work against a bridge that
/// emits progress lines.
#[test]
fn default_entry_points_ignore_progress_lines() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok", "progress=1"]);
    let resp = r
        .enroll(enroll_params(), Duration::from_secs(5))
        .expect("enroll");
    assert!(matches!(resp, RunnerResponse::Enroll { .. }), "{resp:?}");
}

// ---------------------------------------------------------------------------
// Authoritative bridge pin
// ---------------------------------------------------------------------------

/// SHA-256 of a file, for computing an expected pin in tests.
fn sha256_of(path: &Path) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let bytes = fs::read(path).expect("read bridge");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let d = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// A minimal executable that writes a marker file when it runs, then exits 0 with no
/// frame. The marker proves *which* file the runner actually executed.
fn write_marker_exe(dir: &Path, name: &str, marker: &Path) -> PathBuf {
    tiny_bridge(dir, name, &format!("echo ran > {marker:?}\nexit 0"))
}

/// The pin is taken from the descriptor opened by pre-flight, and a path swap *after*
/// that open cannot change the executed image. The hook performs the swap deterministically
/// between the descriptor open and the hash/exec.
#[test]
fn pin_is_bound_to_the_executed_descriptor_not_the_path() {
    thread_local! {
        static SWAP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }
    fn run_swap() {
        if let Some(f) = SWAP.with(|s| s.borrow_mut().take()) {
            f();
        }
    }

    let dir = cwd_dir();
    let orig_marker = dir.path().join("orig-marker");
    let repl_marker = dir.path().join("repl-marker");
    let bridge = write_marker_exe(dir.path(), "bridge", &orig_marker);
    let replacement = write_marker_exe(dir.path(), "replacement", &repl_marker);
    let pin = sha256_of(&bridge);

    // The hook swaps the path after pre-flight has opened it. A hash that re-opened the
    // path would see `replacement` and fail; the held descriptor must still hash and
    // execute the original bytes.
    let hook_path = bridge.clone();
    let repl = replacement.clone();
    SWAP.with(|s| {
        *s.borrow_mut() = Some(Box::new(move || {
            fs::rename(&repl, &hook_path).expect("swap bridge path");
        }));
    });

    let r = Runner::without_interop_check(&bridge, dir.path())
        .taskkill_program("/bin/true")
        .expected_sha256(pin)
        .post_preflight_hook(run_swap);

    // The marker script emits no frame, so the exchange fails transport after exec. What
    // matters is that the pin matched (no `BridgeIntegrity`) and the original ran.
    let err = r
        .probe(Duration::from_secs(5))
        .expect_err("a marker script is not a valid bridge frame");
    assert!(
        !matches!(err, RunnerError::BridgeIntegrity { .. }),
        "pin must be bound to the held descriptor, not the swapped path: {err:?}"
    );
    assert!(orig_marker.exists(), "the originally-opened image must run");
    assert!(
        !repl_marker.exists(),
        "the swapped-in path must not be the executed image"
    );
}

/// A wrong expected pin is refused with the typed `BridgeIntegrity` error, and the bridge
/// is never spawned.
#[test]
fn wrong_pin_refuses_before_spawn() {
    let dir = cwd_dir();
    let marker = dir.path().join("ran-marker");
    let bridge = write_marker_exe(dir.path(), "bridge", &marker);

    // Flip one bit of the real digest.
    let mut wrong = sha256_of(&bridge);
    wrong[0] ^= 0xff;

    let r = Runner::without_interop_check(&bridge, dir.path())
        .taskkill_program("/bin/true")
        .expected_sha256(wrong);
    match r.probe(Duration::from_secs(5)) {
        Err(RunnerError::BridgeIntegrity { path, detail }) => {
            assert_eq!(path, bridge);
            assert!(detail.contains("mismatch"), "{detail}");
        }
        other => panic!("expected BridgeIntegrity, got {other:?}"),
    }
    assert!(
        !marker.exists(),
        "the bridge must not be spawned when the pin fails"
    );
}

/// The exchange reports the executed descriptor's digest, which is the value enrollment
/// records as the pin.
#[test]
fn exchange_reports_the_executed_digest() {
    let dir = cwd_dir();
    let r = build_runner(dir.path(), &["ok"]);
    let exchange = r
        .probe_with_diagnostics(Duration::from_secs(5))
        .expect("probe");
    assert_eq!(exchange.bridge_sha256, sha256_of(Path::new(FAKE)));
}

/// The pin is enforced on the auth path too, and the diagnostics variant surfaces the
/// digest on success.
#[test]
fn authenticate_with_diagnostics_returns_digest_and_enforces_pin() {
    let dir = cwd_dir();
    let pin = sha256_of(Path::new(FAKE));
    let r = build_runner(dir.path(), &["ok"])
        .expected_sha256(pin)
        .authenticate_with_diagnostics(assert_params(), Duration::from_secs(5))
        .expect("assert");
    assert_eq!(r.bridge_sha256, pin);
}
