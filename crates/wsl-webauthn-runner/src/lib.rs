//! Linux interop spawner (plan §7).
//!
//! This crate spawns the Windows bridge executable over WSL interop, speaks the framed
//! stdio protocol from [`wsl_webauthn_protocol`], and enforces a hard deadline with a
//! bounded, non-blocking read loop. It performs **no trust decisions** — all assertion
//! and attestation verification is the caller's job.
//!
//! # Key behaviours
//!
//! * **No shell, ever.** The bridge is spawned with [`std::process::Command`] and an
//!   argument array (currently zero arguments; the request travels on stdin).
//! * **`current_dir` is the Windows mount root** (`win_mnt`, e.g. `/mnt/c`). The plan's
//!   §7 signatures omit this, but WSL interop breaks when the working directory is not a
//!   translatable Windows path, so all three entry points take `win_mnt` (deviation
//!   documented in the crate report).
//! * **Deadline read loop.** The child's stdout/stderr are put in non-blocking mode and
//!   driven by `poll(2)` with a timeout computed from the caller's deadline. This never
//!   blocks past the deadline and never calls `wait_with_output`.
//! * **Timeout handling.** On deadline expiry the shim is `SIGKILL`ed and reaped; if the
//!   bridge printed its Windows PID as the first stderr line (`PID <n>`), a best-effort
//!   `taskkill.exe /F /PID <n>` is spawned with `current_dir = win_mnt` under a 5 s
//!   budget. Failures are ignored. The deadline is therefore a *lower bound* on the total
//!   time when an escalation runs; see [`RunnerError::Timeout`].
//! * **Held-fd spawn (tamper resistance).** The bridge is opened
//!   `O_RDONLY|O_NOFOLLOW|O_CLOEXEC` and that descriptor — not the path — is what is
//!   spawned, so a check-then-use swap between the module's hash and the exec cannot change
//!   the executed image. A `pre_exec` guard re-checks `(dev, ino)` immediately before
//!   `execve` as belt-and-braces. See the `L2-2` note in `proc::TrustedFile`.
//! * **Pre-flight.** [`RunnerError::BridgeMissing`] only if the bridge path genuinely
//!   does not exist (`NotFound`); any other open failure (e.g. `EACCES` on an
//!   unreadable parent, or `ELOOP` for a symlinked bridge) is [`RunnerError::Spawn`]
//!   carrying the real `io::Error`.
//!   [`RunnerError::InteropUnavailable`] if the WSL interop binfmt entry is absent or not
//!   `enabled`. All fail fast without spawning.
//! * **Ceremony vs. transport.** A well-formed `ok:false` framed response is returned as
//!   [`RunnerResponse::Error`] inside `Ok`. Transport problems (non-zero exit, malformed
//!   framing, oversize, EOF) become [`RunnerError`].
//!
//! # Errors
//!
//! [`RunnerError`] distinguishes transport failures; ceremony failures are **not** errors.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod proc;

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;
use wsl_webauthn_protocol::{
    BridgeError, FrameError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Request, Response, b64u_decode,
    read_frame,
};

/// Path of the WSL interop binfmt_misc registration (plan §7 pre-flight).
pub const SYSTEM_INTEROP_PATH: &str = "/proc/sys/fs/binfmt_misc/WSLInterop";

/// `timeout_ms` sent to the bridge for a `probe` (plan §3).
pub const BRIDGE_PROBE_TIMEOUT_MS: u32 = 3_000;

/// Default `timeout_ms` for `enroll` (mirrors the protocol constant, plan §3).
pub const BRIDGE_ENROLL_TIMEOUT_MS: u32 = wsl_webauthn_protocol::BRIDGE_ENROLL_TIMEOUT_MS;

/// Default `timeout_ms` for `assert` (mirrors the protocol constant, plan §3).
pub const BRIDGE_ASSERT_TIMEOUT_MS: u32 = wsl_webauthn_protocol::BRIDGE_AUTH_TIMEOUT_MS;

/// Maximum bytes of the child's stderr we retain (bounded capture).
pub const MAX_STDERR_BYTES: usize = 4 * 1024;

/// Maximum bytes of the retained stderr tail that is folded into an error diagnostic.
///
/// Deliberately much smaller than [`MAX_STDERR_BYTES`]: the bridge writes its Windows PID
/// as the first stderr line on every run, followed by at most a few diagnostic lines (an
/// HRESULT/error name). A short tail keeps syslog records and PAM reason strings bounded
/// while still carrying the useful line.
pub const STDERR_DIAGNOSTIC_BYTES: usize = 512;

/// `taskkill.exe` escalation budget after a Linux-side timeout.
pub const TASKKILL_BUDGET: Duration = Duration::from_secs(5);

/// Poll granularity used while waiting for the child (keeps deadline checks responsive).
const POLL_GRANULARITY: Duration = Duration::from_millis(20);

/// Short backoff used on the EOF fast path (both child pipes closed, child not yet
/// reaped). A full [`POLL_GRANULARITY`] tick would add up to ~20 ms after the response is
/// already in hand, delaying the `sudo` shell.
const EOF_SPIN: Duration = Duration::from_millis(1);

/// How long [`EOF_SPIN`] is used before backing off to [`POLL_GRANULARITY`]. Bounds the
/// extra wakeups a child that closed its stdio but stays alive for a long time can cause.
const EOF_SPIN_WINDOW: Duration = Duration::from_millis(5);

/// Errors from spawning or talking to the bridge.
///
/// These are all *transport* failures. A ceremony failure arrives as
/// [`RunnerResponse::Error`] on the success path instead.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// The bridge executable does not exist.
    #[error("bridge executable not found: {path}")]
    BridgeMissing {
        /// The missing path.
        path: PathBuf,
    },
    /// WSL interop is not available (binfmt_misc entry absent or not enabled).
    #[error("WSL interop unavailable ({path}): {detail}")]
    InteropUnavailable {
        /// The binfmt_misc path that was checked.
        path: PathBuf,
        /// Why the check failed.
        detail: String,
    },
    /// The request could not be encoded within the wire size cap.
    #[error("request too large: {len} bytes exceeds cap {cap}")]
    RequestTooLarge {
        /// Encoded payload length.
        len: usize,
        /// Maximum accepted payload length.
        cap: usize,
    },
    /// The bridge could not be inspected or spawned.
    ///
    /// Covers both an `exec` failure and a pre-flight `stat` that failed for a reason
    /// other than `NotFound` (e.g. `EACCES` on an unreadable parent directory).
    #[error("failed to spawn bridge {path}: {source}")]
    Spawn {
        /// The bridge path.
        path: PathBuf,
        /// The underlying stat/exec error.
        #[source]
        source: std::io::Error,
    },
    /// The child exited non-zero (transport failure per the process contract).
    ///
    /// `reason` distinguishes a normal exit code from death by signal; `message` is the
    /// pre-composed human-readable description: the documented meaning of the exit code
    /// (or the signal name/number) plus a bounded, sanitized tail of the child's stderr
    /// (the bridge's HRESULT/error line, when present).
    #[error("{message}")]
    BridgeFailed {
        /// How the child terminated (exit code or signal).
        reason: ExitReason,
        /// Exit-code/signal meaning plus the bounded stderr tail, ready for a log line.
        message: String,
    },
    /// Malformed framing, unexpected EOF, oversize response, or an IO failure mid-stream.
    #[error("bridge transport error: {message}")]
    Transport {
        /// Human-readable description.
        message: String,
    },
    /// The caller's deadline expired before a complete response arrived.
    ///
    /// This is a **lower bound**: when the bridge reported a Windows PID on stderr, a
    /// best-effort `taskkill.exe` escalation runs afterwards with its own
    /// [`TASKKILL_BUDGET`] (5 s), so the call can take up to that much longer than
    /// `deadline_ms`. The escalation is a backstop, not part of the promise.
    #[error("bridge exceeded deadline of {deadline_ms} ms")]
    Timeout {
        /// The deadline that expired, in milliseconds.
        deadline_ms: u64,
        /// Windows PID parsed from the bridge's first stderr line, if any.
        windows_pid: Option<u32>,
        /// Whether a `taskkill.exe` escalation was attempted.
        taskkill_attempted: bool,
    },
    /// A bare interop helper name could not be resolved to an absolute path.
    ///
    /// Bare names are not portable under `sudo`'s `secure_path`, which hides the Windows
    /// mount; the kernel's binfmt handoff needs an absolute path.
    #[error(
        "cannot resolve Windows interop helper {program:?}: not found under {win_mnt} or on \
PATH (when running under sudo, secure_path can hide the Windows mount; use the absolute path)"
    )]
    InteropHelperMissing {
        /// The bare helper name that could not be resolved.
        program: String,
        /// The Windows mount root it was searched under.
        win_mnt: PathBuf,
    },
}

/// How a bridge process terminated.
///
/// Distinguishes a normal exit code from death by an unmasked signal, so a transport
/// failure names the actual cause instead of an ambiguous `None` status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Exited normally with this code (`0..=255`).
    Code(i32),
    /// Killed by this signal number (e.g. `9` = `SIGKILL`).
    Signal(i32),
}

impl ExitReason {
    /// Classify an [`ExitStatus`].
    pub fn from_status(status: &ExitStatus) -> ExitReason {
        use std::os::unix::process::ExitStatusExt;
        match status.code() {
            Some(code) => ExitReason::Code(code),
            // No exit code means the child was terminated by a signal.
            None => ExitReason::Signal(status.signal().unwrap_or(0)),
        }
    }

    /// The exit code, if this was a normal exit.
    pub fn code(self) -> Option<i32> {
        match self {
            ExitReason::Code(code) => Some(code),
            ExitReason::Signal(_) => None,
        }
    }

    /// The terminating signal, if any.
    pub fn signal(self) -> Option<i32> {
        match self {
            ExitReason::Code(_) => None,
            ExitReason::Signal(sig) => Some(sig),
        }
    }
}

impl std::fmt::Display for ExitReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitReason::Code(code) => write!(f, "exit code {code}"),
            ExitReason::Signal(signal) => {
                write!(f, "signal {signal} ({})", signal_name(*signal))
            }
        }
    }
}

/// Name of a POSIX signal number, for diagnostics (falls back to the raw number).
fn signal_name(signal: i32) -> String {
    match signal {
        libc::SIGHUP => "SIGHUP".to_string(),
        libc::SIGINT => "SIGINT".to_string(),
        libc::SIGQUIT => "SIGQUIT".to_string(),
        libc::SIGILL => "SIGILL".to_string(),
        libc::SIGTRAP => "SIGTRAP".to_string(),
        libc::SIGABRT => "SIGABRT".to_string(),
        libc::SIGBUS => "SIGBUS".to_string(),
        libc::SIGFPE => "SIGFPE".to_string(),
        libc::SIGKILL => "SIGKILL".to_string(),
        libc::SIGUSR1 => "SIGUSR1".to_string(),
        libc::SIGSEGV => "SIGSEGV".to_string(),
        libc::SIGUSR2 => "SIGUSR2".to_string(),
        libc::SIGPIPE => "SIGPIPE".to_string(),
        libc::SIGALRM => "SIGALRM".to_string(),
        libc::SIGTERM => "SIGTERM".to_string(),
        other => format!("signal {other}"),
    }
}

/// A decoded, protocol-valid response from the bridge.
///
/// [`RunnerResponse::Error`] carries a *ceremony* failure (the transport succeeded); the
/// PAM/CLI callers map it to their own error codes. This deliberately keeps ceremony and
/// transport failures distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerResponse {
    /// Reply to a probe.
    Probe {
        /// Whether a user-verifying platform authenticator is available.
        uv_platform_available: bool,
        /// `WebAuthNGetApiVersionNumber()` as seen by the bridge.
        api_version: u32,
    },
    /// Reply to an enrollment.
    Enroll {
        /// Attestation statement format (e.g. `packed`).
        format: String,
        /// Full CBOR attestation object (b64url).
        attestation_object: String,
        /// Credential ID cross-checked against `authData` (b64url).
        credential_id: String,
    },
    /// Reply to an assertion.
    Assert {
        /// Authenticator data (b64url).
        authenticator_data: String,
        /// Signature over `authenticatorData || SHA-256(clientDataJSON)` (b64url).
        signature: String,
        /// Credential ID used (b64url).
        credential_id: String,
        /// Echo of the request `clientDataJSON` when available (b64url), else `None`.
        client_data_json_echo: Option<String>,
    },
    /// A ceremony failure delivered on a healthy transport.
    Error(BridgeError),
}

/// A decoded bridge response together with bounded diagnostics from the same exchange.
///
/// On an `ok:false` ceremony failure the bridge writes its Windows HRESULT/error line to
/// **stderr** and then exits `0` with a well-formed frame on stdout. The plain
/// [`RunnerResponse`] carries only the coarse taxonomy, so callers that want the HRESULT
/// (the PAM logger) use [`Runner::authenticate_with_diagnostics`] and log
/// [`RunnerExchange::bridge_stderr`].
///
/// `bridge_stderr` is a NUL/control-escaped tail of at most [`STDERR_DIAGNOSTIC_BYTES`]
/// bytes; it is `None` when the child wrote nothing to stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerExchange {
    /// The decoded response (ceremony result or error).
    pub response: RunnerResponse,
    /// Sanitized, bounded stderr tail from the exchange, if any.
    pub bridge_stderr: Option<String>,
}

/// Errors from decoding b64url fields of a [`RunnerResponse`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// A decoder for one variant was called on another.
    #[error("response variant is not {expected}")]
    WrongVariant {
        /// The variant the field belongs to, e.g. `assert`.
        expected: &'static str,
    },
    /// A field that must be present was `null`/absent.
    #[error("field {field} is null")]
    Null {
        /// The field name.
        field: &'static str,
    },
    /// A base64url field was malformed.
    #[error(transparent)]
    Base64(#[from] FrameError),
}

impl RunnerResponse {
    /// Decode the `attestation_object` of an [`RunnerResponse::Enroll`].
    pub fn decode_attestation_object(&self) -> Result<Vec<u8>, DecodeError> {
        match self {
            RunnerResponse::Enroll {
                attestation_object, ..
            } => Ok(b64u_decode(attestation_object)?),
            _ => Err(DecodeError::WrongVariant { expected: "enroll" }),
        }
    }

    /// Decode the `credential_id` of an enroll or assert response.
    pub fn decode_credential_id(&self) -> Result<Vec<u8>, DecodeError> {
        match self {
            RunnerResponse::Enroll { credential_id, .. }
            | RunnerResponse::Assert { credential_id, .. } => Ok(b64u_decode(credential_id)?),
            _ => Err(DecodeError::WrongVariant {
                expected: "enroll|assert",
            }),
        }
    }

    /// Decode the `authenticator_data` of an [`RunnerResponse::Assert`].
    pub fn decode_authenticator_data(&self) -> Result<Vec<u8>, DecodeError> {
        match self {
            RunnerResponse::Assert {
                authenticator_data, ..
            } => Ok(b64u_decode(authenticator_data)?),
            _ => Err(DecodeError::WrongVariant { expected: "assert" }),
        }
    }

    /// Decode the `signature` of an [`RunnerResponse::Assert`].
    pub fn decode_signature(&self) -> Result<Vec<u8>, DecodeError> {
        match self {
            RunnerResponse::Assert { signature, .. } => Ok(b64u_decode(signature)?),
            _ => Err(DecodeError::WrongVariant { expected: "assert" }),
        }
    }

    /// Decode the optional `client_data_json_echo` of an [`RunnerResponse::Assert`].
    ///
    /// Returns `Ok(None)` when the bridge reported no echo (ASSERTION v1–v5).
    pub fn decode_client_data_json_echo(&self) -> Result<Option<Vec<u8>>, DecodeError> {
        match self {
            RunnerResponse::Assert {
                client_data_json_echo,
                ..
            } => match client_data_json_echo {
                Some(v) => Ok(Some(b64u_decode(v)?)),
                None => Ok(None),
            },
            _ => Err(DecodeError::WrongVariant { expected: "assert" }),
        }
    }
}

/// A configured bridge invoker.
///
/// Construct with [`Runner::new`] (or [`Runner::with_interop_path`]); call
/// [`Runner::probe`], [`Runner::enroll`], or [`Runner::authenticate`]. The
/// `without_interop_check`/`args`/`taskkill_program` seams are test support behind the
/// non-default `test-support` feature.
#[derive(Debug, Clone)]
pub struct Runner {
    bridge: PathBuf,
    win_mnt: PathBuf,
    interop_path: PathBuf,
    check_interop: bool,
    args: Vec<std::ffi::OsString>,
    taskkill_program: std::ffi::OsString,
}

impl Runner {
    /// Create a runner for `bridge` with `win_mnt` as the child's working directory.
    ///
    /// The real [`SYSTEM_INTEROP_PATH`] is checked before every spawn.
    pub fn new(bridge: impl AsRef<Path>, win_mnt: impl AsRef<Path>) -> Runner {
        Runner {
            bridge: bridge.as_ref().to_path_buf(),
            win_mnt: win_mnt.as_ref().to_path_buf(),
            interop_path: PathBuf::from(SYSTEM_INTEROP_PATH),
            check_interop: true,
            args: Vec::new(),
            taskkill_program: std::ffi::OsString::from("taskkill.exe"),
        }
    }

    /// Like [`Runner::new`] but checks a custom binfmt path (for tests and non-standard
    /// installations).
    pub fn with_interop_path(
        bridge: impl AsRef<Path>,
        win_mnt: impl AsRef<Path>,
        interop_path: impl AsRef<Path>,
    ) -> Runner {
        let mut runner = Runner::new(bridge, win_mnt);
        runner.interop_path = interop_path.as_ref().to_path_buf();
        runner
    }

    /// Like [`Runner::new`] but skips the interop check entirely.
    ///
    /// **Test/harness only** — production callers must use the checked constructors.
    /// Available only with the non-default `test-support` feature.
    #[cfg(feature = "test-support")]
    pub fn without_interop_check(bridge: impl AsRef<Path>, win_mnt: impl AsRef<Path>) -> Runner {
        let mut runner = Runner::new(bridge, win_mnt);
        runner.check_interop = false;
        runner
    }

    /// Enable or disable the interop pre-flight (builder form).
    ///
    /// Test support only: production callers must keep the pre-flight enabled.
    #[cfg(feature = "test-support")]
    pub fn interop_check(mut self, enabled: bool) -> Self {
        self.check_interop = enabled;
        self
    }

    /// Override the binfmt path checked during pre-flight (builder form).
    pub fn interop_path(mut self, path: impl AsRef<Path>) -> Self {
        self.interop_path = path.as_ref().to_path_buf();
        self
    }

    /// Set the argument array passed to the bridge (test support; production bridges take
    /// no arguments and receive their request on stdin). Available only with the
    /// non-default `test-support` feature.
    #[cfg(feature = "test-support")]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Override the program used to cancel a timed-out Windows PID (default
    /// `taskkill.exe`).
    ///
    /// Exposed so tests never invoke the real `taskkill.exe` found on WSL hosts; using
    /// an absolute Linux path (e.g. `/bin/false`) makes the escalation deterministic and
    /// side-effect free. Available only with the non-default `test-support` feature.
    #[cfg(feature = "test-support")]
    pub fn taskkill_program(mut self, program: impl Into<std::ffi::OsString>) -> Self {
        self.taskkill_program = program.into();
        self
    }

    /// The configured bridge path.
    pub fn bridge(&self) -> &Path {
        &self.bridge
    }

    /// The configured Windows mount root.
    pub fn win_mnt(&self) -> &Path {
        &self.win_mnt
    }

    /// Probe for a user-verifying platform authenticator.
    ///
    /// Uses [`BRIDGE_PROBE_TIMEOUT_MS`] as the bridge `timeout_ms`.
    pub fn probe(&self, deadline: Duration) -> Result<RunnerResponse, RunnerError> {
        self.run(
            Request::Probe {
                timeout_ms: BRIDGE_PROBE_TIMEOUT_MS,
            },
            deadline,
        )
        .map(|exchange| exchange.response)
    }

    /// Enroll a credential, using the caller-supplied [`EnrollParams`].
    pub fn enroll(
        &self,
        params: EnrollParams,
        deadline: Duration,
    ) -> Result<RunnerResponse, RunnerError> {
        self.run(
            Request::Enroll {
                client_data_json: params.client_data_json,
                user_id: params.user_id,
                user_name: params.user_name,
                user_display_name: params.user_display_name,
                algs: params.algs,
                timeout_ms: params.timeout_ms,
            },
            deadline,
        )
        .map(|exchange| exchange.response)
    }

    /// Produce an assertion, using the caller-supplied [`AssertParams`].
    pub fn authenticate(
        &self,
        params: AssertParams,
        deadline: Duration,
    ) -> Result<RunnerResponse, RunnerError> {
        self.run(
            Request::Assert {
                client_data_json: params.client_data_json,
                allow_credentials: params.allow_credentials,
                timeout_ms: params.timeout_ms,
            },
            deadline,
        )
        .map(|exchange| exchange.response)
    }

    /// Like [`Runner::authenticate`], but also returns the bounded bridge-stderr tail.
    ///
    /// The bridge reports an `internal` (or other) ceremony failure as an `ok:false`
    /// frame with exit `0`, writing its HRESULT/error line to stderr. That diagnostic is
    /// otherwise discarded on the success path; this variant carries it so an audit
    /// logger can record it. All authentication *decisions* still come from
    /// [`RunnerExchange::response`]; `bridge_stderr` is diagnostic only.
    pub fn authenticate_with_diagnostics(
        &self,
        params: AssertParams,
        deadline: Duration,
    ) -> Result<RunnerExchange, RunnerError> {
        self.run(
            Request::Assert {
                client_data_json: params.client_data_json,
                allow_credentials: params.allow_credentials,
                timeout_ms: params.timeout_ms,
            },
            deadline,
        )
    }

    /// Run one request/response exchange against the bridge.
    fn run(&self, request: Request, deadline: Duration) -> Result<RunnerExchange, RunnerError> {
        let bridge = self.preflight()?;

        let payload = serde_json::to_vec(&request).map_err(|e| RunnerError::Transport {
            message: format!("encoding request: {e}"),
        })?;
        if payload.len() > MAX_REQUEST_BYTES {
            return Err(RunnerError::RequestTooLarge {
                len: payload.len(),
                cap: MAX_REQUEST_BYTES,
            });
        }
        let frame = wsl_webauthn_protocol::encode_frame(&payload);

        // Spawn the *held descriptor*, not the path: `/proc/self/fd/N` resolves to the
        // inode opened (O_NOFOLLOW) during pre-flight, so a path swap after that open
        // cannot change the executed image. `bridge` owns the descriptor until the end of
        // this function; the child has its own inheritable duplicate. A `pre_exec` guard
        // re-checks (dev,ino) immediately before `execve` as belt-and-braces.
        let mut command = Command::new(bridge.fd_path());
        command
            .args(&self.args)
            .current_dir(&self.win_mnt)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        proc::set_spawn_guard(&mut command, &bridge);
        let child = command.spawn().map_err(|source| RunnerError::Spawn {
            path: self.bridge.clone(),
            source,
        })?;

        // Own the child for the rest of the exchange: every early return below (including
        // the `?`-propagated ones) now kills and reaps it via `ChildGuard::drop`.
        let mut guard = ChildGuard::new(child);

        // Write the single framed request, then close stdin. 8 KiB fits comfortably in
        // the default 64 KiB pipe buffer, but we still make the write non-blocking and
        // bound it by the deadline: a bridge/child that never reads stdin must never be
        // able to hang the PAM stack past its deadline.
        {
            let stdin = guard.child_mut().stdin.take().expect("stdin was piped");
            if let Err(e) = self.write_frame(stdin.as_raw_fd(), &frame, deadline) {
                let status = guard.try_wait().ok().flatten();
                guard.kill_and_reap();
                return Err(match status {
                    Some(status) if !status.success() => bridge_failed(&status, &[]),
                    _ => e,
                });
            }
            // `stdin` is dropped here, closing the read side of the child's pipe.
        }

        let stdout = guard.child_mut().stdout.take().expect("stdout was piped");
        let stderr = guard.child_mut().stderr.take().expect("stderr was piped");
        self.pump(guard, stdout, stderr, deadline)
    }

    /// Fast-fail pre-flight checks, then hold the bridge descriptor for the spawn.
    ///
    /// The bridge is opened `O_RDONLY|O_NOFOLLOW` and the descriptor is returned, so the
    /// caller spawns exactly the opened inode rather than re-resolving the path (closing
    /// the hash→exec check-then-use window; see `L2-2`). Because the path is never used
    /// for the spawn, a symlink is refused (`O_NOFOLLOW` → `ELOOP`), not followed.
    fn preflight(&self) -> Result<proc::TrustedFile, RunnerError> {
        // `Path::exists()`/`metadata` collapse *every* `stat` failure into "missing".
        // Open directly so only a genuine `NotFound` is reported as
        // [`RunnerError::BridgeMissing`]; any other OS error (EACCES on an unreadable
        // parent, ELOOP on a symlink, ENAMETOOLONG, …) is surfaced with its real
        // `io::Error` instead of being disguised.
        let bridge =
            proc::TrustedFile::open(&self.bridge).map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => RunnerError::BridgeMissing {
                    path: self.bridge.clone(),
                },
                _ => RunnerError::Spawn {
                    path: self.bridge.clone(),
                    source,
                },
            })?;
        if self.check_interop {
            let contents = std::fs::read_to_string(&self.interop_path).map_err(|e| {
                RunnerError::InteropUnavailable {
                    path: self.interop_path.clone(),
                    detail: e.to_string(),
                }
            })?;
            let enabled = contents.lines().any(|line| line.trim() == "enabled");
            if !enabled {
                return Err(RunnerError::InteropUnavailable {
                    path: self.interop_path.clone(),
                    detail: "registration does not contain an `enabled` line".to_string(),
                });
            }
        }
        Ok(bridge)
    }

    /// Write `frame` to the child's stdin with a non-blocking, deadline-bounded loop.
    ///
    /// The frame (≤ [`MAX_REQUEST_BYTES`]) normally fits the 64 KiB pipe buffer in a
    /// single `write`, so this returns immediately. It exists so a child that never drains
    /// its stdin cannot block the PAM stack past `deadline`.
    ///
    /// Write errors are *not* fatal: a child that has already exited (typically after
    /// writing its response without draining stdin — the framed response is
    /// authoritative per the protocol contract, and WSL interop pipes stdin
    /// unconditionally) surfaces as `EPIPE` here. Instead of failing, the write is
    /// abandoned and the read loop decides: a complete valid frame still succeeds; a
    /// missing or short frame fails closed on the read path (`Transport` or
    /// `Timeout`). This keeps "early-exit child with a valid response" working while
    /// never accepting an incomplete one.
    fn write_frame(
        &self,
        fd: std::os::fd::RawFd,
        frame: &[u8],
        deadline: Duration,
    ) -> Result<(), RunnerError> {
        proc::set_nonblocking(fd).map_err(|e| RunnerError::Transport {
            message: format!("setting stdin non-blocking: {e}"),
        })?;
        let start = Instant::now();
        let mut offset = 0usize;
        while offset < frame.len() {
            match proc::write(fd, &frame[offset..]) {
                Ok(0) => {
                    // Read end closed: the child exited early. Abandon the write
                    // without error; the read path is authoritative.
                    return Ok(());
                }
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let elapsed = start.elapsed();
                    if elapsed >= deadline {
                        return Err(RunnerError::Timeout {
                            deadline_ms: deadline.as_millis() as u64,
                            windows_pid: None,
                            taskkill_attempted: false,
                        });
                    }
                    let remaining = deadline.saturating_sub(elapsed);
                    let poll_ms = remaining.as_millis().min(POLL_GRANULARITY.as_millis()) as i32;
                    let mut fds = [libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    }];
                    match proc::poll(&mut fds, poll_ms) {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => {
                            return Err(RunnerError::Transport {
                                message: format!("poll on bridge stdin: {e}"),
                            });
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    // EPIPE (child exited), EIO, or any other write error: abandon
                    // the write without failing. If the child produced a complete
                    // response it is still honored; otherwise the read path fails
                    // closed (EOF/no frame → Transport, or Timeout).
                    let _ = e;
                    return Ok(());
                }
            }
            // Bound a pathological child that accepts only a byte at a time.
            if start.elapsed() >= deadline {
                return Err(RunnerError::Timeout {
                    deadline_ms: deadline.as_millis() as u64,
                    windows_pid: None,
                    taskkill_attempted: false,
                });
            }
        }
        Ok(())
    }

    /// Non-blocking read loop bounded by `deadline`.
    ///
    /// Delegates the deadline/poll/drain mechanics to the shared [`drive_child`] engine
    /// and maps its outcome onto the runner's transport contract.
    fn pump(
        &self,
        guard: ChildGuard,
        stdout: std::process::ChildStdout,
        stderr: std::process::ChildStderr,
        deadline: Duration,
    ) -> Result<RunnerExchange, RunnerError> {
        match drive_child(
            guard,
            stdout,
            stderr,
            deadline,
            MAX_RESPONSE_BYTES + 4, // frame prefix + payload
            MAX_STDERR_BYTES,
        ) {
            DriveOutcome::Exited {
                status,
                stdout,
                stderr,
            } => self.finish(status, &stdout, &stderr),
            DriveOutcome::TimedOut { stderr } => self.deadline_error(deadline, &stderr),
            DriveOutcome::StdoutOverflow => Err(RunnerError::Transport {
                message: format!("response exceeds {MAX_RESPONSE_BYTES} bytes"),
            }),
            DriveOutcome::Failed { message } => Err(RunnerError::Transport { message }),
        }
    }

    /// Interpret a fully-drained child: parse the response or map the exit status.
    ///
    /// `err_buf` is the bounded stderr captured during the same exchange. It is folded
    /// into transport/bridge-failure diagnostics (the bridge's HRESULT line lives there)
    /// and returned alongside a successful ceremony response so a caller can log it.
    fn finish(
        &self,
        status: ExitStatus,
        out_buf: &[u8],
        err_buf: &[u8],
    ) -> Result<RunnerExchange, RunnerError> {
        // Non-zero exit is a transport failure even if bytes happen to parse.
        if !status.success() {
            return Err(bridge_failed(&status, err_buf));
        }

        let mut cursor = std::io::Cursor::new(out_buf);
        let payload = read_frame(&mut cursor, MAX_RESPONSE_BYTES)
            .map_err(|e| transport_with_stderr(format!("reading response frame: {e}"), err_buf))?;
        // The exchange is exactly one frame. Anything after it means the child emitted
        // extra bytes (a second frame, or garbage); treat that as a transport failure
        // rather than silently ignoring it.
        let consumed = cursor.position() as usize;
        if consumed != out_buf.len() {
            return Err(transport_with_stderr(
                format!(
                    "trailing bytes after response frame: {} unread of {}",
                    out_buf.len() - consumed,
                    out_buf.len()
                ),
                err_buf,
            ));
        }
        let response: Response = serde_json::from_slice(&payload)
            .map_err(|e| transport_with_stderr(format!("parsing response JSON: {e}"), err_buf))?;
        Ok(RunnerExchange {
            response: runner_response(response),
            bridge_stderr: stderr_tail(err_buf, STDERR_DIAGNOSTIC_BYTES),
        })
    }

    /// Deadline expired: the child has already been killed and reaped by the [`ChildGuard`]
    /// inside [`drive_child`]; best-effort cancel the Windows PID reported on stderr.
    fn deadline_error(
        &self,
        deadline: Duration,
        err_buf: &[u8],
    ) -> Result<RunnerExchange, RunnerError> {
        let windows_pid = parse_pid_line(err_buf);
        let taskkill_attempted = match windows_pid {
            Some(pid) => {
                self.taskkill(pid);
                true
            }
            None => false,
        };
        Err(RunnerError::Timeout {
            deadline_ms: deadline.as_millis() as u64,
            windows_pid,
            taskkill_attempted,
        })
    }

    /// Best-effort `taskkill.exe /F /PID <pid>` with `cwd = win_mnt`, 5 s budget.
    ///
    /// # Untrusted PID
    ///
    /// `pid` is parsed from the bridge's stderr and is **not authenticated**: a malicious
    /// or spoofed bridge can print any `PID <n>` it likes. This is therefore only a
    /// best-effort cancellation hint and is never used for any trust decision. It runs
    /// only after a Linux-side timeout, and the bridge already executes with the invoking
    /// user's privileges, so the escalation grants an attacker no privilege they did not
    /// already have — but it *can* terminate an arbitrary process owned by that same user
    /// on the Windows side. All failures are ignored: this is a backstop, not a security
    /// control.
    fn taskkill(&self, pid: u32) {
        let Some(resolved) = resolve_interop_program(&self.taskkill_program, &self.win_mnt) else {
            return;
        };
        let mut command = Command::new(resolved);
        command
            .arg("/F")
            .arg("/PID")
            .arg(pid.to_string())
            .current_dir(&self.win_mnt)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let Ok(mut child) = command.spawn() else {
            return;
        };
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
            if start.elapsed() >= TASKKILL_BUDGET {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Parameters for [`Runner::enroll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollParams {
    /// `clientDataJSON` built by the caller (b64url).
    pub client_data_json: String,
    /// WebAuthn user handle (b64url, ≤ 64 bytes).
    pub user_id: String,
    /// WebAuthn user name.
    pub user_name: String,
    /// WebAuthn user display name.
    pub user_display_name: String,
    /// Allowed COSE algorithm identifiers in preference order.
    pub algs: Vec<i32>,
    /// Per-ceremony timeout sent to the bridge (`timeout_ms`).
    pub timeout_ms: u32,
}

impl EnrollParams {
    /// Build enrollment parameters with the default algorithm allow-list `[-7, -257]`.
    pub fn new(
        client_data_json: impl Into<String>,
        user_id: impl Into<String>,
        user_name: impl Into<String>,
        user_display_name: impl Into<String>,
    ) -> EnrollParams {
        EnrollParams {
            client_data_json: client_data_json.into(),
            user_id: user_id.into(),
            user_name: user_name.into(),
            user_display_name: user_display_name.into(),
            algs: vec![-7, -257],
            timeout_ms: BRIDGE_ENROLL_TIMEOUT_MS,
        }
    }

    /// Override the allowed algorithms.
    pub fn with_algs(mut self, algs: Vec<i32>) -> Self {
        self.algs = algs;
        self
    }

    /// Override the bridge `timeout_ms`.
    pub fn with_timeout_ms(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// Parameters for [`Runner::authenticate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertParams {
    /// `clientDataJSON` built by the caller (b64url).
    pub client_data_json: String,
    /// Credential IDs the authenticator may use (b64url each).
    pub allow_credentials: Vec<String>,
    /// Per-ceremony timeout sent to the bridge (`timeout_ms`).
    pub timeout_ms: u32,
}

impl AssertParams {
    /// Build assertion parameters with the default bridge timeout.
    pub fn new(
        client_data_json: impl Into<String>,
        allow_credentials: Vec<String>,
    ) -> AssertParams {
        AssertParams {
            client_data_json: client_data_json.into(),
            allow_credentials,
            timeout_ms: BRIDGE_ASSERT_TIMEOUT_MS,
        }
    }

    /// Override the bridge `timeout_ms`.
    pub fn with_timeout_ms(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// Convert a protocol [`Response`] into a [`RunnerResponse`].
fn runner_response(response: Response) -> RunnerResponse {
    match response {
        Response::Probe {
            uv_platform_available,
            api_version,
            ..
        } => RunnerResponse::Probe {
            uv_platform_available,
            api_version,
        },
        Response::Enroll {
            format,
            attestation_object,
            credential_id,
            ..
        } => RunnerResponse::Enroll {
            format,
            attestation_object,
            credential_id,
        },
        Response::Assert {
            authenticator_data,
            signature,
            credential_id,
            client_data_json_echo,
            ..
        } => RunnerResponse::Assert {
            authenticator_data,
            signature,
            credential_id,
            client_data_json_echo,
        },
        Response::Error { error, .. } => RunnerResponse::Error(error),
    }
}

/// Documented meaning of a bridge exit code (see the bridge process contract).
fn bridge_exit_meaning(reason: ExitReason) -> &'static str {
    match reason {
        ExitReason::Code(3) => {
            "malformed/oversized/truncated request frame or invalid request body \
             (bridge transport failure)"
        }
        ExitReason::Code(4) => {
            "valid JSON object whose `op` is not probe/enroll/assert (bridge transport failure)"
        }
        ExitReason::Code(5) => {
            "stdout write/flush failure while emitting the response (bridge transport failure)"
        }
        ExitReason::Code(_) => "unrecognized bridge transport failure",
        ExitReason::Signal(_) => "terminated by a signal before writing a response",
    }
}

/// Build a [`RunnerError::BridgeFailed`] carrying the exit reason and stderr tail.
fn bridge_failed(status: &ExitStatus, err_buf: &[u8]) -> RunnerError {
    let reason = ExitReason::from_status(status);
    let label = match reason {
        ExitReason::Code(code) => format!("bridge exited with status {code}"),
        ExitReason::Signal(signal) => {
            format!(
                "bridge terminated by signal {signal} ({})",
                signal_name(signal)
            )
        }
    };
    let mut message = format!("{label}: {}", bridge_exit_meaning(reason));
    if let Some(tail) = stderr_tail(err_buf, STDERR_DIAGNOSTIC_BYTES) {
        message.push_str(" (stderr: ");
        message.push_str(&tail);
        message.push(')');
    }
    RunnerError::BridgeFailed { reason, message }
}

/// Attach the bounded stderr tail to a transport error message.
fn transport_with_stderr(message: String, err_buf: &[u8]) -> RunnerError {
    match stderr_tail(err_buf, STDERR_DIAGNOSTIC_BYTES) {
        Some(tail) => RunnerError::Transport {
            message: format!("{message} (bridge stderr: {tail})"),
        },
        None => RunnerError::Transport { message },
    }
}

/// Render at most `cap` bytes of the child's stderr as a single-line, NUL/control-escaped
/// diagnostic string.
///
/// The stderr text is attacker-influenced (child output), so bytes that could corrupt a
/// syslog record or the PAM reason string are escaped: newlines collapse to ` | ` and any
/// other non-printable character becomes a visible `\u{..}` escape. Returns `None` for an
/// empty (or all-whitespace) tail so callers can omit the diagnostic entirely.
fn stderr_tail(bytes: &[u8], cap: usize) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let slice = &bytes[..bytes.len().min(cap)];
    let mut out = String::with_capacity(slice.len());
    for ch in String::from_utf8_lossy(slice).chars() {
        match ch {
            '\n' | '\r' => out.push_str(" | "),
            c if c == '\t' || (' '..='~').contains(&c) => out.push(c),
            c => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
        }
    }
    let trimmed = out.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Owns a spawned child and guarantees it is killed and reaped on drop.
///
/// `std::process::Child` does *not* reap on drop, so every early return in the
/// spawn/write/drain paths used to leak a running (root-spawned) child. Wrapping the
/// child in this guard makes those paths safe by construction: whatever `?`/`return`
/// unwinds, the child is `SIGKILL`ed and waited on.
struct ChildGuard {
    child: Option<std::process::Child>,
}

impl ChildGuard {
    fn new(child: std::process::Child) -> ChildGuard {
        ChildGuard { child: Some(child) }
    }

    /// Access the still-owned child.
    fn child_mut(&mut self) -> &mut std::process::Child {
        self.child.as_mut().expect("child is alive until reaped")
    }

    /// Non-blocking reap. Records the exit so `Drop` will not kill/reap again.
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        let status = child.try_wait()?;
        if status.is_some() {
            self.child = None;
        }
        Ok(status)
    }

    /// `SIGKILL` (via `Child::kill`) and reap, ignoring errors. Idempotent.
    fn kill_and_reap(&mut self) {
        if let Some(mut child) = self.child.take() {
            // `Child::kill` sends SIGKILL; `wait` reaps the process so no zombie remains.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

/// Bounded capture of a single non-blocking child descriptor.
///
/// `overflow` is a *real* persisted flag: once set, [`DrainState::drain`] stops reading
/// and [`DrainState::pollin`] reports the fd as inactive, so an over-cap fd is removed
/// from `poll` instead of staying readable and busy-spinning the loop at ~100% CPU.
struct DrainState {
    fd: std::os::fd::RawFd,
    buf: Vec<u8>,
    cap: usize,
    eof: bool,
    overflow: bool,
}

impl DrainState {
    fn new(fd: std::os::fd::RawFd, cap: usize) -> DrainState {
        DrainState {
            fd,
            buf: Vec::new(),
            cap,
            eof: false,
            overflow: false,
        }
    }

    /// Read whatever is currently buffered, stopping at EOF, `WouldBlock`, or the cap.
    fn drain(&mut self) {
        if self.eof || self.overflow {
            return;
        }
        let mut chunk = [0u8; 8192];
        loop {
            match proc::read(self.fd, &mut chunk) {
                Ok(0) => {
                    self.eof = true;
                    return;
                }
                Ok(n) => {
                    if self.buf.len() + n > self.cap {
                        self.overflow = true;
                        return;
                    }
                    self.buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.eof = true;
                    return;
                }
            }
        }
    }

    /// Whether this fd still needs to be polled (no EOF, no overflow).
    fn pollin(&self) -> bool {
        !self.eof && !self.overflow
    }
}

/// Outcome of driving a child's stdio under a deadline.
enum DriveOutcome {
    /// The child exited; buffers are final.
    Exited {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    /// The deadline elapsed; the child has been killed and reaped.
    TimedOut { stderr: Vec<u8> },
    /// stdout exceeded its cap; the child has been killed and reaped.
    StdoutOverflow,
    /// `poll`/`wait`/`fcntl` failed; the child has been killed and reaped.
    Failed { message: String },
}

/// Shared bounded-IO engine: drive a child's stdout/stderr to completion under a hard
/// deadline.
///
/// Both [`Runner::pump`] and [`InteropCommand::run`] use this instead of maintaining
/// duplicate deadline/poll/drain loops. It owns the [`ChildGuard`], so it *always* reaps
/// the child on every exit path. Per-fd [`DrainState`]s cap the retained bytes and drop
/// an over-cap descriptor from `poll`, which bounds CPU as well as memory.
fn drive_child(
    mut guard: ChildGuard,
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
    deadline: Duration,
    out_cap: usize,
    err_cap: usize,
) -> DriveOutcome {
    let start = Instant::now();
    let out_fd = stdout.as_raw_fd();
    let err_fd = stderr.as_raw_fd();
    if let Err(e) = proc::set_nonblocking(out_fd) {
        return DriveOutcome::Failed {
            message: format!("setting stdout non-blocking: {e}"),
        };
    }
    if let Err(e) = proc::set_nonblocking(err_fd) {
        return DriveOutcome::Failed {
            message: format!("setting stderr non-blocking: {e}"),
        };
    }

    let mut out = DrainState::new(out_fd, out_cap);
    let mut err = DrainState::new(err_fd, err_cap);

    loop {
        out.drain();
        err.drain();

        match guard.try_wait() {
            Ok(Some(status)) => {
                // Final drain: the child has closed its write ends, so a complete frame
                // (and any trailing stderr) is now visible.
                out.drain();
                err.drain();
                if out.overflow {
                    return DriveOutcome::StdoutOverflow;
                }
                return DriveOutcome::Exited {
                    status,
                    stdout: out.buf,
                    stderr: err.buf,
                };
            }
            Ok(None) => {}
            Err(e) => {
                return DriveOutcome::Failed {
                    message: format!("waiting for child: {e}"),
                };
            }
        }

        if out.overflow {
            return DriveOutcome::StdoutOverflow;
        }

        // Check the deadline *before* sleeping, and never sleep past it: `remaining` (or
        // `remaining - 1 ms` when non-zero) bounds every wait, so the loop returns at or
        // just after the deadline rather than up to a full tick late.
        let elapsed = start.elapsed();
        if elapsed >= deadline {
            return DriveOutcome::TimedOut { stderr: err.buf };
        }
        let remaining = deadline.saturating_sub(elapsed);

        let out_active = out.pollin();
        let err_active = err.pollin();
        if !out_active && !err_active {
            // Nothing more can be read (EOF/HUP, or an over-cap stderr fd), so waiting on
            // the child is the only remaining work. On the EOF fast path (both pipes
            // cleanly closed, not overflowed) a child is usually about to exit within
            // microseconds; wake on a short spin for a bounded window so a completed
            // response is not delayed by a whole 20 ms tick, then back off to the coarse
            // tick to bound wakeups for a child that lingers after closing stdio.
            let clean_eof = !out.overflow && !err.overflow;
            let step = if clean_eof && elapsed < EOF_SPIN_WINDOW {
                EOF_SPIN
            } else {
                POLL_GRANULARITY
            };
            std::thread::sleep(step.min(remaining));
            continue;
        }

        let mut fds = [
            libc::pollfd {
                fd: if out_active { out_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if err_active { err_fd } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // `poll` only wakes early; its timeout must not exceed `remaining`, or a spurious
        // wakeup plus the timeout can drift past the deadline.
        let poll_ms = remaining
            .as_millis()
            .min(POLL_GRANULARITY.as_millis())
            .max(1) as i32;
        match proc::poll(&mut fds, poll_ms) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return DriveOutcome::Failed {
                    message: format!("poll on child pipes: {e}"),
                };
            }
        }
    }
}

/// Parse `PID <n>` from the first stderr line, if present.
///
/// # Security
///
/// The value is **untrusted**: it comes from the bridge's stderr, which a compromised or
/// spoofed bridge fully controls. It is only a best-effort escalation hint for
/// [`Runner::taskkill`] and never feeds a trust decision. `0`, a negative value, or one
/// that does not fit a `u32` yields `None` (no escalation).
fn parse_pid_line(stderr: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(stderr).ok()?;
    let first = text.lines().next()?.trim();
    let rest = first.strip_prefix("PID ")?;
    // `0` is not a valid Windows PID and is a common sentinel; reject it too.
    rest.trim().parse::<u32>().ok().filter(|&pid| pid != 0)
}

/// Test-support wrapper over the bridge PID-line parser: returns the Windows PID if the
/// first stderr line matched `PID <n>`. Available only with the non-default
/// `test-support` feature.
#[cfg(feature = "test-support")]
pub fn parse_pid(stderr: &[u8]) -> Option<u32> {
    parse_pid_line(stderr)
}

/// If `response` is a probe reply, return `(uv_platform_available, api_version)`.
///
/// Test support only (available with the non-default `test-support` feature).
#[cfg(feature = "test-support")]
pub fn decode_probe(response: &RunnerResponse) -> Option<(bool, u32)> {
    match response {
        RunnerResponse::Probe {
            uv_platform_available,
            api_version,
        } => Some((*uv_platform_available, *api_version)),
        _ => None,
    }
}

/// Candidate absolute paths for a bare interop helper name, in priority order.
///
/// An already-absolute `program` is returned as the sole candidate. Otherwise the
/// `win_mnt`-derived `Windows/System32` and `Windows` directories are tried first (so a
/// custom mount root works), then the conventional `/mnt/c/WINDOWS` locations, then every
/// directory on `path_env`.
fn interop_candidates(
    program: &std::ffi::OsStr,
    win_mnt: &Path,
    path_env: Option<&std::ffi::OsStr>,
) -> Vec<PathBuf> {
    if Path::new(program).is_absolute() {
        return vec![PathBuf::from(program)];
    }
    let mut candidates = vec![
        win_mnt.join("Windows").join("System32").join(program),
        win_mnt.join("Windows").join(program),
        Path::new("/mnt/c/WINDOWS/system32").join(program),
        Path::new("/mnt/c/WINDOWS").join(program),
    ];
    if let Some(path) = path_env {
        candidates.extend(std::env::split_paths(path).map(|dir| dir.join(program)));
    }
    candidates
}

/// Resolve a bare Windows interop helper name (`cmd.exe`, `whoami.exe`, `taskkill.exe`)
/// to an absolute Linux path under `win_mnt`, the conventional `/mnt/c` locations, or
/// `$PATH`.
///
/// A bare name is not portable under `sudo`'s `secure_path` (which omits the Windows
/// mount): the kernel resolves the name against `PATH` at `execve` and returns `ENOENT`
/// before the binfmt handler can hand it to WSL. Passing an absolute path sidesteps that.
///
/// Returns the first candidate that exists as a file, or `None` if none do.
pub fn resolve_interop_program(
    program: impl AsRef<std::ffi::OsStr>,
    win_mnt: &Path,
) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH");
    interop_candidates(program.as_ref(), win_mnt, path_env.as_deref())
        .into_iter()
        .find(|candidate| candidate.is_file())
}

/// Convenience: run `whoami.exe`-style helper commands with a deadline.
///
/// Used by the CLI to capture the Windows identity (§9); exposed here so the interop
/// cwd/timeout handling is shared. `argv` are passed as an argument array (no shell).
pub struct InteropCommand;

impl InteropCommand {
    /// Run `program` with `args` in `win_mnt`, capturing stdout within `deadline`.
    ///
    /// Returns the captured [`Output`] with bounded stderr. On timeout the child is
    /// killed and reaped and [`RunnerError::Timeout`] is returned.
    pub fn run(
        program: &str,
        args: &[&str],
        win_mnt: &Path,
        deadline: Duration,
    ) -> Result<Output, RunnerError> {
        let resolved = resolve_interop_program(program, win_mnt).ok_or_else(|| {
            RunnerError::InteropHelperMissing {
                program: program.to_string(),
                win_mnt: win_mnt.to_path_buf(),
            }
        })?;
        let mut command = Command::new(&resolved);
        command
            .args(args)
            .current_dir(win_mnt)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command.spawn().map_err(|source| RunnerError::Spawn {
            path: resolved,
            source,
        })?;
        let mut guard = ChildGuard::new(child);
        let stdout = guard.child_mut().stdout.take().expect("stdout was piped");
        let stderr = guard.child_mut().stderr.take().expect("stderr was piped");
        match drive_child(
            guard,
            stdout,
            stderr,
            deadline,
            MAX_RESPONSE_BYTES,
            MAX_STDERR_BYTES,
        ) {
            DriveOutcome::Exited {
                status,
                stdout,
                stderr,
            } => Ok(Output {
                status,
                stdout,
                stderr,
            }),
            DriveOutcome::TimedOut { .. } => Err(RunnerError::Timeout {
                deadline_ms: deadline.as_millis() as u64,
                windows_pid: None,
                taskkill_attempted: false,
            }),
            DriveOutcome::StdoutOverflow => Err(RunnerError::Transport {
                message: format!("output exceeds {MAX_RESPONSE_BYTES} bytes"),
            }),
            DriveOutcome::Failed { message } => Err(RunnerError::Transport { message }),
        }
    }
}

/// Test-support hook: perform a single `write(2)` through the runner's SIGPIPE-safe path.
///
/// Exposed (`#[doc(hidden)]`) so the `sigpipe-probe` helper binary can verify that a
/// closed read end never delivers `SIGPIPE` to a `SIGPIPE=SIG_DFL` host process.
/// Available only with the non-default `test-support` feature.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_write_fd(fd: std::os::fd::RawFd, bytes: &[u8]) -> std::io::Result<usize> {
    proc::write(fd, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// A bare helper name under a stripped `PATH` (no Windows dirs) must resolve to the
    /// `win_mnt`-derived `Windows/System32` candidate, not fall through to `ENOENT`.
    #[test]
    fn resolve_interop_program_prefers_win_mnt_system32() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let system32 = root.path().join("Windows").join("System32");
        std::fs::create_dir_all(&system32).expect("mkdir System32");
        std::fs::write(system32.join("whoami.exe"), b"").expect("write fake helper");

        let candidates = interop_candidates(
            OsStr::new("whoami.exe"),
            root.path(),
            Some(OsStr::new("/usr/bin:/bin")),
        );
        let first_existing = candidates
            .into_iter()
            .find(|candidate| candidate.is_file())
            .expect("a candidate must exist");
        assert_eq!(first_existing, system32.join("whoami.exe"));
    }

    /// When no candidate exists, resolution fails rather than returning a bare name.
    #[test]
    fn resolve_interop_program_missing_returns_none() {
        let root = tempfile::TempDir::new().expect("tempdir");
        assert!(
            resolve_interop_program("definitely-not-a-helper.exe", root.path()).is_none(),
            "an unresolvable helper must return None"
        );
    }

    /// An absolute path short-circuits the search (used by the test override and by
    /// callers that already pass a Linux path such as `/bin/echo`).
    #[test]
    fn interop_candidates_absolute_is_returned_as_is() {
        let candidates = interop_candidates(OsStr::new("/bin/echo"), Path::new("/mnt/c"), None);
        assert_eq!(candidates, vec![PathBuf::from("/bin/echo")]);
    }

    /// The clear error surfaces instead of a raw `ENOENT` spawn failure.
    #[test]
    fn interop_command_missing_helper_reports_clear_error() {
        let root = tempfile::TempDir::new().expect("tempdir");
        let err = InteropCommand::run(
            "definitely-not-a-helper.exe",
            &[],
            root.path(),
            Duration::from_secs(1),
        )
        .expect_err("an unresolvable helper must fail");
        assert!(
            matches!(err, RunnerError::InteropHelperMissing { .. }),
            "{err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // L2-3 child lifecycle: the guard must kill+reap on every exit path.
    // -----------------------------------------------------------------------

    /// Dropping the guard around a live child must `SIGKILL` and reap it, so any early
    /// return that unwinds through the guard cannot leak a root-owned process.
    #[test]
    fn child_guard_kills_and_reaps_on_drop() {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let guard = ChildGuard::new(child);
        assert!(proc::process_alive(pid), "child should be running");
        drop(guard);
        assert!(
            !proc::process_alive(pid),
            "child {pid} survived guard drop (not killed/reaped)"
        );
    }

    /// A child observed via `try_wait` is marked reaped, so the guard's drop neither
    /// kills nor double-reaps it, and the process is gone.
    #[test]
    fn child_guard_try_wait_reaps_without_kill() {
        let child = Command::new("/bin/true").spawn().expect("spawn true");
        let pid = child.id();
        let mut guard = ChildGuard::new(child);
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            matches!(guard.try_wait(), Ok(Some(_))),
            "should have exited"
        );
        drop(guard);
        assert!(!proc::process_alive(pid), "child {pid} was not reaped");
    }

    // -----------------------------------------------------------------------
    // L2-1 = L9-2 bounded IO: an over-cap descriptor must not busy-drain.
    // -----------------------------------------------------------------------

    /// A child that floods stderr past `MAX_STDERR_BYTES` and then blocks must be waited
    /// out to the deadline without the drain loop spinning the calling thread.
    #[test]
    fn stderr_flood_does_not_spin() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let deadline = Duration::from_millis(400);
        // The bridge is now opened O_NOFOLLOW, so use the resolved binary rather than a
        // symlink (which the runner deliberately refuses).
        let sh = std::fs::canonicalize("/bin/sh").expect("resolve /bin/sh");
        let runner = Runner::without_interop_check(sh, dir.path())
            .args(["-c", "while :; do printf x 1>&2; done"]);

        let cpu_before = proc::thread_cpu_time();
        let start = Instant::now();
        let err = runner.probe(deadline).expect_err("must time out");
        let elapsed = start.elapsed();
        let cpu = proc::thread_cpu_time().saturating_sub(cpu_before);

        assert!(matches!(err, RunnerError::Timeout { .. }), "{err:?}");
        assert!(
            cpu < Duration::from_millis(150),
            "stderr drain spun the calling thread: cpu={cpu:?} over wall={elapsed:?}"
        );
        assert!(
            elapsed < deadline + Duration::from_secs(2),
            "timeout should fire near the deadline, took {elapsed:?}"
        );
    }

    /// The shared engine gives `InteropCommand::run` real overflow state for *both*
    /// pipes, so a stdout/stderr flood is bounded instead of a `~100%` CPU spin.
    #[test]
    fn interop_command_stderr_flood_does_not_spin() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let deadline = Duration::from_millis(400);

        let cpu_before = proc::thread_cpu_time();
        let start = Instant::now();
        let err = InteropCommand::run(
            "/bin/sh",
            &["-c", "while :; do printf x 1>&2; done"],
            dir.path(),
            deadline,
        )
        .expect_err("must time out");
        let elapsed = start.elapsed();
        let cpu = proc::thread_cpu_time().saturating_sub(cpu_before);

        assert!(matches!(err, RunnerError::Timeout { .. }), "{err:?}");
        assert!(
            cpu < Duration::from_millis(150),
            "stderr drain spun the calling thread: cpu={cpu:?} over wall={elapsed:?}"
        );
        assert!(elapsed < deadline + Duration::from_secs(2));
    }
}
