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
//!   budget. Failures are ignored.
//! * **Pre-flight.** [`RunnerError::BridgeMissing`] if the bridge path does not exist,
//!   [`RunnerError::InteropUnavailable`] if the WSL interop binfmt entry is absent or not
//!   `enabled`. Both fail fast without spawning.
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
pub const DEFAULT_PROBE_TIMEOUT_MS: u32 = 3_000;

/// Default `timeout_ms` for `enroll` (mirrors the protocol constant, plan §3).
pub const DEFAULT_ENROLL_TIMEOUT_MS: u32 = wsl_webauthn_protocol::BRIDGE_ENROLL_TIMEOUT_MS;

/// Default `timeout_ms` for `assert` (mirrors the protocol constant, plan §3).
pub const DEFAULT_ASSERT_TIMEOUT_MS: u32 = wsl_webauthn_protocol::BRIDGE_AUTH_TIMEOUT_MS;

/// Maximum bytes of the child's stderr we retain (bounded capture).
pub const MAX_STDERR_BYTES: usize = 4 * 1024;

/// `taskkill.exe` escalation budget after a Linux-side timeout.
pub const TASKKILL_BUDGET: Duration = Duration::from_secs(5);

/// Poll granularity used while waiting for the child (keeps deadline checks responsive).
const POLL_GRANULARITY: Duration = Duration::from_millis(20);

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
    /// The child process could not be spawned.
    #[error("failed to spawn bridge {path}: {source}")]
    Spawn {
        /// The bridge path.
        path: PathBuf,
        /// The underlying spawn error.
        #[source]
        source: std::io::Error,
    },
    /// The child exited non-zero (transport failure per the process contract).
    #[error("bridge exited with status {code:?}")]
    BridgeFailed {
        /// The exit code, or `None` if the child was terminated by a signal.
        code: Option<i32>,
    },
    /// Malformed framing, unexpected EOF, oversize response, or an IO failure mid-stream.
    #[error("bridge transport error: {message}")]
    Transport {
        /// Human-readable description.
        message: String,
    },
    /// The caller's deadline expired before a complete response arrived.
    #[error("bridge exceeded deadline of {deadline_ms} ms")]
    Timeout {
        /// The deadline that expired, in milliseconds.
        deadline_ms: u64,
        /// Windows PID parsed from the bridge's first stderr line, if any.
        windows_pid: Option<u32>,
        /// Whether a `taskkill.exe` escalation was attempted.
        taskkill_attempted: bool,
    },
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
/// Construct with [`Runner::new`] (or [`Runner::with_interop_path`] /
/// [`Runner::without_interop_check`] for tests) and call [`Runner::probe`],
/// [`Runner::enroll`], or [`Runner::authenticate`].
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
    pub fn without_interop_check(bridge: impl AsRef<Path>, win_mnt: impl AsRef<Path>) -> Runner {
        let mut runner = Runner::new(bridge, win_mnt);
        runner.check_interop = false;
        runner
    }

    /// Enable or disable the interop pre-flight (builder form).
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
    /// no arguments and receive their request on stdin).
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
    /// side-effect free.
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
    /// Uses [`DEFAULT_PROBE_TIMEOUT_MS`] as the bridge `timeout_ms`.
    pub fn probe(&self, deadline: Duration) -> Result<RunnerResponse, RunnerError> {
        self.run(
            Request::Probe {
                timeout_ms: DEFAULT_PROBE_TIMEOUT_MS,
            },
            deadline,
        )
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
    }

    /// Run one request/response exchange against the bridge.
    fn run(&self, request: Request, deadline: Duration) -> Result<RunnerResponse, RunnerError> {
        self.preflight()?;

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

        let mut child = Command::new(&self.bridge)
            .args(&self.args)
            .current_dir(&self.win_mnt)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| RunnerError::Spawn {
                path: self.bridge.clone(),
                source,
            })?;

        // Write the single framed request, then close stdin. 8 KiB fits comfortably in
        // the default 64 KiB pipe buffer, but we still make the write non-blocking and
        // bound it by the deadline: a bridge/child that never reads stdin must never be
        // able to hang the PAM stack past its deadline.
        {
            let stdin = child.stdin.take().expect("stdin was piped");
            if let Err(e) = self.write_frame(stdin.as_raw_fd(), &frame, deadline) {
                let status = child.try_wait().ok().flatten();
                kill_and_reap(&mut child);
                return Err(match status {
                    Some(status) if !status.success() => RunnerError::BridgeFailed {
                        code: status.code(),
                    },
                    _ => e,
                });
            }
            // `stdin` is dropped here, closing the read side of the child's pipe.
        }

        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        self.pump(&mut child, stdout, stderr, deadline)
    }

    /// Fast-fail pre-flight checks (no process is spawned if these fail).
    fn preflight(&self) -> Result<(), RunnerError> {
        if !self.bridge.exists() {
            return Err(RunnerError::BridgeMissing {
                path: self.bridge.clone(),
            });
        }
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
        Ok(())
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
    fn pump(
        &self,
        child: &mut std::process::Child,
        stdout: std::process::ChildStdout,
        stderr: std::process::ChildStderr,
        deadline: Duration,
    ) -> Result<RunnerResponse, RunnerError> {
        let start = Instant::now();
        let out_fd = stdout.as_raw_fd();
        let err_fd = stderr.as_raw_fd();
        proc::set_nonblocking(out_fd).map_err(|e| RunnerError::Transport {
            message: format!("setting stdout non-blocking: {e}"),
        })?;
        proc::set_nonblocking(err_fd).map_err(|e| RunnerError::Transport {
            message: format!("setting stderr non-blocking: {e}"),
        })?;

        let mut out_buf: Vec<u8> = Vec::new();
        let mut err_buf: Vec<u8> = Vec::new();
        let mut out_eof = false;
        let mut err_eof = false;
        let mut out_overflow = false;
        let out_cap = MAX_RESPONSE_BYTES + 4; // frame prefix + payload

        let mut fds = [
            libc::pollfd {
                fd: out_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: err_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let mut status: Option<ExitStatus> = None;
        loop {
            drain_fd(
                out_fd,
                &mut out_buf,
                &mut out_eof,
                &mut out_overflow,
                out_cap,
            );
            drain_fd(
                err_fd,
                &mut err_buf,
                &mut err_eof,
                &mut false,
                MAX_STDERR_BYTES,
            );

            if status.is_none() {
                status = child.try_wait().map_err(|e| RunnerError::Transport {
                    message: format!("waiting for bridge: {e}"),
                })?;
            }

            if out_overflow {
                kill_and_reap(child);
                return Err(RunnerError::Transport {
                    message: format!("response exceeds {MAX_RESPONSE_BYTES} bytes"),
                });
            }

            // Fast path: both pipes reached EOF, so the child has closed its stdio. Reap
            // it and finish; this avoids lingering until the deadline when a bridge exits
            // after writing its frame but `try_wait` has not yet observed the exit. The
            // reap is deadline-bounded and kills a child that closes its pipes but never
            // exits, so it can never block past the caller's deadline.
            if out_eof && err_eof {
                let budget = deadline.saturating_sub(start.elapsed());
                let status = self.reap_bounded(child, budget, deadline)?;
                return self.finish(status, &out_buf);
            }

            if let Some(status) = status.take() {
                // Final drain: the child has closed its write ends, so a complete frame
                // (and any trailing stderr) is now visible.
                drain_fd(
                    out_fd,
                    &mut out_buf,
                    &mut out_eof,
                    &mut out_overflow,
                    out_cap,
                );
                drain_fd(
                    err_fd,
                    &mut err_buf,
                    &mut err_eof,
                    &mut false,
                    MAX_STDERR_BYTES,
                );
                if out_overflow {
                    return Err(RunnerError::Transport {
                        message: format!("response exceeds {MAX_RESPONSE_BYTES} bytes"),
                    });
                }
                return self.finish(status, &out_buf);
            }

            let elapsed = start.elapsed();
            if elapsed >= deadline {
                return self.on_deadline(child, deadline, &err_buf);
            }
            let remaining = deadline.saturating_sub(elapsed);
            let poll_ms = remaining.as_millis().min(POLL_GRANULARITY.as_millis()) as i32;

            match proc::poll(&mut fds, poll_ms) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    kill_and_reap(child);
                    return Err(RunnerError::Transport {
                        message: format!("poll on bridge pipes: {e}"),
                    });
                }
            }
        }
    }

    /// Wait for an EOF'd child to exit within `budget`, killing and reaping it on overrun.
    ///
    /// Used only after both stdio pipes have reached EOF; a child that closes its pipes
    /// but stays alive must not block the caller past the deadline. `reported_deadline` is
    /// the caller-facing deadline echoed in [`RunnerError::Timeout`].
    fn reap_bounded(
        &self,
        child: &mut std::process::Child,
        budget: Duration,
        reported_deadline: Duration,
    ) -> Result<ExitStatus, RunnerError> {
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(e) => {
                    return Err(RunnerError::Transport {
                        message: format!("waiting for bridge: {e}"),
                    });
                }
            }
            if start.elapsed() >= budget {
                kill_and_reap(child);
                return Err(RunnerError::Timeout {
                    deadline_ms: reported_deadline.as_millis() as u64,
                    windows_pid: None,
                    taskkill_attempted: false,
                });
            }
            let sleep = POLL_GRANULARITY.min(budget.saturating_sub(start.elapsed()));
            std::thread::sleep(sleep);
        }
    }

    /// Interpret a fully-drained child: parse the response or map the exit status.
    fn finish(&self, status: ExitStatus, out_buf: &[u8]) -> Result<RunnerResponse, RunnerError> {
        // Non-zero exit is a transport failure even if bytes happen to parse.
        if !status.success() {
            return Err(RunnerError::BridgeFailed {
                code: status.code(),
            });
        }

        let mut cursor = std::io::Cursor::new(out_buf);
        let payload =
            read_frame(&mut cursor, MAX_RESPONSE_BYTES).map_err(|e| RunnerError::Transport {
                message: format!("reading response frame: {e}"),
            })?;
        let response: Response =
            serde_json::from_slice(&payload).map_err(|e| RunnerError::Transport {
                message: format!("parsing response JSON: {e}"),
            })?;
        Ok(runner_response(response))
    }

    /// Deadline expired: kill the shim, reap it, and best-effort cancel the Windows PID.
    fn on_deadline(
        &self,
        child: &mut std::process::Child,
        deadline: Duration,
        err_buf: &[u8],
    ) -> Result<RunnerResponse, RunnerError> {
        let windows_pid = parse_pid_line(err_buf);
        kill_and_reap(child);
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
    /// All failures are ignored: this is a backstop, not a security control.
    fn taskkill(&self, pid: u32) {
        let mut command = Command::new(&self.taskkill_program);
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
            std::thread::sleep(Duration::from_millis(20));
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
            timeout_ms: DEFAULT_ENROLL_TIMEOUT_MS,
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
            timeout_ms: DEFAULT_ASSERT_TIMEOUT_MS,
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

/// Read whatever is currently buffered on `fd` into `buf`.
///
/// Stops at `WouldBlock` (pipe drained) or EOF. Once `buf` would exceed `cap`, sets
/// `overflow` and stops accumulating — the caller then kills the child.
fn drain_fd(
    fd: std::os::fd::RawFd,
    buf: &mut Vec<u8>,
    eof: &mut bool,
    overflow: &mut bool,
    cap: usize,
) {
    let mut chunk = [0u8; 8192];
    loop {
        match proc::read(fd, &mut chunk) {
            Ok(0) => {
                *eof = true;
                return;
            }
            Ok(n) => {
                if buf.len() + n > cap {
                    *overflow = true;
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                *eof = true;
                return;
            }
        }
    }
}

/// `SIGKILL` and reap a child, ignoring errors.
fn kill_and_reap(child: &mut std::process::Child) {
    proc::kill_sigkill(child.id() as i32);
    let _ = child.kill();
    let _ = child.wait();
}

/// Parse `PID <n>` from the first stderr line, if present.
fn parse_pid_line(stderr: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(stderr).ok()?;
    let first = text.lines().next()?.trim();
    let rest = first.strip_prefix("PID ")?;
    rest.trim().parse::<u32>().ok()
}

/// Public wrapper over the bridge PID-line parser: returns the Windows PID if the first
/// stderr line matched `PID <n>`.
pub fn parse_pid(stderr: &[u8]) -> Option<u32> {
    parse_pid_line(stderr)
}

/// If `response` is a probe reply, return `(uv_platform_available, api_version)`.
pub fn decode_probe(response: &RunnerResponse) -> Option<(bool, u32)> {
    match response {
        RunnerResponse::Probe {
            uv_platform_available,
            api_version,
        } => Some((*uv_platform_available, *api_version)),
        _ => None,
    }
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
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(win_mnt)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|source| RunnerError::Spawn {
            path: PathBuf::from(program),
            source,
        })?;
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let start = Instant::now();
        let out_fd = stdout.as_raw_fd();
        let err_fd = stderr.as_raw_fd();
        proc::set_nonblocking(out_fd).map_err(|e| RunnerError::Transport {
            message: format!("setting stdout non-blocking: {e}"),
        })?;
        proc::set_nonblocking(err_fd).map_err(|e| RunnerError::Transport {
            message: format!("setting stderr non-blocking: {e}"),
        })?;
        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();
        let (mut out_eof, mut err_eof) = (false, false);
        let mut fds = [
            libc::pollfd {
                fd: out_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: err_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            drain_fd(
                out_fd,
                &mut out_buf,
                &mut out_eof,
                &mut false,
                MAX_RESPONSE_BYTES,
            );
            drain_fd(
                err_fd,
                &mut err_buf,
                &mut err_eof,
                &mut false,
                MAX_STDERR_BYTES,
            );
            if let Some(status) = child.try_wait().map_err(|e| RunnerError::Transport {
                message: format!("waiting for {program}: {e}"),
            })? {
                return Ok(Output {
                    status,
                    stdout: out_buf,
                    stderr: err_buf,
                });
            }
            let elapsed = start.elapsed();
            if elapsed >= deadline {
                kill_and_reap(&mut child);
                return Err(RunnerError::Timeout {
                    deadline_ms: deadline.as_millis() as u64,
                    windows_pid: None,
                    taskkill_attempted: false,
                });
            }
            let remaining = deadline.saturating_sub(elapsed);
            let poll_ms = remaining.as_millis().min(POLL_GRANULARITY.as_millis()) as i32;
            match proc::poll(&mut fds, poll_ms) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    kill_and_reap(&mut child);
                    return Err(RunnerError::Transport {
                        message: format!("poll on {program} pipes: {e}"),
                    });
                }
            }
        }
    }
}
