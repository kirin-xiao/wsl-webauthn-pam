//! The fail-closed authentication state machine (plan §8).
//!
//! [`authenticate`] holds the entire decision logic. It talks to libpam through a
//! [`PamSeam`] and to the outside world (store, bridge, verifier, entropy) through a
//! [`Deps`] trait, so it is exercised end-to-end by unit tests with fakes and can be
//! audited as one linear function.
//!
//! [`run`] adds argument parsing, panic containment, and the `pam_fail_delay`
//! request; the exported `pam_sm_*` symbols are thin wrappers over it.
//!
//! # Fail-closed rule
//!
//! There is exactly one way to return [`PAM_SUCCESS`]: a fully verified assertion.
//! Every other path returns a specific failure code from the crate root's mapping
//! table. No error is swallowed into success.

use std::path::Path;
use std::time::Duration;

use wsl_webauthn_protocol::{
    BridgeError, ClientDataKind, ORIGIN, RP_ID, b64u_decode, b64u_encode, build_client_data,
};
use wsl_webauthn_runner::{AssertParams, RunnerError, RunnerResponse};
use wsl_webauthn_store::{Config, CredentialRecord, StoreError};
use wsl_webauthn_verifier::{AssertionCheck, VerifyError, verify_assertion};

use crate::args::ModuleArgs;
use crate::bindings::{
    LOG_CRIT, LOG_ERR, LOG_INFO, LOG_NOTICE, LOG_WARNING, PAM_ABORT, PAM_AUTH_ERR,
    PAM_AUTHINFO_UNAVAIL, PAM_IGNORE, PAM_SILENT, PAM_SUCCESS, PAM_TEXT_INFO, PAM_USER_UNKNOWN,
};
use crate::logger;
use crate::seam::PamSeam;

/// Failure delay requested on every failure path (2 s; plan §3/§8, CR-14).
pub const FAIL_DELAY_USEC: u32 = 2_000_000;

/// The result of one authentication attempt.
///
/// There is no PAM-code accessor and no counter on the success arm: the PAM code is
/// the failure's `code` (or `PAM_SUCCESS` for `Success`), mapped by [`run`], and the
/// observed signature counter is only debug-logged. Keeping the counter out of the
/// type avoids a field that no consumer reads (L16-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// A verified assertion. This is the only success variant.
    Success,
    /// A failure with the PAM code to return to libpam.
    Failure {
        /// The PAM return code.
        code: i32,
        /// Human-readable reason. The audit log line built by [`failure_message`] already
        /// carries it together with the PAM code and its name.
        reason: String,
    },
}

/// Everything the state machine needs from beyond the seam.
///
/// Production wires these to [`wsl_webauthn_store::Store::system`] and
/// [`wsl_webauthn_runner::Runner`]; tests substitute deterministic fakes.
pub trait Deps {
    /// Load `/etc/wsl_webauthn/config`.
    fn load_config(&self) -> Result<Config, StoreError>;
    /// Load the credential record for `username`.
    fn load_record(&self, username: &str) -> Result<CredentialRecord, StoreError>;
    /// SHA-256 of the file at `path`, opened `O_NOFOLLOW` (no symlink following).
    ///
    /// The pin is a real integrity control, so the digest must come from a descriptor
    /// opened with the hardening flags rather than a path-following `open`.
    fn sha256_file(&self, path: &Path) -> Result<[u8; 32], String>;
    /// Whether `path` is a trustworthy bridge executable location: not a symlink, and
    /// (unless `win_mnt` itself is a WSL DrvFs mount) owned by root and not
    /// group/other-writable, with every parent up to `win_mnt` held to the same rule.
    ///
    /// DrvFs (`/mnt/c`, 9p) reports Windows-derived uid/mode that the Windows ACL does
    /// not honour, so enforcing the POSIX ownership/mode rule there would reject every
    /// legitimate bridge; on such a mount the check is reduced to "regular file, not a
    /// symlink" and the SHA-256 pin remains the integrity control. Anywhere else a
    /// user-writable directory is refused (L2-4).
    fn bridge_path_is_trusted(&self, path: &Path, win_mnt: &Path) -> Result<(), String>;
    /// Fill `dest` with cryptographically secure random bytes.
    ///
    /// Entropy exhaustion is an operational condition, not a bug: implementations
    /// report it as `Err` rather than panicking, so the state machine can map it to
    /// `PAM_AUTHINFO_UNAVAIL` instead of letting a panic classify it as `PAM_ABORT`.
    fn fill_random(&self, dest: &mut [u8]) -> Result<(), String>;
    /// Run the `assert` ceremony against the bridge under a hard deadline.
    fn authenticate(
        &self,
        bridge: &Path,
        win_mnt: &Path,
        params: AssertParams,
        deadline: Duration,
    ) -> Result<RunnerResponse, RunnerError>;
    /// Test-only panic injection point (production is a no-op).
    fn panic_probe(&self);
}

/// Build a [`Deps`] driven by the real store and runner.
#[derive(Debug, Default)]
pub struct SystemDeps;

impl SystemDeps {
    /// Construct the production dependency bundle.
    pub fn new() -> SystemDeps {
        SystemDeps
    }
}

impl Deps for SystemDeps {
    fn load_config(&self) -> Result<Config, StoreError> {
        wsl_webauthn_store::Store::system().load_config()
    }
    fn load_record(&self, username: &str) -> Result<CredentialRecord, StoreError> {
        wsl_webauthn_store::Store::system().load(username)
    }
    fn sha256_file(&self, path: &Path) -> Result<[u8; 32], String> {
        sha256_file_nofollow(path)
    }
    fn bridge_path_is_trusted(&self, path: &Path, win_mnt: &Path) -> Result<(), String> {
        bridge_path_is_trusted(path, win_mnt)
    }
    fn fill_random(&self, dest: &mut [u8]) -> Result<(), String> {
        use rand::RngCore as _;
        // `OsRng::fill_bytes` panics on entropy failure; `try_fill_bytes` propagates
        // the underlying `getrandom` error instead, which the caller maps to
        // `PAM_AUTHINFO_UNAVAIL` (service unavailable) rather than `PAM_ABORT`.
        rand::rngs::OsRng
            .try_fill_bytes(dest)
            .map_err(|e| format!("OS entropy unavailable: {e}"))
    }
    fn authenticate(
        &self,
        bridge: &Path,
        win_mnt: &Path,
        params: AssertParams,
        deadline: Duration,
    ) -> Result<RunnerResponse, RunnerError> {
        let exchange = wsl_webauthn_runner::Runner::new(bridge, win_mnt)
            .authenticate_with_diagnostics(params, deadline)?;
        // A ceremony failure arrives on a healthy transport, so the HRESULT/error line the
        // bridge writes to stderr is the only fine-grained diagnostic. Log it (bounded and
        // already escaped by the runner) under debug; the taxonomy itself is logged
        // unconditionally by the state machine below.
        if let RunnerResponse::Error(error) = &exchange.response
            && let Some(diag) = &exchange.bridge_stderr
        {
            logger::debug(&format!(
                "bridge ceremony error {}: {diag}",
                bridge_error_name(*error)
            ));
        }
        Ok(exchange.response)
    }
    fn panic_probe(&self) {}
}

/// Hash a file with SHA-256 from an `O_NOFOLLOW` descriptor, streaming so an
/// arbitrarily large bridge executable is never held in memory.
///
/// `O_NOFOLLOW` closes the "hash a symlink target, then spawn the link" gap: a symlink
/// at the configured path is refused rather than silently followed (L2-2). The runner
/// spawns by path *after* this hash, so this narrows — but does not by itself close —
/// the check-then-use window; see [`bridge_path_is_trusted`].
pub fn sha256_file_nofollow(path: &Path) -> Result<[u8; 32], String> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    /// Upper bound on the bytes this module will read from the bridge path. The real
    /// bridge is ~2 MB; a value this far above it is a sanity guard against hashing an
    /// attacker-planted huge/special file (L10-2), not a functional limit.
    const MAX_BRIDGE_BYTES: u64 = 64 * 1024 * 1024;

    let file = crate::sys::open_readonly_nofollow(path)
        .map_err(|e| format!("open {path:?} (O_NOFOLLOW): {e}"))?;
    let len = file
        .metadata()
        .map_err(|e| format!("stat {path:?}: {e}"))?
        .len();
    if len > MAX_BRIDGE_BYTES {
        return Err(format!(
            "{path:?} is {len} bytes, above the {MAX_BRIDGE_BYTES}-byte bridge sanity cap"
        ));
    }

    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("read {path:?}: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Refuse a bridge path that a non-root writer could swap.
///
/// The leaf must be a regular file that is not a symlink; outside a DrvFs mount it
/// must additionally not be group/other-writable, and every parent component below
/// `win_mnt` (the configured trust anchor, itself already pinned by the store/config)
/// must be a real directory owned by root and not group/other-writable. When `win_mnt`
/// is DrvFs the POSIX owner/mode rule is unenforceable (DrvFs synthesizes them), so
/// only the symlink/regular-file part applies and the SHA-256 pin carries the
/// integrity load.
pub fn bridge_path_is_trusted(path: &Path, win_mnt: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("bridge path {path:?} is not usable: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "bridge path {path:?} is a symlink; refusing to launch a mutable target"
        ));
    }
    if !meta.is_file() {
        return Err(format!("bridge path {path:?} is not a regular file"));
    }

    if crate::sys::is_drvfs(win_mnt) {
        return Ok(());
    }

    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "bridge executable {path:?} is group/other-writable (mode {:o}); refusing to launch",
            meta.mode() & 0o7777
        ));
    }

    // Reject a path that is not physically under win_mnt (e.g. via `..`).
    let rel = path.strip_prefix(win_mnt).map_err(|_| {
        format!("bridge path {path:?} is outside the configured win_mnt {win_mnt:?}")
    })?;
    let mut dir = win_mnt.to_path_buf();
    for component in rel.parent().unwrap_or_else(|| Path::new("")).components() {
        dir.push(component);
        let m = std::fs::symlink_metadata(&dir)
            .map_err(|e| format!("bridge parent {dir:?} is not usable: {e}"))?;
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err(format!("bridge parent {dir:?} is not a directory"));
        }
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(format!(
                "bridge parent {dir:?} is writable by group/other or not root-owned \
                 (uid {}, mode {:o}); refusing to launch",
                m.uid(),
                m.mode() & 0o7777
            ));
        }
    }
    Ok(())
}

/// Map a bridge ceremony error to a PAM code (plan §8 mapping table).
///
/// The plan is explicit: only `user_cancelled` is an authentication failure; every
/// other taxonomy entry means the underlying service could not authenticate
/// information, which is `PAM_AUTHINFO_UNAVAIL`.
fn bridge_error_code(error: BridgeError) -> i32 {
    match error {
        BridgeError::UserCancelled => PAM_AUTH_ERR,
        BridgeError::Timeout
        | BridgeError::NotAvailable
        | BridgeError::NotSupported
        | BridgeError::Busy
        | BridgeError::InvalidParameter
        | BridgeError::Internal => PAM_AUTHINFO_UNAVAIL,
    }
}

fn bridge_error_name(error: BridgeError) -> &'static str {
    match error {
        BridgeError::NotAvailable => "not_available",
        BridgeError::NotSupported => "not_supported",
        BridgeError::UserCancelled => "user_cancelled",
        BridgeError::Timeout => "timeout",
        BridgeError::Busy => "busy",
        BridgeError::InvalidParameter => "invalid_parameter",
        BridgeError::Internal => "internal",
    }
}

/// Human-readable name for a PAM return code, for audit logs.
///
/// Unknown codes still get their numeric value in [`failure_message`]; this helper only
/// names the codes the module can return.
fn pam_code_name(code: i32) -> &'static str {
    match code {
        PAM_SUCCESS => "PAM_SUCCESS",
        PAM_AUTH_ERR => "PAM_AUTH_ERR",
        PAM_AUTHINFO_UNAVAIL => "PAM_AUTHINFO_UNAVAIL",
        PAM_USER_UNKNOWN => "PAM_USER_UNKNOWN",
        PAM_IGNORE => "PAM_IGNORE",
        PAM_ABORT => "PAM_ABORT",
        _ => "PAM_UNKNOWN",
    }
}

/// The syslog severity for a failure code.
///
/// `PAM_AUTH_ERR` is the authentication-decision class: a rejected/forged assertion, a
/// malformed response, or a user cancel. `LOG_NOTICE` is the conventional severity for an
/// authentication decision (it is normal but significant, not an infra fault). A missing
/// or unknown identity is a plain `LOG_WARNING`. Every other failure (config, credential
/// store, bridge pin/transport, entropy — i.e. `PAM_AUTHINFO_UNAVAIL` and friends) is an
/// infrastructure condition and is logged at `LOG_ERR`, which is more severe so it still
/// stands out in alerting.
fn failure_severity(code: i32) -> i32 {
    match code {
        PAM_AUTH_ERR => LOG_NOTICE,
        PAM_USER_UNKNOWN => LOG_WARNING,
        _ => LOG_ERR,
    }
}

/// Format the audit-log line for a failure.
///
/// The PAM code *and* its name are always present, so an admin grepping `authpriv` can
/// tell a rejected assertion (`PAM_AUTH_ERR`) from an unavailable service
/// (`PAM_AUTHINFO_UNAVAIL`) from an unknown user (`PAM_USER_UNKNOWN`).
fn failure_message(code: i32, reason: &str) -> String {
    format!(
        "authentication failed: {}({code}): {reason}",
        pam_code_name(code)
    )
}

/// Map a `VerifyError` to a PAM code (plan §8 mapping table).
///
/// Every current variant is an authentication decision → `PAM_AUTH_ERR`; the function
/// exists so the mapping is one auditable place and every variant is table-tested
/// (L8-7). A future variant that is *not* an authentication decision (say, an
/// unsupported algorithm we choose to treat as a service condition) must be added here
/// deliberately rather than falling through an undocumented catch-all.
fn pam_code_for_verify(_error: &VerifyError) -> i32 {
    PAM_AUTH_ERR
}

/// Log and construct a failure outcome.
///
/// The returned `reason` is the raw reason; the syslog line adds the PAM code and name
/// plus the severity selected by [`failure_severity`].
fn fail(code: i32, reason: impl Into<String>) -> AuthOutcome {
    let reason = reason.into();
    logger::auth(failure_severity(code), &failure_message(code, &reason));
    AuthOutcome::Failure { code, reason }
}

/// Run the authentication state machine. May panic only through [`Deps::panic_probe`]
/// (test injection); production never panics.
pub fn authenticate<S: PamSeam, D: Deps>(
    seam: &mut S,
    deps: &D,
    flags: i32,
    args: &ModuleArgs,
) -> AuthOutcome {
    let silent = (flags & PAM_SILENT) != 0;
    // Test-only injection point just inside the guarded region.
    deps.panic_probe();

    // --- 1. Username -----------------------------------------------------
    let username = match seam.get_user_name() {
        Ok(name) if !name.is_empty() => name,
        Ok(_) => return fail(PAM_USER_UNKNOWN, "pam_get_user returned an empty name"),
        Err(e) => return fail(PAM_USER_UNKNOWN, format!("pam_get_user failed: {e:?}")),
    };
    if let Err(e) = wsl_webauthn_store::validate_username(&username) {
        return fail(PAM_USER_UNKNOWN, format!("invalid user name: {e}"));
    }

    // --- 2. Config -------------------------------------------------------
    let config = match deps.load_config() {
        Ok(c) => c,
        Err(e) => {
            return fail(
                PAM_AUTHINFO_UNAVAIL,
                format!("configuration unavailable: {e}"),
            );
        }
    };

    // --- 3. Credential record -------------------------------------------
    let record = match deps.load_record(&username) {
        Ok(r) => r,
        Err(StoreError::NotFound { .. }) => {
            return fail(PAM_USER_UNKNOWN, "no credential enrolled for user");
        }
        Err(e) => {
            // Log only the stable error *kind*: the full `Display` embeds the absolute
            // record path and therefore the username, which must not reach `authpriv`
            // syslog (L8-9). The CLI keeps the rich `Display` for operators.
            return fail(
                PAM_AUTHINFO_UNAVAIL,
                format!("credential store error: {}", e.kind_str()),
            );
        }
    };
    // Defense in depth: a record whose pinned RP/origin do not match this build can
    // never verify (the verifier checks clientData against the same constants), so
    // fail fast with an unavailable service rather than a generic auth error.
    if record.rp_id != RP_ID || record.origin != ORIGIN {
        return fail(
            PAM_AUTHINFO_UNAVAIL,
            "credential record RP ID/origin does not match this module build (re-enroll)",
        );
    }
    let credential_id = match b64u_decode(&record.credential_id) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => return fail(PAM_AUTHINFO_UNAVAIL, "credential id is empty"),
        Err(e) => {
            return fail(
                PAM_AUTHINFO_UNAVAIL,
                format!("credential id is not base64url: {e}"),
            );
        }
    };
    let cose_public_key = match b64u_decode(&record.cose_public_key) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => return fail(PAM_AUTHINFO_UNAVAIL, "COSE public key is empty"),
        Err(e) => {
            return fail(
                PAM_AUTHINFO_UNAVAIL,
                format!("COSE public key is not base64url: {e}"),
            );
        }
    };

    // --- 4. Bridge executable pin (plan D11) -----------------------------
    let bridge_path = config.bridge_path.as_path();
    if record.bridge_path != config.bridge_path.to_string_lossy() {
        logger::debug(&format!(
            "record bridge_path {:?} differs from configured {:?}",
            record.bridge_path, config.bridge_path
        ));
    }
    // The pin is always enforced (L2-4 removed the `noverifypin` argument). Before
    // hashing, refuse a path a non-root writer could swap: with the pin disabled there
    // would be no integrity control at all, and even with it the runner spawns by name
    // after this hash, so the path must be trustworthy in its own right (L2-2/L2-4).
    if let Err(e) = deps.bridge_path_is_trusted(bridge_path, &config.win_mnt) {
        return fail(
            PAM_AUTHINFO_UNAVAIL,
            format!("bridge executable path is not trusted: {e}"),
        );
    }
    let expected = match decode_hex32(&record.bridge_sha256) {
        Some(v) => v,
        None => {
            return fail(
                PAM_AUTHINFO_UNAVAIL,
                "recorded bridge_sha256 is not a 32-byte lowercase hex digest",
            );
        }
    };
    match deps.sha256_file(bridge_path) {
        Ok(actual) if actual == expected => {}
        Ok(_) => {
            return fail(
                PAM_AUTHINFO_UNAVAIL,
                format!(
                    "bridge executable {bridge_path:?} failed its SHA-256 pin check \
                     (possible tampering); refusing to launch"
                ),
            );
        }
        Err(e) => {
            return fail(
                PAM_AUTHINFO_UNAVAIL,
                format!("bridge executable {bridge_path:?} unreadable for pin check: {e}"),
            );
        }
    }

    // --- 5. Challenge + clientDataJSON -----------------------------------
    let mut challenge = [0u8; 32];
    if let Err(e) = deps.fill_random(&mut challenge) {
        // Entropy failure is an operational condition (the kernel CSPRNG is
        // unavailable), not a module bug: fail closed as "auth info unavailable"
        // rather than panicking into `PAM_ABORT`, which would tear down the PAM
        // stack for every service on the host.
        return fail(
            PAM_AUTHINFO_UNAVAIL,
            format!("could not obtain entropy for the challenge: {e}"),
        );
    }
    let client_data_json = match build_client_data(ClientDataKind::Get, &challenge) {
        Ok(bytes) => bytes,
        Err(e) => {
            return fail(
                PAM_AUTHINFO_UNAVAIL,
                format!("could not build clientDataJSON: {e}"),
            );
        }
    };

    // --- 6. Optional consent pre-prompt (SR-11) --------------------------
    // Windows Hello shows the RP ID, not RP_NAME; this conversation message is the
    // primary consent-naming mechanism. It is best-effort: a missing or failing
    // conversation never blocks authentication.
    if !silent && seam.conv_available() {
        let service = seam.get_service().unwrap_or_else(|| "?".to_string());
        let text = format!(
            "Windows Hello: authenticating '{service}' for Linux user {username} \
             \u{2014} check the Windows prompt"
        );
        if let Err(e) = seam.conv_text(PAM_TEXT_INFO, &text) {
            logger::debug(&format!("conversation info message not delivered: {e:?}"));
        }
    }

    // --- 7. Bridge ceremony ----------------------------------------------
    let deadline = Duration::from_secs(args.deadline_secs(config.timeout_secs));
    let params = AssertParams::new(
        b64u_encode(&client_data_json),
        vec![b64u_encode(&credential_id)],
    );
    logger::debug(&format!(
        "running assertion for user {username} via {bridge_path:?} (deadline {deadline:?})"
    ));
    let response = match deps.authenticate(bridge_path, &config.win_mnt, params, deadline) {
        Ok(r) => r,
        Err(e) => {
            return fail(
                PAM_AUTHINFO_UNAVAIL,
                format!("bridge transport failure: {e}"),
            );
        }
    };

    // --- 8. Response handling --------------------------------------------
    match response {
        RunnerResponse::Assert { .. } => {
            // 8a. echo consistency (ASSERTION v6 bonus).
            match response.decode_client_data_json_echo() {
                Ok(Some(echo)) => {
                    if echo != client_data_json {
                        return fail(
                            PAM_AUTH_ERR,
                            "clientDataJSON echo from bridge does not match the request",
                        );
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    return fail(PAM_AUTH_ERR, format!("malformed clientDataJSON echo: {e}"));
                }
            }
            // 8b. decode + validate the credential id.
            match response.decode_credential_id() {
                Ok(id) if id == credential_id => {}
                Ok(_) => {
                    return fail(
                        PAM_AUTH_ERR,
                        "bridge returned a different credential id than requested",
                    );
                }
                Err(e) => {
                    return fail(PAM_AUTH_ERR, format!("malformed credential id: {e}"));
                }
            }
            let authenticator_data = match response.decode_authenticator_data() {
                Ok(v) => v,
                Err(e) => return fail(PAM_AUTH_ERR, format!("malformed authenticator data: {e}")),
            };
            let signature = match response.decode_signature() {
                Ok(v) => v,
                Err(e) => return fail(PAM_AUTH_ERR, format!("malformed signature: {e}")),
            };

            // 8c. cryptographic verification.
            let check = AssertionCheck {
                expected_challenge: &challenge,
                credential_id: &credential_id,
                cose_public_key: &cose_public_key,
                client_data_json: &client_data_json,
                authenticator_data: &authenticator_data,
                signature: &signature,
                expected_sign_count: Some(record.sign_count),
            };
            match verify_assertion(&check) {
                Ok(outcome) => {
                    // The PAM module does NOT persist the counter: the record stays
                    // authoritative for enrollment-time data and the counter is
                    // advisory (Windows Hello reports zero). A follow-up may persist it.
                    logger::debug(&format!(
                        "assertion verified (observed sign_count {})",
                        outcome.sign_count
                    ));
                    logger::auth(
                        LOG_INFO,
                        &format!(
                            "authentication succeeded for user {username} (sign_count {})",
                            outcome.sign_count
                        ),
                    );
                    AuthOutcome::Success
                }
                Err(e) => fail(
                    pam_code_for_verify(&e),
                    format!("assertion verification failed: {e}"),
                ),
            }
        }
        RunnerResponse::Error(error) => {
            // Structured, always-on taxonomy line (the reason below is the human text;
            // the HRESULT/stderr diagnostic, when present, is logged at debug by the
            // SystemDeps bridge call).
            logger::debug(&format!("bridge_error={}", bridge_error_name(error)));
            let code = bridge_error_code(error);
            fail(
                code,
                format!("bridge ceremony error: {}", bridge_error_name(error)),
            )
        }
        RunnerResponse::Probe { .. } | RunnerResponse::Enroll { .. } => fail(
            PAM_AUTH_ERR,
            "bridge returned an unexpected response variant for an assertion",
        ),
    }
}

/// Parse module arguments, contain panics, and map the outcome to a PAM code.
///
/// On failure this requests `pam_fail_delay` (2 s) *before* returning.
pub fn run<S: PamSeam, D: Deps>(seam: &mut S, deps: &D, flags: i32, raw_args: &[String]) -> i32 {
    // Install the syslog-only panic hook before enclosing `authenticate` in
    // `catch_unwind` (L8-1); this also covers direct callers that skip `guarded`.
    logger::install_panic_hook();
    let args = crate::args::parse(raw_args);
    logger::set_debug(args.debug);
    logger::debug(&format!(
        "pam_sm_authenticate invoked (flags {flags:#x}, args {args:?})"
    ));

    let outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        authenticate(seam, deps, flags, &args)
    })) {
        Ok(outcome) => outcome,
        Err(_) => {
            logger::auth(
                LOG_CRIT,
                "panic while authenticating; returning PAM_ABORT (fail closed)",
            );
            return PAM_ABORT;
        }
    };

    match outcome {
        AuthOutcome::Success => PAM_SUCCESS,
        AuthOutcome::Failure { code, .. } => {
            seam.fail_delay(FAIL_DELAY_USEC);
            code
        }
    }
}

/// Decode a lowercase hex 32-byte digest.
fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// Keep `SeamError` referenced from the trait contract documentation without importing
// it into the value namespace.
#[allow(unused_imports)]
use crate::seam::SeamError as _SeamError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_error_mapping_matches_plan_table() {
        assert_eq!(bridge_error_code(BridgeError::UserCancelled), PAM_AUTH_ERR);
        for e in [
            BridgeError::Timeout,
            BridgeError::NotAvailable,
            BridgeError::NotSupported,
            BridgeError::Busy,
            BridgeError::InvalidParameter,
            BridgeError::Internal,
        ] {
            assert_eq!(bridge_error_code(e), PAM_AUTHINFO_UNAVAIL, "{e:?}");
        }
    }

    /// One of every [`VerifyError`] variant, so the mapping and reason shape are
    /// exhaustive today. A new variant forces a deliberate addition here.
    fn all_verify_errors() -> Vec<VerifyError> {
        vec![
            VerifyError::MalformedClientData { reason: "r" },
            VerifyError::ClientDataTypeMismatch,
            VerifyError::ChallengeMismatch,
            VerifyError::OriginMismatch,
            VerifyError::MalformedAuthenticatorData { reason: "r" },
            VerifyError::RpIdHashMismatch,
            VerifyError::UserPresenceRequired,
            VerifyError::UserVerificationRequired,
            VerifyError::CounterRegression {
                stored: 5,
                observed: 0,
            },
            VerifyError::MalformedAttestationObject { reason: "r" },
            VerifyError::MissingAttestationField,
            VerifyError::UnsupportedAttestationFormat {
                format: "f".to_string(),
            },
            VerifyError::InvalidAttestationStatement,
            VerifyError::AttestationNotAllowed,
            VerifyError::MalformedCoseKey { reason: "r" },
            VerifyError::CosePointNotOnCurve,
            VerifyError::CoseKeyModulusSize { bits: 1024 },
            VerifyError::CoseKeyExponentNotAllowed,
            VerifyError::UnsupportedKeyType { kty: 99 },
            VerifyError::KeyTypeAlgorithmMismatch { kty: 2, alg: -257 },
            VerifyError::UnsupportedAlgorithm { alg: -9999 },
            VerifyError::AlgorithmMismatch,
            VerifyError::EmptyCredentialId,
            VerifyError::CredentialIdMismatch,
            VerifyError::MalformedSignature { reason: "r" },
            VerifyError::SignatureInvalid,
            VerifyError::MalformedCertificate { reason: "r" },
            VerifyError::CertificateTooLarge {
                len: 9000,
                max: 8192,
            },
            VerifyError::CertificateChainEmpty,
            VerifyError::CertificateChainAnchorNotFound,
            VerifyError::CertificateChainSignatureInvalid,
            VerifyError::CertificateChainIssuerMismatch,
            VerifyError::CertificateVersionNotV3,
            VerifyError::CertificateLeafIsCa,
            VerifyError::CertificateIntermediateNotCa,
            VerifyError::CertificateMissingBasicConstraints,
            VerifyError::CertificatePathLenExceeded,
            VerifyError::CertificateSubjectOuMismatch,
            VerifyError::CertificateExpired,
            VerifyError::CertificateNotYetValid,
            VerifyError::CertificateAaguidExtensionMissing,
            VerifyError::CertificateAaguidMalformed,
            VerifyError::CertificateAaguidMismatch,
            VerifyError::AaguidNotAllowed,
            VerifyError::UnsupportedCertificateAlgorithm,
            VerifyError::TpmVersionUnsupported {
                ver: "1.0".to_string(),
            },
            VerifyError::MalformedTpmCertInfo { reason: "r" },
            VerifyError::MalformedTpmPubArea { reason: "r" },
            VerifyError::TpmCertInfoMagic,
            VerifyError::TpmCertInfoType,
            VerifyError::TpmCertInfoExtraDataMismatch,
            VerifyError::TpmCertInfoNameMismatch,
            VerifyError::TpmNameAlgUnsupported { name_alg: 0x000b },
            VerifyError::TpmPubAreaKeyMismatch,
            VerifyError::TpmPubAreaKeyBitsMismatch {
                declared: 2048,
                actual: 1024,
            },
            VerifyError::TpmAlgorithmUnsupported { alg: -9999 },
            VerifyError::TpmAikSubjectNotEmpty,
            VerifyError::TpmAikEkuMissing,
            VerifyError::TpmAikKeyUsageForbidsSignature,
            VerifyError::Internal { reason: "r" },
            VerifyError::InputTooLarge {
                field: "signature",
                len: 2048,
                max: 1024,
            },
        ]
    }

    /// L8-7: every `VerifyError` maps to `PAM_AUTH_ERR`, and the call-site reason and
    /// audit line carry both the event label and the error's own display text.
    #[test]
    fn every_verify_error_maps_to_pam_auth_err_with_a_stable_reason() {
        let errors = all_verify_errors();
        // A guard against silently dropping variants from the fixture.
        assert!(errors.len() >= 59, "expected the full variant set");
        for e in errors {
            assert_eq!(pam_code_for_verify(&e), PAM_AUTH_ERR, "{e:?}");

            // The reason shape the state machine emits for a verify failure.
            let reason = format!("assertion verification failed: {e}");
            assert!(
                reason.starts_with("assertion verification failed: "),
                "{reason}"
            );
            // The syslog line names the code and includes the error's display text.
            let msg = failure_message(pam_code_for_verify(&e), &reason);
            assert!(msg.contains("PAM_AUTH_ERR"), "{msg}");
            assert!(msg.contains(&e.to_string()), "{msg}");
        }
    }

    /// L10-2: the bridge hasher streams (never `fs::read`-ing the whole executable) and
    /// returns a digest identical to a one-shot hash of the same bytes.
    #[test]
    fn sha256_file_nofollow_streams_and_matches_a_known_digest() {
        use std::io::Write as _;
        // Kept small: the process temp dir can be a tiny tmpfs in constrained CI. The
        // behaviour under test is digest correctness and O_NOFOLLOW, not file size.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("bridge.exe");
        let bytes = vec![0x5au8; 8 * 1024];
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(&bytes))
            .expect("write");
        let expected: [u8; 32] = {
            use sha2::{Digest as _, Sha256};
            let mut out = [0u8; 32];
            out.copy_from_slice(&Sha256::digest(&bytes));
            out
        };
        assert_eq!(sha256_file_nofollow(&path).unwrap(), expected);
        // A symlink at the path is refused rather than followed.
        let link = dir.path().join("link.exe");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(sha256_file_nofollow(&link).is_err());
    }

    #[test]
    fn hex_decode_round_trip() {
        let digest = [0xabu8; 32];
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(decode_hex32(&hex), Some(digest));
        assert_eq!(decode_hex32(&hex.to_uppercase()), Some(digest));
        assert_eq!(decode_hex32("short"), None);
        assert_eq!(decode_hex32(&"z".repeat(64)), None);
    }

    /// `pam_code_name` must name the codes the module returns and stay honest for the
    /// rest.
    #[test]
    fn pam_code_names_are_stable() {
        assert_eq!(pam_code_name(PAM_SUCCESS), "PAM_SUCCESS");
        assert_eq!(pam_code_name(PAM_AUTH_ERR), "PAM_AUTH_ERR");
        assert_eq!(pam_code_name(PAM_AUTHINFO_UNAVAIL), "PAM_AUTHINFO_UNAVAIL");
        assert_eq!(pam_code_name(PAM_USER_UNKNOWN), "PAM_USER_UNKNOWN");
        assert_eq!(pam_code_name(PAM_ABORT), "PAM_ABORT");
        assert_eq!(pam_code_name(-1234), "PAM_UNKNOWN");
    }

    /// The audit line must carry both the symbolic name and the numeric code for every
    /// representative failure class. The logger itself writes straight to `syslog` and
    /// is not injectable, so this exercises the formatting helper directly; the wiring
    /// from `fail` to `failure_message` is a one-line call.
    #[test]
    fn failure_message_carries_pam_code_and_name() {
        for (code, name) in [
            (PAM_USER_UNKNOWN, "PAM_USER_UNKNOWN"),
            (PAM_AUTHINFO_UNAVAIL, "PAM_AUTHINFO_UNAVAIL"),
            (PAM_AUTH_ERR, "PAM_AUTH_ERR"),
        ] {
            let msg = failure_message(code, "representative reason");
            assert!(msg.contains(name), "missing name in {msg:?}");
            assert!(
                msg.contains(&code.to_string()),
                "missing numeric code in {msg:?}"
            );
            assert!(
                msg.contains("representative reason"),
                "missing reason in {msg:?}"
            );
            assert!(
                msg.starts_with("authentication failed:"),
                "the event name must lead the line: {msg:?}"
            );
        }
        // Distinct classes must render distinct lines.
        let unknown = failure_message(PAM_USER_UNKNOWN, "r");
        let unavail = failure_message(PAM_AUTHINFO_UNAVAIL, "r");
        let auth = failure_message(PAM_AUTH_ERR, "r");
        assert_ne!(unknown, unavail);
        assert_ne!(unavail, auth);
    }

    /// Severity alignment: a rejected assertion is an attack signal (`LOG_NOTICE`), an
    /// unknown identity is `LOG_WARNING`, and infrastructure unavailability is
    /// `LOG_ERR`.
    #[test]
    fn failure_severity_separates_attack_from_infrastructure() {
        assert_eq!(failure_severity(PAM_AUTH_ERR), LOG_NOTICE);
        assert_eq!(failure_severity(PAM_USER_UNKNOWN), LOG_WARNING);
        assert_eq!(failure_severity(PAM_AUTHINFO_UNAVAIL), LOG_ERR);
        assert_eq!(failure_severity(PAM_ABORT), LOG_ERR);
    }
}
