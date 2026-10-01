//! `wsl-webauthn-pam` — the operator-facing CLI (plan §9).
//!
//! Subcommands:
//!
//! * `enroll` — probe, run a Windows Hello enrollment ceremony, verify the attestation
//!   under the selected policy (including the D3 **double-enroll** quirk), capture the
//!   Windows identity, and atomically persist a credential record.
//! * `unregister` — remove exactly one user's credential record (SR-20).
//! * `probe` — report interop / Hello availability and the bridge pin.
//! * `status` — list enrolled users and the config summary.
//! * `verify` — run the verifier against an in-process synthetic attestation+assertion
//!   to prove the crypto stack works on this machine.
//! * `install` — the D6 installer (plan §10): provision the bridge, config, module and
//!   profile, migrate a legacy WSL-Hello-sudo install (D7), and offer enrollment.
//! * `uninstall` — remove one user's record (SR-20) or, with `--all`, every provisioned
//!   component (never the legacy `/etc/pam_wsl_hello`).
//!
//! # Design notes
//!
//! * **Minimal dependencies.** Argument parsing is hand-rolled (no `clap`); the only
//!   cryptography used here is for the `verify` self-test, reusing the workspace's
//!   `p256`/`ecdsa`/`sha2`/`ciborium` (all already in `Cargo.lock`).
//! * **Diagnostics go to stderr; stdout is human-readable status output only.** The
//!   Windows SID captured for audit is stored in the record but never printed.
//! * Exit codes: `0` success, `1` operational failure, `2` usage error.
//! * The `alg` field is derived from the enrolled COSE key with a tiny local CBOR
//!   reader ([`read_cose_alg`]) rather than the verifier's `#[doc(hidden)] pub mod
//!   testing` seam, so the CLI does not depend on a test-only API.
//!
//! # D3 double-enroll
//!
//! The first-ever enrollment for the pinned RP ID yields a `none`-attested credential
//! from Windows (spike-confirmed). Under Strict the verifier rejects it; the CLI runs
//! exactly one further ceremony with a **fresh** challenge and verifies that instead.
//! The first ceremony's outcome is **discarded** and can never reach the record — the
//! persisted `credential_id` always names the second credential. See
//! [`enroll_with_double_enroll`].
//!
//! # Wave C installer (plan §10)
//!
//! The `install` subcommand (plan §10) MUST, before `enroll`/PAM can work, write:
//!
//! * `/etc/wsl_webauthn/config` (TOML, `0600` root:root) with `bridge_path` (absolute),
//!   `win_mnt`, and optional `timeout_secs`;
//! * `/etc/wsl_webauthn/credentials/` (`0700` root:root);
//! * record files (`0600` root:root) — written later by `enroll`;
//! * the bridge exe to
//!   `%LOCALAPPDATA%\Programs\wsl-webauthn-pam\WSLWebAuthnBridge.exe` and pin its
//!   SHA-256 at enrollment;
//! * `pam_wsl_webauthn.so` and the `pam-config` profile **before** removing the legacy
//!   module (D7: a stale reference means a load failure and lockout).
//!
//! The implementation lives in [`installer`]; every system path is carried in an
//! [`installer::InstallPaths`] value so tests are fully tempdir-backed and never touch
//! `/etc`.
//!
//! The `probe`/`status`/`enroll` subcommands read that config via
//! `wsl_webauthn_store::Store::load_config`; until it exists, `enroll` requires an
//! explicit `--bridge`.

#![deny(unsafe_code)]

mod confparse;
mod fsutil;
mod installer;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow, bail};
use sha2::{Digest as _, Sha256};

use wsl_webauthn_protocol::{BRIDGE_ENROLL_TIMEOUT_MS, ClientDataKind, RP_ID, build_client_data};
use wsl_webauthn_runner::{EnrollParams, InteropCommand, Runner, RunnerResponse};
use wsl_webauthn_store::{
    AttestationRecord, CredentialRecord, MODE_STRICT, MODE_UNATTESTED_OPT_IN, SCHEMA_VERSION,
    Store, StoreError, WindowsIdentity,
};
use wsl_webauthn_verifier::{
    AttestationMode, AttestationPolicy, EnrollCheck, EnrollOutcome, STRICT_AAGUIDS, VerifyError,
    verify_attestation,
};

/// Default Windows mount root when neither the config nor `--win-mnt` supplies one.
const DEFAULT_WIN_MNT: &str = "/mnt/c";
/// Hard Linux deadline for a whole enrollment child process (plan §3).
const ENROLL_DEADLINE: Duration = Duration::from_secs(180);

/// Hard Linux deadline for a probe.
const PROBE_DEADLINE: Duration = Duration::from_secs(10);

/// Deadline used for the `whoami.exe` identity probes (plan §9: 5 s).
const WHOAMI_DEADLINE: Duration = Duration::from_secs(5);

/// Length of the enrollment challenge in bytes.
const CHALLENGE_BYTES: usize = 32;

/// Default COSE algorithm allow-list presented to Windows at enrollment.
const ENROLL_ALGS: [i32; 2] = [-7, -257];

/// `--help` text.
const USAGE: &str = "\
wsl-webauthn-pam — Windows Hello authentication for sudo/su on WSL

USAGE:
    wsl-webauthn-pam <COMMAND> [OPTIONS]

COMMANDS:
    enroll       Enroll a Windows Hello credential for a Linux user (root)
                   --replace             overwrite an existing credential
                   --allow-unattested    admit self/`none` attestations (opt-in, loud)
                   --user <NAME>         target user (default: SUDO_USER or current)
                   --bridge <PATH>       bridge exe path (else config, else required)
                   --win-mnt <PATH>      Windows mount root (else config, else /mnt/c)
    unregister   Remove one user's credential record (root, per-user only)
                   --user <NAME>         target user (default: SUDO_USER or current)
                   --yes, -y             skip the confirmation prompt
    probe        Report interop / Hello availability and the bridge pin
                   --bridge <PATH>       bridge exe path (else config, else required)
                   --win-mnt <PATH>      Windows mount root (else config, else /mnt/c)
    status       List enrolled users and the config summary (root for records)
                   --user <NAME>         show one user's full record
    verify       Self-test the crypto stack against a synthetic ceremony
    install      Provision the bridge, config, PAM module and profile (root)
                   --artifact-dir <DIR>   where to find the .so/.exe (else env/cwd)
                   --module-dir <DIR>     override the PAM security directory
                   --win-mnt <PATH>       override the Windows mount root
                   --allow-unattested     admit self/`none` attestation at enroll
                   --skip-enroll          do not offer enrollment at the end
                   --yes, -y              answer yes to every prompt
                   --non-interactive      never read stdin; use question defaults
    uninstall    Remove a credential or all components (root)
                   --user <NAME>         remove one user's record (default)
                   --all                 remove profile, module, config, bridge
                   --module-dir <DIR>     override the PAM security directory
                   --win-mnt <PATH>       override the Windows mount root
                   --yes, -y              skip confirmations
                   --non-interactive     never read stdin; use question defaults

GLOBAL:
    -h, --help       Print this help
    -V, --version    Print the version

EXIT CODES:
    0   success
    1   operational failure; in `status` list mode this includes one or more
        unreadable/corrupt credential records (re-run as root to read them)
    2   usage error (missing values, unknown/empty flags, misplaced flags)
";

// ---------------------------------------------------------------------------
// passwd database access
// ---------------------------------------------------------------------------

/// Minimal `libc` passwd lookups.
///
/// This is the only module permitted to contain `unsafe` (the crate is
/// `#![deny(unsafe_code)]`); the wrappers are safe and documented. `getpwnam`/`getpwuid`
/// return a pointer into a process-global static buffer that must not be retained, so
/// each wrapper copies the value it needs immediately and never returns the pointer.
///
/// **Thread safety:** these reentrant-unsafe libc functions are not safe to call
/// concurrently with other libc user/group lookups. The CLI is single-threaded and calls
/// them only during startup/enrollment, before the ceremony spawns any external process;
/// no concurrent lookup can occur. If the crate ever gains threads, switch to
/// `getpwnam_r`/`getpwuid_r`.
mod userdb {
    #![allow(unsafe_code)]

    /// Look up a uid by name. Returns `None` for an empty/NUL-containing name or an
    /// unknown account.
    pub(crate) fn uid_by_name(name: &str) -> Option<u32> {
        if name.is_empty() || name.contains('\0') {
            return None;
        }
        let cname = std::ffi::CString::new(name).ok()?;
        // SAFETY: `cname` is a valid NUL-terminated C string for the duration of the
        // call; `getpwnam` returns a pointer into a static buffer we only read.
        let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
        if pw.is_null() {
            None
        } else {
            // SAFETY: non-null, owned by libc's static buffer.
            Some(unsafe { (*pw).pw_uid })
        }
    }

    /// Look up a username by uid.
    pub(crate) fn name_by_uid(uid: u32) -> Option<String> {
        // SAFETY: `getpwuid` returns a pointer into a static buffer we only read.
        let pw = unsafe { libc::getpwuid(uid) };
        if pw.is_null() {
            return None;
        }
        // SAFETY: non-null; `pw_name` is a NUL-terminated C string.
        let name_ptr = unsafe { (*pw).pw_name };
        if name_ptr.is_null() {
            return None;
        }
        // SAFETY: valid NUL-terminated string as above; copied before any later libc call.
        unsafe { std::ffi::CStr::from_ptr(name_ptr) }
            .to_str()
            .ok()
            .map(str::to_string)
    }
}

// ---------------------------------------------------------------------------
// Exit codes + top-level error
// ---------------------------------------------------------------------------

const EXIT_OK: i32 = 0;
const EXIT_FAIL: i32 = 1;
const EXIT_USAGE: i32 = 2;

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Enroll {
        replace: bool,
        allow_unattested: bool,
        user: Option<String>,
        bridge: Option<PathBuf>,
        win_mnt: Option<PathBuf>,
    },
    Unregister {
        user: Option<String>,
        yes: bool,
    },
    Probe {
        bridge: Option<PathBuf>,
        win_mnt: Option<PathBuf>,
    },
    Status {
        user: Option<String>,
    },
    Verify,
    Install {
        allow_unattested: bool,
        skip_enroll: bool,
        non_interactive: bool,
        yes: bool,
        module_dir: Option<PathBuf>,
        win_mnt: Option<PathBuf>,
        artifact_dir: Option<PathBuf>,
    },
    Uninstall {
        user: Option<String>,
        all: bool,
        non_interactive: bool,
        yes: bool,
        module_dir: Option<PathBuf>,
        win_mnt: Option<PathBuf>,
    },
}

/// Outcome of parsing `argv` (excluding the program name).
#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Help,
    Version,
    Run(Command),
}

/// Parse the argument vector (without the program name).
///
/// Returns `Err(message)` for a usage error (the caller prints usage and exits `2`).
/// `-h`/`--help` is honored for every subcommand.
fn parse(args: &[String]) -> Result<Parsed, String> {
    let Some(first) = args.first() else {
        return Err("missing subcommand".to_string());
    };
    match first.as_str() {
        "-h" | "--help" | "help" => Ok(Parsed::Help),
        "-V" | "--version" => Ok(Parsed::Version),
        name => parse_sub(name, &args[1..]),
    }
}

/// Parse one subcommand's flags.
fn parse_sub(name: &str, args: &[String]) -> Result<Parsed, String> {
    let mut replace = false;
    let mut allow_unattested = false;
    let mut yes = false;
    let mut all = false;
    let mut skip_enroll = false;
    let mut non_interactive = false;
    let mut user: Option<String> = None;
    let mut bridge: Option<PathBuf> = None;
    let mut win_mnt: Option<PathBuf> = None;
    let mut module_dir: Option<PathBuf> = None;
    let mut artifact_dir: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--replace" => replace = true,
            "--allow-unattested" => allow_unattested = true,
            "--yes" | "-y" => yes = true,
            "--all" => all = true,
            "--skip-enroll" => skip_enroll = true,
            "--non-interactive" => non_interactive = true,
            "--user" => user = Some(take_value(args, &mut i, "--user")?.to_string()),
            "--bridge" => bridge = Some(PathBuf::from(take_value(args, &mut i, "--bridge")?)),
            "--win-mnt" => win_mnt = Some(PathBuf::from(take_value(args, &mut i, "--win-mnt")?)),
            "--module-dir" => {
                module_dir = Some(PathBuf::from(take_value(args, &mut i, "--module-dir")?));
            }
            "--artifact-dir" => {
                artifact_dir = Some(PathBuf::from(take_value(args, &mut i, "--artifact-dir")?));
            }
            // There are no positional arguments; `--` is accepted only as a trailing
            // no-op terminator, and anything after it is a usage error.
            "--" => {
                if i + 1 != args.len() {
                    return Err(format!("`{name}` accepts no positional arguments"));
                }
            }
            other => {
                // `--flag=value` inline form. An empty or unknown flag is a usage error;
                // this keeps `--user=` from silently producing an empty username.
                let Some((flag, value)) = other.split_once('=') else {
                    return Err(format!("unknown argument {other:?} for `{name}`"));
                };
                let value = require_value(flag, value)?;
                match flag {
                    "--user" => user = Some(value.to_string()),
                    "--bridge" => bridge = Some(PathBuf::from(value)),
                    "--win-mnt" => win_mnt = Some(PathBuf::from(value)),
                    "--module-dir" => module_dir = Some(PathBuf::from(value)),
                    "--artifact-dir" => artifact_dir = Some(PathBuf::from(value)),
                    _ => return Err(format!("unknown argument {other:?} for `{name}`")),
                }
            }
        }
        i += 1;
    }

    // Flag/command validation: keep every accepted flag tied to a subcommand so a
    // typo or a misplaced flag is a usage error rather than silently ignored.
    let only = |allowed: &[bool]| allowed.iter().all(|b| !b);
    let cmd = match name {
        "enroll" => Command::Enroll {
            replace,
            allow_unattested,
            user,
            bridge,
            win_mnt,
        },
        "unregister" => {
            if !only(&[replace, allow_unattested, all]) {
                return Err("`unregister` accepts only --user/--yes".to_string());
            }
            if bridge.is_some() || win_mnt.is_some() {
                return Err("`unregister` does not accept --bridge/--win-mnt".to_string());
            }
            Command::Unregister { user, yes }
        }
        "probe" => {
            if !only(&[replace, allow_unattested, yes, all]) {
                return Err("`probe` accepts only --bridge/--win-mnt".to_string());
            }
            if user.is_some() {
                return Err("`probe` does not accept --user".to_string());
            }
            Command::Probe { bridge, win_mnt }
        }
        "status" => {
            if !only(&[replace, allow_unattested, yes, all]) {
                return Err("`status` accepts only --user".to_string());
            }
            if bridge.is_some() || win_mnt.is_some() {
                return Err("`status` does not accept --bridge/--win-mnt".to_string());
            }
            Command::Status { user }
        }
        "verify" => {
            if !only(&[replace, allow_unattested, yes, all])
                || user.is_some()
                || bridge.is_some()
                || win_mnt.is_some()
            {
                return Err("`verify` takes no arguments".to_string());
            }
            Command::Verify
        }
        "install" => {
            if replace || bridge.is_some() || user.is_some() || all {
                return Err("`install` accepts only \
                     --artifact-dir/--module-dir/--win-mnt/--allow-unattested/--skip-enroll/--yes/--non-interactive"
                    .to_string());
            }
            Command::Install {
                allow_unattested,
                skip_enroll,
                non_interactive,
                yes,
                module_dir,
                win_mnt,
                artifact_dir,
            }
        }
        "uninstall" => {
            if replace
                || allow_unattested
                || skip_enroll
                || bridge.is_some()
                || artifact_dir.is_some()
            {
                return Err(
                    "`uninstall` accepts only --user/--all/--module-dir/--win-mnt/--yes/--non-interactive"
                        .to_string(),
                );
            }
            if user.is_some() && all {
                return Err("`uninstall` accepts only one of --user/--all".to_string());
            }
            Command::Uninstall {
                user,
                all,
                non_interactive,
                yes,
                module_dir,
                win_mnt,
            }
        }
        other => return Err(format!("unknown subcommand {other:?}")),
    };
    Ok(Parsed::Run(cmd))
}

/// Consume the value for a flag in the `--flag value` form.
///
/// The value must be present and must not itself look like a flag: `--user --replace`
/// is a usage error, never `user="--replace"`. Use `--flag=value` to pass a value that
/// begins with `-`.
fn take_value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, String> {
    let next = *i + 1;
    let value = args
        .get(next)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))?;
    if value.starts_with('-') {
        return Err(format!("{flag} requires a value (got flag-like {value:?})"));
    }
    *i = next;
    Ok(value)
}

/// Validate that the inline `--flag=value` form carries a non-empty value.
fn require_value<'a>(flag: &str, value: &'a str) -> Result<&'a str, String> {
    if value.is_empty() {
        return Err(format!("{flag} requires a non-empty value"));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    // Reject non-UTF-8 arguments explicitly rather than lossily converting them (the
    // bridge learned this as SEC-018): a mangled username or path must be a clean usage
    // error, never a silently altered argument.
    let mut raw: Vec<String> = Vec::new();
    for arg in std::env::args_os().skip(1) {
        match arg.into_string() {
            Ok(value) => raw.push(value),
            Err(bad) => {
                eprintln!("error: argument is not valid UTF-8: {bad:?}");
                eprintln!();
                eprint!("{USAGE}");
                return ExitCode::from(EXIT_USAGE as u8);
            }
        }
    }

    let code = match parse(&raw) {
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!();
            eprint!("{USAGE}");
            EXIT_USAGE
        }
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            EXIT_OK
        }
        Ok(Parsed::Version) => {
            println!("wsl-webauthn-pam {}", env!("CARGO_PKG_VERSION"));
            EXIT_OK
        }
        Ok(Parsed::Run(command)) => match run(command) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("error: {error:#}");
                EXIT_FAIL
            }
        },
    };
    ExitCode::from(code as u8)
}

/// Dispatch a parsed command.
fn run(command: Command) -> anyhow::Result<i32> {
    match command {
        Command::Enroll {
            replace,
            allow_unattested,
            user,
            bridge,
            win_mnt,
        } => cmd_enroll(replace, allow_unattested, user, bridge, win_mnt),
        Command::Unregister { user, yes } => cmd_unregister(user, yes),
        Command::Probe { bridge, win_mnt } => cmd_probe(bridge, win_mnt),
        Command::Status { user } => cmd_status(user),
        Command::Verify => cmd_verify(),
        Command::Install {
            allow_unattested,
            skip_enroll,
            non_interactive,
            yes,
            module_dir,
            win_mnt,
            artifact_dir,
        } => installer::cmd_install(
            installer::InstallOptions {
                allow_unattested,
                skip_enroll,
                module_dir,
                win_mnt,
                artifact_dir,
            },
            yes,
            non_interactive,
        ),
        Command::Uninstall {
            user,
            all,
            non_interactive,
            yes,
            module_dir,
            win_mnt,
        } => installer::cmd_uninstall(user, all, yes, win_mnt, module_dir, non_interactive),
    }
}

// ---------------------------------------------------------------------------
// Root / identity helpers
// ---------------------------------------------------------------------------

/// Return an error unless the effective uid is 0.
fn require_root(action: &str) -> anyhow::Result<()> {
    if wsl_webauthn_store::current_euid() != 0 {
        bail!("{action} must run as root (try: sudo wsl-webauthn-pam {action})");
    }
    Ok(())
}

/// A resolved Linux user identity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UserInfo {
    name: String,
    uid: u32,
}

/// Resolve the enrollment/removal target user.
///
/// When the process is running under `sudo`, the *invoking* (real) user is the target:
/// `SUDO_USER` is used when it names a valid local account, otherwise the real uid's
/// passwd entry. This means `sudo wsl-webauthn-pam enroll` enrolls the user who typed
/// `sudo`, not `root`.
///
/// The resolved name is validated against the store's username grammar
/// ([`wsl_webauthn_store::validate_username`]) so an exotic `--user`/`SUDO_USER` value is
/// rejected here with a clear message, before it could reach a path or produce a record
/// the PAM hot path would later refuse to load.
fn resolve_target_user(explicit: Option<String>) -> anyhow::Result<UserInfo> {
    let resolved = if let Some(name) = explicit {
        let uid = lookup_uid(&name).ok_or_else(|| anyhow!("unknown local user {name:?}"))?;
        UserInfo { name, uid }
    } else if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let name = sudo_user.trim();
        if !name.is_empty()
            && name != "root"
            && let Some(uid) = lookup_uid(name)
        {
            UserInfo {
                name: name.to_string(),
                uid,
            }
        } else {
            current_user()?
        }
    } else {
        current_user()?
    };

    wsl_webauthn_store::validate_username(&resolved.name).map_err(|_| {
        anyhow!(
            "username {:?} is not a valid Linux login name \
             (the store accepts ^[A-Za-z_][A-Za-z0-9._-]{{0,31}}$)",
            resolved.name
        )
    })?;
    Ok(resolved)
}

/// Build the [`UserInfo`] for the current real uid.
fn current_user() -> anyhow::Result<UserInfo> {
    let uid = wsl_webauthn_store::current_uid();
    let name = lookup_name(uid)
        .ok_or_else(|| anyhow!("could not resolve a username for uid {uid}; pass --user"))?;
    Ok(UserInfo { name, uid })
}

/// Look up a uid by name using `getpwnam`.
fn lookup_uid(name: &str) -> Option<u32> {
    userdb::uid_by_name(name)
}

/// Look up a username by uid using `getpwuid`.
fn lookup_name(uid: u32) -> Option<String> {
    userdb::name_by_uid(uid)
}

// ---------------------------------------------------------------------------
// Bridge / config resolution
// ---------------------------------------------------------------------------

/// A resolved bridge invocation configuration.
#[derive(Debug, Clone)]
struct BridgeConfig {
    bridge: PathBuf,
    win_mnt: PathBuf,
    /// A non-fatal error reading the on-disk config (e.g. a read-permission failure as
    /// a non-root user despite `--bridge`/`--win-mnt` being supplied). Surfaced by
    /// `probe` as a warning; `enroll` folds it into its missing-bridge error.
    config_error: Option<String>,
}

/// Resolve the bridge path and Windows mount root from flags, then the config file.
///
/// The config file is written by the installer (Wave C); until then `enroll` requires
/// the config **or** an explicit `--bridge`. `probe`/`status` degrade gracefully.
fn resolve_bridge(
    bridge_flag: Option<PathBuf>,
    win_mnt_flag: Option<PathBuf>,
) -> anyhow::Result<BridgeConfig> {
    let store = Store::system();

    // Only consult the config when a flag does not already supply the value; this keeps
    // `probe --bridge … --win-mnt …` usable as non-root (the config is root-readable).
    let mut config: Option<wsl_webauthn_store::Config> = None;
    let mut config_error: Option<String> = None;
    if bridge_flag.is_none() || win_mnt_flag.is_none() {
        match store.load_config() {
            Ok(config_value) => config = Some(config_value),
            Err(StoreError::ConfigMissing { .. }) => {}
            Err(error) => {
                config_error = Some(format!(
                    "could not read {}: {error}",
                    store.config_path().display()
                ));
            }
        }
    }

    let bridge = match bridge_flag.or_else(|| config.as_ref().map(|c| c.bridge_path.clone())) {
        Some(bridge) => bridge,
        None => {
            let detail = config_error.clone().unwrap_or_else(|| {
                format!(
                    "{} is missing (written by `install`, Wave C)",
                    store.config_path().display()
                )
            });
            bail!("no bridge executable configured: {detail} — pass --bridge <PATH>");
        }
    };

    // Absolute paths only: the runner spawns the child with `current_dir = win_mnt`, so a
    // relative bridge path would be resolved against the wrong directory. `canonicalize`
    // also normalizes `/mnt/c/...`; if the file does not exist yet we keep the path and
    // let the existence check report it with the path the user typed.
    let bridge = std::fs::canonicalize(&bridge).unwrap_or(bridge);

    let win_mnt = win_mnt_flag
        .or_else(|| config.as_ref().map(|c| c.win_mnt.clone()))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WIN_MNT));
    let win_mnt = std::fs::canonicalize(&win_mnt).unwrap_or(win_mnt);

    Ok(BridgeConfig {
        bridge,
        win_mnt,
        config_error,
    })
}

// ---------------------------------------------------------------------------
// enroll
// ---------------------------------------------------------------------------

/// `enroll [--replace] [--allow-unattested] [--user NAME] [--bridge PATH] [--win-mnt PATH]`.
fn cmd_enroll(
    replace: bool,
    allow_unattested: bool,
    user: Option<String>,
    bridge: Option<PathBuf>,
    win_mnt: Option<PathBuf>,
) -> anyhow::Result<i32> {
    require_root("enroll")?;
    let target = resolve_target_user(user)?;
    let config = resolve_bridge(bridge, win_mnt)?;

    println!(
        "Enrolling \"{}\" (uid {}) with Windows Hello",
        target.name, target.uid
    );
    println!("  bridge:  {}", config.bridge.display());
    println!("  win_mnt: {}", config.win_mnt.display());
    if allow_unattested {
        println!("  policy:  AllowUnattested (--allow-unattested)");
    } else {
        println!("  policy:  Strict");
    }

    if !config.bridge.exists() {
        bail!(
            "bridge executable not found: {} (run as root, or pass --bridge)",
            config.bridge.display()
        );
    }

    // Pin the bridge before the ceremony so the recorded hash corresponds to the exe
    // that will actually be launched.
    let bridge_sha256 = sha256_hex_file(&config.bridge)
        .with_context(|| format!("hashing bridge {}", config.bridge.display()))?;

    let runner = Runner::new(&config.bridge, &config.win_mnt);

    // 1. Probe first: a clear message is better than a mysterious ceremony failure.
    match runner.probe(PROBE_DEADLINE) {
        Ok(RunnerResponse::Probe {
            uv_platform_available,
            api_version,
        }) => {
            println!("  probe:   Windows Hello available (api_version {api_version})");
            if !uv_platform_available {
                bail!(
                    "no user-verifying platform authenticator is available; enroll Windows Hello \
                     in Windows Settings first"
                );
            }
        }
        Ok(RunnerResponse::Error(err)) => {
            bail!("probe failed: {} ({err:?})", friendly_bridge_error(err));
        }
        Ok(other) => bail!("unexpected probe response: {other:?}"),
        Err(err) => bail!("probe transport error: {err}"),
    }

    // 2. Capture the Windows identity (non-fatal).
    let identity = capture_windows_identity(&config.win_mnt);
    match &identity {
        Some(id) => println!("  windows: {}", id.account),
        None => eprintln!("warning: could not determine the Windows account (whoami.exe failed)"),
    }

    // 3. Ceremony with D3 double-enroll handling.
    let policy = if allow_unattested {
        AttestationPolicy::AllowUnattested
    } else {
        AttestationPolicy::Strict
    };
    let outcome = enroll_with_double_enroll(&runner, &target, &policy, allow_unattested)?;

    // 4. Build and persist the record.
    let enrolled_at = format_rfc3339(SystemTime::now());
    let record = build_record(
        &target,
        &outcome,
        policy,
        identity,
        &config.bridge,
        &bridge_sha256,
        &enrolled_at,
    )?;

    match Store::system().save_atomic(&record, replace) {
        Ok(()) => {}
        Err(StoreError::AlreadyExists { .. }) => {
            bail!(
                "a credential for \"{}\" already exists; pass --replace to overwrite it",
                target.name
            );
        }
        Err(error) => bail!("failed to save credential: {error}"),
    }

    let short = short_credential_id(&outcome.credential_id);
    println!();
    println!("Enrolled \"{}\" successfully.", target.name);
    println!("  format:     {}", outcome.attestation.format);
    println!("  mode:       {}", record.attestation.mode);
    println!("  aaguid:     {}", record.aaguid);
    println!("  credential: {short}");
    println!(
        "  saved:      {}",
        Store::system()
            .credentials_dir()
            .join(format!("{}.json", target.name))
            .display()
    );
    Ok(EXIT_OK)
}

/// Abstraction over the enrollment ceremony, so the double-enroll state machine can be
/// exercised with scripted responses in unit tests without a real bridge.
///
/// The production implementation ([`Runner`]) spawns the Windows bridge; the test mock
/// returns canned [`RunnerResponse`]s.
trait EnrollCeremony {
    fn run_ceremony(
        &self,
        params: EnrollParams,
        deadline: Duration,
    ) -> Result<RunnerResponse, wsl_webauthn_runner::RunnerError>;
}

impl EnrollCeremony for Runner {
    fn run_ceremony(
        &self,
        params: EnrollParams,
        deadline: Duration,
    ) -> Result<RunnerResponse, wsl_webauthn_runner::RunnerError> {
        self.enroll(params, deadline)
    }
}

/// A per-ceremony verification function (the production value is [`verify_ceremony`]).
///
/// This is a function pointer rather than a hard call so the double-enroll state
/// machine's *discard* behaviour can be exercised with a scripted verifier in tests.
type VerifyCeremony =
    fn(&CeremonyOutcome, &AttestationPolicy) -> Result<EnrollOutcome, VerifyError>;

/// Run the enrollment ceremony, implementing the D3 double-enroll quirk.
///
/// The **first-ever** enrollment for the pinned RP ID returns `fmt:"none"` from Windows
/// (spike-confirmed). Under Strict that is rejected by the verifier because of the
/// format; we then run exactly **one** second ceremony with a fresh challenge and verify
/// again. If it is still unattested we fail with a clear `--allow-unattested` hint.
/// Under `--allow-unattested` a single ceremony suffices. Exactly one retry is attempted
/// on every path, so this cannot loop.
///
/// **First-credential discard (critical).** The credential created by ceremony #1 exists
/// on the Windows side and is *never* trusted. Its [`CeremonyOutcome`] is dropped the
/// moment it is rejected (see [`enroll_with_verifier`]) and only the outcome returned by
/// [`verify_ceremony`] for ceremony #2 can reach [`build_record`]; the persisted
/// `credential_id` therefore always names the second credential.
fn enroll_with_double_enroll(
    runner: &dyn EnrollCeremony,
    target: &UserInfo,
    policy: &AttestationPolicy,
    allow_unattested: bool,
) -> anyhow::Result<EnrollOutcome> {
    enroll_with_verifier(runner, target, policy, allow_unattested, verify_ceremony)
}

/// Implementation of [`enroll_with_double_enroll`] parameterized by the verifier.
///
/// `verify` is called at most twice: once on ceremony #1's outcome and, only if that is
/// rejected with [`VerifyError::AttestationNotAllowed`], once on ceremony #2's outcome.
fn enroll_with_verifier(
    runner: &dyn EnrollCeremony,
    target: &UserInfo,
    policy: &AttestationPolicy,
    allow_unattested: bool,
    verify: VerifyCeremony,
) -> anyhow::Result<EnrollOutcome> {
    // Ceremony #1. `first` is scoped to this function and is explicitly dropped before
    // the retry: nothing derived from it can be returned or recorded.
    let first = run_ceremony(runner, target)?;
    match verify(&first, policy) {
        Ok(outcome) => return Ok(outcome),
        Err(error) if is_unattested_rejection(&error) => {
            if allow_unattested {
                // Under AllowUnattested the verifier would have accepted it; an
                // unattested rejection here means an unexpected policy mismatch.
                bail!("attestation was rejected even under --allow-unattested: {error}");
            }
            // Fall through to the single retry. `first` is discarded here.
        }
        Err(error) => return Err(anyhow!("enrollment verification failed: {error}")),
    }
    // Explicitly drop ceremony #1's outcome before running the retry. The first
    // (unattested) credential must never be trusted or persisted.
    drop(first);

    eprintln!();
    eprintln!(
        "First enrollment for this RP ID returned an unattested credential \
         (Windows Hello quirk). Retrying once with a fresh challenge…"
    );
    // Exactly one retry: there is no loop, and a transport/ceremony failure here
    // propagates immediately via `?`.
    let second = run_ceremony(runner, target)?;
    match verify(&second, policy) {
        Ok(outcome) => Ok(outcome),
        Err(error) if is_unattested_rejection(&error) => bail!(
            "both enrollment ceremonies produced an unattested credential; this machine \
             has no TPM-backed Windows Hello. Re-run with --allow-unattested to accept a \
             self/none-attested key (less strong), or enroll a Hello PIN backed by a TPM."
        ),
        Err(error) => Err(anyhow!("second enrollment failed verification: {error}")),
    }
}

/// One enrollment ceremony: mint a challenge, build clientDataJSON, run the bridge.
fn run_ceremony(runner: &dyn EnrollCeremony, target: &UserInfo) -> anyhow::Result<CeremonyOutcome> {
    let challenge = random_bytes(CHALLENGE_BYTES);
    let client_data = build_client_data(ClientDataKind::Create, &challenge)
        .context("building enrollment clientDataJSON")?;

    // User handle: the numeric uid as little-endian bytes. Stable across enrollments and
    // well within the 64-byte WebAuthn limit; documented per plan §9.
    let user_id = wsl_webauthn_protocol::b64u_encode(&target.uid.to_le_bytes());
    let params = EnrollParams::new(
        wsl_webauthn_protocol::b64u_encode(&client_data),
        user_id,
        target.name.clone(),
        format!("{} (Linux sudo)", target.name),
    )
    .with_algs(ENROLL_ALGS.to_vec())
    .with_timeout_ms(BRIDGE_ENROLL_TIMEOUT_MS);

    let response = runner
        .run_ceremony(params, ENROLL_DEADLINE)
        .map_err(|error| anyhow!("enrollment transport error: {error}"))?;

    match response {
        RunnerResponse::Enroll {
            format,
            attestation_object,
            credential_id,
        } => {
            let attestation_bytes = wsl_webauthn_protocol::b64u_decode(&attestation_object)
                .map_err(|_| anyhow!("bridge returned a non-base64url attestation_object"))?;
            let credential_bytes = wsl_webauthn_protocol::b64u_decode(&credential_id)
                .map_err(|_| anyhow!("bridge returned a non-base64url credential_id"))?;
            Ok(CeremonyOutcome {
                challenge,
                client_data,
                format,
                attestation_bytes,
                credential_bytes,
            })
        }
        RunnerResponse::Error(err) => bail!(
            "Windows Hello enrollment failed: {}",
            friendly_bridge_error(err)
        ),
        other => bail!("unexpected enroll response: {other:?}"),
    }
}

/// Inputs retained from one ceremony so it can be verified after the fact.
struct CeremonyOutcome {
    challenge: Vec<u8>,
    client_data: Vec<u8>,
    /// The bridge-reported format (informational; the verifier re-reads `fmt` itself).
    format: String,
    attestation_bytes: Vec<u8>,
    credential_bytes: Vec<u8>,
}

impl std::fmt::Debug for CeremonyOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeremonyOutcome")
            .field("format", &self.format)
            .field("attestation_len", &self.attestation_bytes.len())
            .field("credential_len", &self.credential_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Verify one ceremony outcome under `policy`.
fn verify_ceremony(
    outcome: &CeremonyOutcome,
    policy: &AttestationPolicy,
) -> Result<EnrollOutcome, VerifyError> {
    let check = EnrollCheck::new(
        &outcome.challenge,
        &outcome.attestation_bytes,
        &outcome.client_data,
        &outcome.credential_bytes,
    );
    verify_attestation(&check, policy)
}

/// Whether a verification failure is specifically the unattested-format rejection.
///
/// The verifier rejects `fmt:"none"` and `packed`-without-`x5c` under Strict with
/// [`VerifyError::AttestationNotAllowed`]; that is the D3 signal to double-enroll.
fn is_unattested_rejection(error: &VerifyError) -> bool {
    matches!(error, VerifyError::AttestationNotAllowed)
}

// ---------------------------------------------------------------------------
// Record construction
// ---------------------------------------------------------------------------

/// Build the on-disk credential record from a verified enrollment outcome.
fn build_record(
    target: &UserInfo,
    outcome: &EnrollOutcome,
    policy: AttestationPolicy,
    windows_identity: Option<WindowsIdentity>,
    bridge_path: &Path,
    bridge_sha256: &str,
    enrolled_at: &str,
) -> anyhow::Result<CredentialRecord> {
    let alg = read_cose_alg(&outcome.cose_public_key)
        .context("deriving COSE algorithm from the enrolled credential key")?;

    // `verified` records whether the chain was cryptographically verified. Under
    // AllowUnattested a verified (strict-mode) attestation is still recorded as strict;
    // self/`none` is recorded as the opt-in mode with verified=false.
    let (mode, verified) = match policy {
        AttestationPolicy::Strict => (MODE_STRICT, true),
        AttestationPolicy::AllowUnattested => match outcome.attestation.mode {
            AttestationMode::StrictVerified => (MODE_STRICT, true),
            AttestationMode::SelfAttested | AttestationMode::None => {
                (MODE_UNATTESTED_OPT_IN, false)
            }
        },
    };

    Ok(CredentialRecord {
        schema_version: SCHEMA_VERSION,
        rp_id: RP_ID.to_string(),
        origin: wsl_webauthn_protocol::ORIGIN.to_string(),
        linux_user: target.name.clone(),
        linux_uid: target.uid,
        credential_id: wsl_webauthn_protocol::b64u_encode(&outcome.credential_id),
        cose_public_key: wsl_webauthn_protocol::b64u_encode(&outcome.cose_public_key),
        alg,
        aaguid: uuid_string(&outcome.aaguid),
        attestation: AttestationRecord {
            format: outcome.attestation.format.clone(),
            mode: mode.to_string(),
            verified,
            leaf_sha256: outcome.attestation.leaf_sha256.map(|h| hex(&h)),
        },
        windows_identity,
        enrolled_at: enrolled_at.to_string(),
        sign_count: outcome.sign_count,
        bridge_path: bridge_path.display().to_string(),
        bridge_sha256: bridge_sha256.to_string(),
    })
}

/// Read the COSE `alg` label (3) from an encoded COSE_Key map.
///
/// A small local reader avoids depending on the verifier's `#[doc(hidden)]` test seam.
/// The verifier has already validated the key structure, so this only extracts a label.
fn read_cose_alg(cose_public_key: &[u8]) -> anyhow::Result<i32> {
    let value: ciborium::value::Value = ciborium::from_reader(cose_public_key)
        .map_err(|e| anyhow!("COSE key is not valid CBOR: {e}"))?;
    let map = value
        .as_map()
        .ok_or_else(|| anyhow!("COSE key is not a CBOR map"))?;
    for (key, value) in map {
        if key.as_integer() == Some(ciborium::value::Integer::from(3))
            && let Some(alg) = value.as_integer()
        {
            let alg = i64::try_from(alg).map_err(|_| anyhow!("COSE alg out of range"))?;
            return i32::try_from(alg).map_err(|_| anyhow!("COSE alg out of i32 range"));
        }
    }
    bail!("COSE key is missing the alg label")
}

/// Format a 16-byte AAGUID as a canonical lowercase hyphenated UUID.
fn uuid_string(aaguid: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (i, byte) in aaguid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// unregister
// ---------------------------------------------------------------------------

/// `unregister [--user NAME] [--yes]` — remove exactly one user's record (SR-20).
fn cmd_unregister(user: Option<String>, yes: bool) -> anyhow::Result<i32> {
    require_root("unregister")?;
    let target = resolve_target_user(user)?;
    // Share the per-user removal logic with `uninstall` (SR-20: one user at a time).
    let prompter = installer::StdPrompter {
        assume_yes: yes,
        non_interactive: false,
    };
    installer::uninstall_user(&Store::system(), &target.name, yes, &prompter)
}

// ---------------------------------------------------------------------------
// probe
// ---------------------------------------------------------------------------

/// `probe [--bridge PATH] [--win-mnt PATH]` — report interop / Hello availability.
fn cmd_probe(bridge: Option<PathBuf>, win_mnt: Option<PathBuf>) -> anyhow::Result<i32> {
    let config = resolve_bridge(bridge, win_mnt)?;
    let mut ok = true;

    println!("Bridge:  {}", config.bridge.display());
    println!("win_mnt: {}", config.win_mnt.display());
    if let Some(error) = &config.config_error {
        eprintln!("warning: {error}");
    }

    if !config.bridge.exists() {
        eprintln!(
            "error: bridge executable not found: {}",
            config.bridge.display()
        );
        return Ok(EXIT_FAIL);
    }

    // Bridge pin: if the current user has a record, report whether the pin still matches.
    if let Ok(user) = resolve_target_user(None)
        && let Ok(record) = Store::system().load(&user.name)
    {
        match sha256_hex_file(&config.bridge) {
            Ok(actual) if actual == record.bridge_sha256 => {
                println!("pin:     OK (matches the enrolled bridge)");
            }
            Ok(actual) => {
                println!(
                    "pin:     MISMATCH — enrolled {}, on-disk {}",
                    short_hash(&record.bridge_sha256),
                    short_hash(&actual)
                );
                ok = false;
            }
            Err(error) => {
                eprintln!("warning: could not hash the bridge: {error}");
            }
        }
    }

    let runner = Runner::new(&config.bridge, &config.win_mnt);
    match runner.probe(PROBE_DEADLINE) {
        Ok(RunnerResponse::Probe {
            uv_platform_available,
            api_version,
        }) => {
            println!("interop: OK");
            println!("api_version: {api_version}");
            if uv_platform_available {
                println!("Windows Hello: available");
            } else {
                println!("Windows Hello: NOT available (no user-verifying platform authenticator)");
                ok = false;
            }
        }
        Ok(RunnerResponse::Error(err)) => {
            println!("interop: OK (bridge answered)");
            println!(
                "Windows Hello: error: {} ({err:?})",
                friendly_bridge_error(err)
            );
            ok = false;
        }
        Ok(other) => {
            println!("unexpected probe response: {other:?}");
            ok = false;
        }
        Err(error) => {
            println!("interop: FAILED — {error}");
            ok = false;
        }
    }

    Ok(if ok { EXIT_OK } else { EXIT_FAIL })
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

/// `status [--user NAME]` — list enrolled users and the config summary.
fn cmd_status(user: Option<String>) -> anyhow::Result<i32> {
    status_with_store(&Store::system(), user)
}

/// Implementation of `status` against an explicit store (tempdir-backed in tests).
///
/// Both modes share one policy: an unreadable/corrupt record is an operational failure
/// (exit `1`), so a scripted `if status; then …` cannot mistake a broken store for a
/// healthy one. `--user` bails, the list mode counts and returns [`EXIT_FAIL`].
fn status_with_store(store: &Store, user: Option<String>) -> anyhow::Result<i32> {
    // Config summary (readable only as root by default).
    match store.load_config() {
        Ok(config) => {
            println!("Config ({}):", store.config_path().display());
            println!("  bridge_path:  {}", config.bridge_path.display());
            println!("  win_mnt:      {}", config.win_mnt.display());
            println!(
                "  timeout_secs: {}",
                config
                    .timeout_secs
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "(default)".to_string())
            );
        }
        Err(StoreError::ConfigMissing { .. }) => {
            println!(
                "Config: missing ({}); run `install` (Wave C)",
                store.config_path().display()
            );
        }
        Err(error) => {
            println!(
                "Config: unavailable ({error}); re-run as root to read {}",
                store.config_path().display()
            );
        }
    }
    println!();

    if let Some(name) = user {
        return cmd_status_one(store, &name);
    }

    let users = match store.list() {
        Ok(users) => users,
        Err(error) => bail!(
            "could not list credentials ({error}); re-run as root to read {}",
            store.credentials_dir().display()
        ),
    };

    if users.is_empty() {
        println!("No enrolled users.");
        return Ok(EXIT_OK);
    }

    println!("Enrolled users ({}):", users.len());
    let mut unreadable = 0usize;
    for name in &users {
        match store.load(name) {
            Ok(record) => println!("  {}", summarize_record(&record)),
            Err(error) => {
                unreadable += 1;
                println!("  {name}: UNREADABLE ({error})");
            }
        }
    }
    if unreadable > 0 {
        eprintln!(
            "error: {unreadable} of {} credential record(s) under {} are unreadable; \
             re-run as root to read them",
            users.len(),
            store.credentials_dir().display()
        );
        return Ok(EXIT_FAIL);
    }
    Ok(EXIT_OK)
}

/// Print one user's full record.
fn cmd_status_one(store: &Store, name: &str) -> anyhow::Result<i32> {
    match store.load(name) {
        Ok(record) => {
            println!("Credential for \"{}\":", record.linux_user);
            println!("  uid:         {}", record.linux_uid);
            println!("  alg:         {}", record.alg);
            println!("  aaguid:      {}", record.aaguid);
            println!(
                "  attestation: {} / {}",
                record.attestation.format, record.attestation.mode
            );
            println!("  verified:    {}", record.attestation.verified);
            println!("  enrolled_at: {}", record.enrolled_at);
            println!("  sign_count:  {}", record.sign_count);
            println!(
                "  credential:  {}",
                short_credential_id_b64(&record.credential_id)
            );
            println!("  bridge_path: {}", record.bridge_path);
            println!("  bridge_sha256: {}", short_hash(&record.bridge_sha256));
            match &record.windows_identity {
                Some(identity) if !identity.account.is_empty() => {
                    // Never print the SID: it is machine/user-identifying forensic data.
                    println!("  windows:     {}", identity.account);
                }
                _ => println!("  windows:     (unknown)"),
            }
            Ok(EXIT_OK)
        }
        Err(StoreError::NotFound { .. }) => bail!("no credential record for \"{name}\""),
        Err(error) => bail!("could not read the record for \"{name}\": {error}"),
    }
}

/// One-line summary used by the list view (account only — never the SID).
fn summarize_record(record: &CredentialRecord) -> String {
    let account = record
        .windows_identity
        .as_ref()
        .map(|i| i.account.as_str())
        .filter(|a| !a.is_empty())
        .unwrap_or("-");
    format!(
        "{} (uid {}, alg {}, {}, {}, {}, enrolled {}, win {})",
        record.linux_user,
        record.linux_uid,
        record.alg,
        record.attestation.format,
        record.attestation.mode,
        if record.attestation.verified {
            "verified"
        } else {
            "unverified"
        },
        record.enrolled_at,
        account,
    )
}

// ---------------------------------------------------------------------------
// verify (self-test)
// ---------------------------------------------------------------------------

/// `verify` — run the verifier against an in-process synthetic ceremony.
///
/// This is a living example of the verifier API and a quick "is the crypto stack sane
/// on this machine" check. It needs no Windows and no root.
fn cmd_verify() -> anyhow::Result<i32> {
    use ecdsa::signature::Signer as _;

    // A fresh ES256 credential key.
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let cose_key = p256_cose_key(&signing_key)?;

    let credential_id: Vec<u8> = vec![
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
    ];
    let aaguid = STRICT_AAGUID_SELF_TEST;

    // ---- enrollment: build a `packed` self-attestation ----
    let enroll_challenge = random_bytes(CHALLENGE_BYTES);
    let enroll_client_data = build_client_data(ClientDataKind::Create, &enroll_challenge)?;
    let enroll_auth_data = attested_auth_data(&cose_key, &credential_id, &aaguid);

    let att_to_be_signed = {
        let mut buf = enroll_auth_data.clone();
        buf.extend_from_slice(&Sha256::digest(&enroll_client_data));
        buf
    };
    let attestation_sig: p256::ecdsa::DerSignature = signing_key.sign(&att_to_be_signed);
    let attestation_object =
        packed_self_attestation(&enroll_auth_data, attestation_sig.as_bytes())?;

    let enroll_check = EnrollCheck::new(
        &enroll_challenge,
        &attestation_object,
        &enroll_client_data,
        &credential_id,
    );
    let outcome = match verify_attestation(&enroll_check, &AttestationPolicy::AllowUnattested) {
        Ok(outcome) => outcome,
        Err(error) => {
            println!("verify: FAIL (attestation): {error}");
            return Ok(EXIT_FAIL);
        }
    };
    if outcome.credential_id != credential_id {
        println!("verify: FAIL (attestation credential id mismatch)");
        return Ok(EXIT_FAIL);
    }

    // ---- assertion: sign authData || SHA-256(clientData) ----
    let assert_challenge = random_bytes(CHALLENGE_BYTES);
    let assert_client_data = build_client_data(ClientDataKind::Get, &assert_challenge)?;
    let assert_auth_data = plain_auth_data();
    let assert_signed = {
        let mut buf = assert_auth_data.clone();
        buf.extend_from_slice(&Sha256::digest(&assert_client_data));
        buf
    };
    let assertion_sig: p256::ecdsa::DerSignature = signing_key.sign(&assert_signed);

    let assertion_check = wsl_webauthn_verifier::AssertionCheck::new(
        &assert_challenge,
        &credential_id,
        &cose_key,
        &assert_client_data,
        &assert_auth_data,
        assertion_sig.as_bytes(),
    );
    if let Err(error) = wsl_webauthn_verifier::verify_assertion(&assertion_check) {
        println!("verify: FAIL (assertion): {error}");
        return Ok(EXIT_FAIL);
    }

    // ---- negative control: a tampered signature must fail ----
    let mut tampered = assertion_sig.as_bytes().to_vec();
    tampered[0] ^= 0x01;
    let tampered_check = wsl_webauthn_verifier::AssertionCheck::new(
        &assert_challenge,
        &credential_id,
        &cose_key,
        &assert_client_data,
        &assert_auth_data,
        &tampered,
    );
    if wsl_webauthn_verifier::verify_assertion(&tampered_check).is_ok() {
        println!("verify: FAIL (a tampered signature was accepted)");
        return Ok(EXIT_FAIL);
    }

    println!("verify: PASS");
    println!(
        "  attestation: {} / {:?}",
        outcome.attestation.format, outcome.attestation.mode
    );
    println!("  assertion:   verified (ES256)");
    println!("  negative control: tampered signature rejected");
    Ok(EXIT_OK)
}

/// AAGUID used by the self-test (the hardware-TPM Windows Hello AAGUID).
const STRICT_AAGUID_SELF_TEST: [u8; 16] = STRICT_AAGUIDS[1];

/// Build an uncompressed CoseKey (ES256/P-256) CBOR map for a signing key.
fn p256_cose_key(signing_key: &p256::ecdsa::SigningKey) -> anyhow::Result<Vec<u8>> {
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| anyhow!("P-256 point has no x coordinate"))?
        .to_vec();
    let y = point
        .y()
        .ok_or_else(|| anyhow!("P-256 point has no y coordinate"))?
        .to_vec();
    let map = vec![
        (
            ciborium::value::Value::from(1i64),
            ciborium::value::Value::from(2i64),
        ),
        (
            ciborium::value::Value::from(3i64),
            ciborium::value::Value::from(-7i64),
        ),
        (
            ciborium::value::Value::from(-1i64),
            ciborium::value::Value::from(1i64),
        ),
        (
            ciborium::value::Value::from(-2i64),
            ciborium::value::Value::Bytes(x),
        ),
        (
            ciborium::value::Value::from(-3i64),
            ciborium::value::Value::Bytes(y),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&ciborium::value::Value::Map(map), &mut out)
        .map_err(|e| anyhow!("encoding COSE key: {e}"))?;
    Ok(out)
}

/// Build `authenticatorData` with attested credential data (UP|UV|AT).
fn attested_auth_data(cose_key: &[u8], credential_id: &[u8], aaguid: &[u8; 16]) -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
    auth_data.push(0x01 | 0x04 | 0x40); // UP | UV | AT
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(aaguid);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(cose_key);
    auth_data
}

/// Build a bare `authenticatorData` (UP|UV, no attested data) for an assertion.
fn plain_auth_data() -> Vec<u8> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
    auth_data.push(0x01 | 0x04); // UP | UV
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data
}

/// Build a `none` attestation object (empty `attStmt`) over `auth_data`.
#[cfg(test)]
fn none_attestation(auth_data: &[u8]) -> Vec<u8> {
    use ciborium::value::Value;

    let object = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (Value::Text("attStmt".to_string()), Value::Map(vec![])),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&object, &mut out).expect("encoding a fixed CBOR value cannot fail");
    out
}

/// Build a `packed` self-attestation object (`attStmt` without `x5c`).
fn packed_self_attestation(auth_data: &[u8], signature: &[u8]) -> anyhow::Result<Vec<u8>> {
    use ciborium::value::Value;

    let att_stmt = Value::Map(vec![
        (Value::Text("alg".to_string()), Value::from(-7i64)),
        (
            Value::Text("sig".to_string()),
            Value::Bytes(signature.to_vec()),
        ),
    ]);
    let object = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("packed".to_string()),
        ),
        (Value::Text("attStmt".to_string()), att_stmt),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&object, &mut out)
        .map_err(|e| anyhow!("encoding attestation object: {e}"))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Windows identity
// ---------------------------------------------------------------------------

/// Capture `HOST\user` and the SID via `whoami.exe`. Non-fatal: `None` on failure.
fn capture_windows_identity(win_mnt: &Path) -> Option<WindowsIdentity> {
    let account_output = InteropCommand::run("whoami.exe", &[], win_mnt, WHOAMI_DEADLINE).ok()?;
    let account = String::from_utf8_lossy(&account_output.stdout)
        .trim()
        .to_string();
    if account.is_empty() {
        return None;
    }

    let sid = InteropCommand::run("whoami.exe", &["/user"], win_mnt, WHOAMI_DEADLINE)
        .ok()
        .and_then(|output| {
            let text = String::from_utf8_lossy(&output.stdout);
            text.split_whitespace()
                .find(|token| token.starts_with("S-1-"))
                .map(str::to_string)
        })
        .unwrap_or_default();

    Some(WindowsIdentity { account, sid })
}

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

/// Fill a `Vec<u8>` with OS entropy.
fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore as _;
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// SHA-256 of a file as lowercase hex.
fn sha256_hex_file(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(hex(&Sha256::digest(&bytes)))
}

/// A short, non-reversible preview of a credential id.
fn short_credential_id(bytes: &[u8]) -> String {
    short_credential_id_b64(&wsl_webauthn_protocol::b64u_encode(bytes))
}

/// A short preview of a base64url credential id (first 12 chars).
fn short_credential_id_b64(b64: &str) -> String {
    let preview: String = b64.chars().take(12).collect();
    if b64.len() > 12 {
        format!("{preview}…")
    } else {
        preview
    }
}

/// A short preview of a hex digest (first 12 chars).
fn short_hash(hex: &str) -> String {
    let preview: String = hex.chars().take(12).collect();
    if hex.len() > 12 {
        format!("{preview}…")
    } else {
        preview
    }
}

/// A user-facing message for a bridge ceremony error.
fn friendly_bridge_error(error: wsl_webauthn_protocol::BridgeError) -> &'static str {
    use wsl_webauthn_protocol::BridgeError;
    match error {
        BridgeError::NotAvailable => "no user-verifying platform authenticator is available",
        BridgeError::NotSupported => "webauthn.dll is missing or too old (Windows 10 1903+)",
        BridgeError::UserCancelled => "the user cancelled the Windows Hello prompt",
        BridgeError::Timeout => "the Windows Hello prompt timed out",
        BridgeError::Busy => "another Windows Hello operation is already in progress",
        BridgeError::InvalidParameter => "the bridge rejected the request parameters",
        BridgeError::Internal => "an internal bridge error occurred",
    }
}

/// Format a [`SystemTime`] as RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Implemented with leap-year-accurate civil-from-days arithmetic (Howard Hinnant's
/// algorithm) so the CLI needs no date crate. Sub-second precision is not required by
/// the record schema and is not emitted.
fn format_rfc3339(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert days since the Unix epoch to a (year, month, day) civil date.
///
/// Howard Hinnant's `civil_from_days`; valid for the full range of `i64` days.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // ---- argument parsing ----

    #[test]
    fn parse_no_args_is_usage_error() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn parse_help_and_version() {
        assert_eq!(parse(&args(&["--help"])).unwrap(), Parsed::Help);
        assert_eq!(parse(&args(&["-h"])).unwrap(), Parsed::Help);
        assert_eq!(parse(&args(&["--version"])).unwrap(), Parsed::Version);
    }

    #[test]
    fn parse_enroll_defaults() {
        let parsed = parse(&args(&["enroll"])).unwrap();
        assert_eq!(
            parsed,
            Parsed::Run(Command::Enroll {
                replace: false,
                allow_unattested: false,
                user: None,
                bridge: None,
                win_mnt: None,
            })
        );
    }

    #[test]
    fn parse_enroll_flags_both_forms() {
        assert_eq!(
            parse(&args(&[
                "enroll",
                "--replace",
                "--allow-unattested",
                "--user",
                "alice"
            ]))
            .unwrap(),
            Parsed::Run(Command::Enroll {
                replace: true,
                allow_unattested: true,
                user: Some("alice".into()),
                bridge: None,
                win_mnt: None,
            })
        );
        assert_eq!(
            parse(&args(&[
                "enroll",
                "--user=bob",
                "--win-mnt=/mnt/d",
                "--bridge=/x/y.exe"
            ]))
            .unwrap(),
            Parsed::Run(Command::Enroll {
                replace: false,
                allow_unattested: false,
                user: Some("bob".into()),
                bridge: Some(PathBuf::from("/x/y.exe")),
                win_mnt: Some(PathBuf::from("/mnt/d")),
            })
        );
    }

    #[test]
    fn parse_flag_missing_value_is_error() {
        assert!(parse(&args(&["enroll", "--user"])).is_err());
    }

    /// L11-6: empty and flag-like values are usage errors, not silent misparses.
    #[test]
    fn parse_rejects_empty_and_flag_like_values() {
        // Empty inline value.
        assert!(parse(&args(&["enroll", "--user="])).is_err());
        // The next token is another flag, never a value.
        assert!(parse(&args(&["enroll", "--user", "--replace"])).is_err());
        assert!(parse(&args(&["status", "--user", "-x"])).is_err());
        // The `--flag=value` form may carry a value that begins with `-`.
        assert_eq!(
            parse(&args(&["enroll", "--user=-weird"])).unwrap(),
            Parsed::Run(Command::Enroll {
                replace: false,
                allow_unattested: false,
                user: Some("-weird".into()),
                bridge: None,
                win_mnt: None,
            })
        );
    }

    /// L11-6: `--` is a trailing no-op; anything after it is a positional argument,
    /// and no subcommand accepts those.
    #[test]
    fn parse_double_dash_is_trailing_noop_only() {
        assert!(parse(&args(&["enroll", "--"])).is_ok());
        assert!(parse(&args(&["enroll", "--", "extra"])).is_err());
    }

    /// L11-6: `-y` is the documented short alias for `--yes`.
    #[test]
    fn parse_dash_y_is_yes() {
        assert_eq!(
            parse(&args(&["unregister", "-y"])).unwrap(),
            Parsed::Run(Command::Unregister {
                user: None,
                yes: true,
            })
        );
    }

    #[test]
    fn parse_unknown_flag_is_error() {
        assert!(parse(&args(&["enroll", "--nope"])).is_err());
        assert!(parse(&args(&["bogus"])).is_err());
    }

    #[test]
    fn parse_misplaced_flag_is_error() {
        // `--replace` is not valid for `unregister`.
        assert!(parse(&args(&["unregister", "--replace"])).is_err());
        // `--bridge` is not valid for `status`.
        assert!(parse(&args(&["status", "--bridge", "/x"])).is_err());
        // `--user` is not valid for `probe`.
        assert!(parse(&args(&["probe", "--user", "alice"])).is_err());
        // `verify` takes no flags.
        assert!(parse(&args(&["verify", "--yes"])).is_err());
        // `install` accepts only its documented flags.
        assert!(parse(&args(&["install", "--replace"])).is_err());
        assert!(parse(&args(&["install", "--all"])).is_err());
        assert!(parse(&args(&["install", "--user", "alice"])).is_err());
        // `uninstall` accepts only --user/--all/--module-dir/--win-mnt/--yes/--non-interactive.
        assert!(parse(&args(&["uninstall", "--bridge", "/x"])).is_err());
        assert!(parse(&args(&["uninstall", "--replace"])).is_err());
        assert!(parse(&args(&["uninstall", "--allow-unattested"])).is_err());
        // `--user` and `--all` are mutually exclusive.
        assert!(parse(&args(&["uninstall", "--user", "a", "--all"])).is_err());
    }

    #[test]
    fn parse_uninstall_and_install() {
        assert_eq!(
            parse(&args(&["install"])).unwrap(),
            Parsed::Run(Command::Install {
                allow_unattested: false,
                skip_enroll: false,
                non_interactive: false,
                yes: false,
                module_dir: None,
                win_mnt: None,
                artifact_dir: None,
            })
        );
        assert_eq!(
            parse(&args(&[
                "install",
                "--allow-unattested",
                "--skip-enroll",
                "--yes",
                "--non-interactive",
                "--module-dir=/usr/lib/x/security",
                "--win-mnt",
                "/mnt/d",
                "--artifact-dir",
                "/art",
            ]))
            .unwrap(),
            Parsed::Run(Command::Install {
                allow_unattested: true,
                skip_enroll: true,
                non_interactive: true,
                yes: true,
                module_dir: Some(PathBuf::from("/usr/lib/x/security")),
                win_mnt: Some(PathBuf::from("/mnt/d")),
                artifact_dir: Some(PathBuf::from("/art")),
            })
        );
        assert_eq!(
            parse(&args(&["uninstall", "--user", "alice"])).unwrap(),
            Parsed::Run(Command::Uninstall {
                user: Some("alice".into()),
                all: false,
                non_interactive: false,
                yes: false,
                module_dir: None,
                win_mnt: None,
            })
        );
        assert_eq!(
            parse(&args(&["uninstall", "--all", "--yes"])).unwrap(),
            Parsed::Run(Command::Uninstall {
                user: None,
                all: true,
                non_interactive: false,
                yes: true,
                module_dir: None,
                win_mnt: None,
            })
        );
    }

    #[test]
    fn parse_help_inside_subcommand() {
        assert_eq!(parse(&args(&["enroll", "--help"])).unwrap(), Parsed::Help);
    }

    // ---- bridge resolution ----

    #[test]
    fn resolve_bridge_uses_explicit_flags() {
        // With both flags present the CLI never needs the on-disk config. A nonexistent
        // bridge path is kept verbatim so `probe` can report a clear not-found error.
        let resolved = resolve_bridge(
            Some(PathBuf::from("/definitely/not/here/bridge.exe")),
            Some(PathBuf::from("/tmp")),
        )
        .unwrap();
        assert_eq!(
            resolved.bridge,
            PathBuf::from("/definitely/not/here/bridge.exe")
        );
        assert!(resolved.win_mnt.ends_with("tmp"));
    }

    // ---- user resolution ----

    #[test]
    fn resolve_target_user_explicit() {
        let root = resolve_target_user(Some("root".into())).unwrap();
        assert_eq!(root.uid, 0);
        assert_eq!(root.name, "root");
        assert!(resolve_target_user(Some("no-such-user-b2-xyz".into())).is_err());
        // A name the store grammar rejects is refused (here it also fails the passwd
        // lookup, but the guard is what makes the failure explicit and path-safe).
        assert!(resolve_target_user(Some("0root".into())).is_err());
        assert!(resolve_target_user(Some("a/b".into())).is_err());
    }

    #[test]
    fn short_previews_are_bounded() {
        assert_eq!(short_credential_id_b64("abcdefghijklmnop"), "abcdefghijkl…");
        assert_eq!(short_credential_id_b64("short"), "short");
        assert_eq!(short_hash("0123456789abcdef"), "0123456789ab…");
        assert_eq!(short_hash("abc"), "abc");
    }

    // ---- UUID / timestamp helpers ----

    #[test]
    fn uuid_formatting_matches_canonical_shape() {
        let bytes = STRICT_AAGUIDS[1];
        assert_eq!(uuid_string(&bytes), "9ddd1817-af5a-4672-a2b9-3e3dd95000a9");
        assert_eq!(
            uuid_string(&[0u8; 16]),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn rfc3339_epoch() {
        assert_eq!(format_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_known_instant() {
        // 2026-10-01T12:34:56Z
        let secs = 1_790_858_096u64;
        let time = UNIX_EPOCH + Duration::from_secs(secs);
        assert_eq!(format_rfc3339(time), "2026-10-01T12:34:56Z");
    }

    #[test]
    fn civil_from_days_handles_leap_years() {
        // 2000-02-29 is day 11016; 1900-03-01 is day -25508 (1900 is not a leap year).
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(-25_508), (1900, 3, 1));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    // ---- alg derivation ----

    #[test]
    fn read_cose_alg_extracts_label_three() {
        use ciborium::value::Value;
        let map = Value::Map(vec![
            (Value::from(1i64), Value::from(2i64)),
            (Value::from(3i64), Value::from(-7i64)),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&map, &mut bytes).unwrap();
        assert_eq!(read_cose_alg(&bytes).unwrap(), -7);
    }

    #[test]
    fn read_cose_alg_rejects_missing_label() {
        use ciborium::value::Value;
        let map = Value::Map(vec![(Value::from(1i64), Value::from(2i64))]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&map, &mut bytes).unwrap();
        assert!(read_cose_alg(&bytes).is_err());
    }

    // ---- double-enroll state machine (scripted ceremony) ----

    /// Scripted [`EnrollCeremony`] that returns a well-formed `none` attestation (or a
    /// transport error) and counts invocations.
    struct ScriptedCeremony {
        calls: std::cell::Cell<usize>,
        key: p256::ecdsa::SigningKey,
        transport_error: bool,
    }

    impl ScriptedCeremony {
        fn none_attestation() -> ScriptedCeremony {
            ScriptedCeremony {
                calls: std::cell::Cell::new(0),
                key: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
                transport_error: false,
            }
        }

        fn transport_failure() -> ScriptedCeremony {
            ScriptedCeremony {
                transport_error: true,
                ..ScriptedCeremony::none_attestation()
            }
        }
    }

    impl EnrollCeremony for ScriptedCeremony {
        fn run_ceremony(
            &self,
            _params: EnrollParams,
            _deadline: Duration,
        ) -> Result<RunnerResponse, wsl_webauthn_runner::RunnerError> {
            self.calls.set(self.calls.get() + 1);
            if self.transport_error {
                return Err(wsl_webauthn_runner::RunnerError::BridgeMissing {
                    path: PathBuf::from("/nonexistent-bridge"),
                });
            }
            // Encode the invocation number in the credential id so tests can prove that
            // the *second* ceremony's credential is the one that survives.
            let n = self.calls.get() as u8;
            let credential_id = vec![n, n, n, n];
            let cose = p256_cose_key(&self.key).unwrap();
            let auth_data = attested_auth_data(&cose, &credential_id, &STRICT_AAGUID_SELF_TEST);
            let object = none_attestation(&auth_data);
            Ok(RunnerResponse::Enroll {
                format: "none".to_string(),
                attestation_object: wsl_webauthn_protocol::b64u_encode(&object),
                credential_id: wsl_webauthn_protocol::b64u_encode(&credential_id),
            })
        }
    }

    fn test_target() -> UserInfo {
        UserInfo {
            name: "alice".to_string(),
            uid: 1000,
        }
    }

    #[test]
    fn double_enroll_single_ceremony_succeeds_under_allow_unattested() {
        let ceremony = ScriptedCeremony::none_attestation();
        let outcome = enroll_with_double_enroll(
            &ceremony,
            &test_target(),
            &AttestationPolicy::AllowUnattested,
            true,
        )
        .unwrap();
        assert_eq!(outcome.attestation.format, "none");
        assert_eq!(outcome.attestation.mode, AttestationMode::None);
        assert_eq!(ceremony.calls.get(), 1, "no retry needed under opt-in");
    }

    #[test]
    fn double_enroll_retries_exactly_once_then_fails_under_strict() {
        let ceremony = ScriptedCeremony::none_attestation();
        let error =
            enroll_with_double_enroll(&ceremony, &test_target(), &AttestationPolicy::Strict, false)
                .unwrap_err();
        assert!(
            error.to_string().contains("--allow-unattested"),
            "the failure must point at --allow-unattested: {error}"
        );
        assert_eq!(ceremony.calls.get(), 2, "exactly one retry, never a loop");
    }

    #[test]
    fn double_enroll_transport_error_propagates_without_retry() {
        let ceremony = ScriptedCeremony::transport_failure();
        let error =
            enroll_with_double_enroll(&ceremony, &test_target(), &AttestationPolicy::Strict, false)
                .unwrap_err();
        assert!(error.to_string().contains("transport"));
        assert_eq!(ceremony.calls.get(), 1, "transport errors are not retried");
    }

    thread_local! {
        static SCRIPTED_VERIFY_SEEN: std::cell::RefCell<Vec<Vec<u8>>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    /// A scripted verifier: rejects ceremony #1 with [`VerifyError::AttestationNotAllowed`]
    /// (the D3 unattested-first-enroll signal) and accepts ceremony #2, returning an
    /// outcome whose `credential_id` identifies which ceremony it came from.
    fn scripted_verify(
        outcome: &CeremonyOutcome,
        _policy: &AttestationPolicy,
    ) -> Result<EnrollOutcome, VerifyError> {
        SCRIPTED_VERIFY_SEEN.with(|seen| seen.borrow_mut().push(outcome.credential_bytes.clone()));
        if outcome.credential_bytes == [1, 1, 1, 1] {
            return Err(VerifyError::AttestationNotAllowed);
        }
        Ok(EnrollOutcome {
            credential_id: outcome.credential_bytes.clone(),
            cose_public_key: es256_cose_bytes(),
            aaguid: STRICT_AAGUIDS[1],
            sign_count: 0,
            attestation: wsl_webauthn_verifier::AttestationMetadata {
                format: "tpm".to_string(),
                mode: AttestationMode::StrictVerified,
                leaf_sha256: None,
            },
        })
    }

    /// **First-credential discard (D3, critical).** When ceremony #1 is unattested and
    /// ceremony #2 succeeds, the returned outcome must reference ceremony #2's credential
    /// id, and the verifier must have seen exactly the two distinct ceremonies.
    #[test]
    fn double_enroll_discards_the_first_ceremony_outcome() {
        SCRIPTED_VERIFY_SEEN.with(|s| s.borrow_mut().clear());
        let ceremony = ScriptedCeremony::none_attestation();
        let outcome = enroll_with_verifier(
            &ceremony,
            &test_target(),
            &AttestationPolicy::Strict,
            false,
            scripted_verify,
        )
        .unwrap();

        assert_eq!(ceremony.calls.get(), 2, "exactly two ceremonies");
        assert_eq!(
            outcome.credential_id,
            vec![2, 2, 2, 2],
            "the persisted credential must be ceremony #2's, never ceremony #1's"
        );
        let seen = SCRIPTED_VERIFY_SEEN.with(|s| s.borrow().clone());
        assert_eq!(
            seen,
            vec![vec![1, 1, 1, 1], vec![2, 2, 2, 2]],
            "verifier saw ceremony #1 then a fresh ceremony #2"
        );
    }

    /// A transport failure on the second ceremony must surface and must not trigger a
    /// third attempt (it can never silently succeed with ceremony #1's abandoned key).
    struct FailSecondCeremony {
        calls: std::cell::Cell<usize>,
        key: p256::ecdsa::SigningKey,
    }

    impl EnrollCeremony for FailSecondCeremony {
        fn run_ceremony(
            &self,
            _params: EnrollParams,
            _deadline: Duration,
        ) -> Result<RunnerResponse, wsl_webauthn_runner::RunnerError> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() == 2 {
                return Err(wsl_webauthn_runner::RunnerError::BridgeMissing {
                    path: PathBuf::from("/nonexistent-bridge"),
                });
            }
            let credential_id = vec![1u8, 1, 1, 1];
            let cose = p256_cose_key(&self.key).unwrap();
            let auth_data = attested_auth_data(&cose, &credential_id, &STRICT_AAGUID_SELF_TEST);
            let object = none_attestation(&auth_data);
            Ok(RunnerResponse::Enroll {
                format: "none".to_string(),
                attestation_object: wsl_webauthn_protocol::b64u_encode(&object),
                credential_id: wsl_webauthn_protocol::b64u_encode(&credential_id),
            })
        }
    }

    #[test]
    fn double_enroll_second_transport_error_surfaces_without_third_attempt() {
        let ceremony = FailSecondCeremony {
            calls: std::cell::Cell::new(0),
            key: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
        };
        let error =
            enroll_with_double_enroll(&ceremony, &test_target(), &AttestationPolicy::Strict, false)
                .unwrap_err();
        assert!(error.to_string().contains("transport"), "{error}");
        assert_eq!(ceremony.calls.get(), 2, "exactly one retry, never a loop");
    }

    // ---- record construction ----

    #[test]
    fn unattested_rejection_is_detected() {
        assert!(is_unattested_rejection(&VerifyError::AttestationNotAllowed));
        assert!(!is_unattested_rejection(&VerifyError::SignatureInvalid));
        assert!(!is_unattested_rejection(&VerifyError::ChallengeMismatch));
    }

    /// The record builder produces a schema-complete record from a synthetic outcome.
    #[test]
    fn build_record_maps_outcome_fields() {
        let outcome = EnrollOutcome {
            credential_id: vec![1, 2, 3, 4],
            cose_public_key: es256_cose_bytes(),
            aaguid: STRICT_AAGUIDS[0],
            sign_count: 0,
            attestation: wsl_webauthn_verifier::AttestationMetadata {
                format: "tpm".to_string(),
                mode: AttestationMode::StrictVerified,
                leaf_sha256: Some([0xab; 32]),
            },
        };
        let target = UserInfo {
            name: "alice".to_string(),
            uid: 1000,
        };
        let record = build_record(
            &target,
            &outcome,
            AttestationPolicy::Strict,
            None,
            Path::new("/mnt/c/bridge.exe"),
            "deadbeef",
            "2026-10-01T00:00:00Z",
        )
        .unwrap();

        assert_eq!(record.schema_version, 1);
        assert_eq!(record.linux_user, "alice");
        assert_eq!(record.linux_uid, 1000);
        assert_eq!(record.alg, -7);
        assert_eq!(record.aaguid, "08987058-cadc-4b81-b6e1-30de50dcbe96");
        assert_eq!(record.attestation.mode, MODE_STRICT);
        assert!(record.attestation.verified);
        assert_eq!(
            record.attestation.leaf_sha256.as_deref(),
            Some(&"ab".repeat(32)[..])
        );
        assert_eq!(record.bridge_sha256, "deadbeef");
    }

    #[test]
    fn build_record_unattested_opt_in_mode() {
        let outcome = EnrollOutcome {
            credential_id: vec![9],
            cose_public_key: es256_cose_bytes(),
            aaguid: STRICT_AAGUIDS[0],
            sign_count: 0,
            attestation: wsl_webauthn_verifier::AttestationMetadata {
                format: "none".to_string(),
                mode: AttestationMode::None,
                leaf_sha256: None,
            },
        };
        let target = UserInfo {
            name: "bob".to_string(),
            uid: 1001,
        };
        let record = build_record(
            &target,
            &outcome,
            AttestationPolicy::AllowUnattested,
            Some(WindowsIdentity {
                account: "HOST\\bob".to_string(),
                sid: "S-1-5-21-1".to_string(),
            }),
            Path::new("/bridge"),
            "00",
            "2026-10-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(record.attestation.mode, MODE_UNATTESTED_OPT_IN);
        assert!(!record.attestation.verified);
        assert!(record.attestation.leaf_sha256.is_none());
        assert_eq!(
            record.windows_identity.as_ref().unwrap().account,
            "HOST\\bob"
        );
    }

    /// Build a valid ES256 COSE key byte string for record-builder tests.
    fn es256_cose_bytes() -> Vec<u8> {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        p256_cose_key(&signing_key).unwrap()
    }

    // ---- store integration (tempdir-backed) ----

    fn tempdir_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
        // `save_atomic` requires the credentials dir to be exactly 0700 and owned by
        // the store's expected uid; `with_owner` + explicit chmod matches it.
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            dir.path().join("credentials"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let store = Store::with_owner(dir.path(), wsl_webauthn_store::current_euid());
        (dir, store)
    }

    fn sample_record(user: &str, uid: u32) -> CredentialRecord {
        let outcome = EnrollOutcome {
            credential_id: vec![7, 7, 7, 7],
            cose_public_key: es256_cose_bytes(),
            aaguid: STRICT_AAGUIDS[0],
            sign_count: 0,
            attestation: wsl_webauthn_verifier::AttestationMetadata {
                format: "packed".to_string(),
                mode: AttestationMode::StrictVerified,
                leaf_sha256: None,
            },
        };
        build_record(
            &UserInfo {
                name: user.to_string(),
                uid,
            },
            &outcome,
            AttestationPolicy::Strict,
            None,
            Path::new("/mnt/c/bridge.exe"),
            "abc123",
            "2026-10-01T00:00:00Z",
        )
        .unwrap()
    }

    #[test]
    fn store_round_trip_record() {
        let (_dir, store) = tempdir_store();
        let record = sample_record("alice", 1000);
        store.save_atomic(&record, false).unwrap();
        let loaded = store.load("alice").unwrap();
        assert_eq!(loaded, record);
    }

    #[test]
    fn store_already_exists_then_replace() {
        let (_dir, store) = tempdir_store();
        store
            .save_atomic(&sample_record("alice", 1000), false)
            .unwrap();
        assert!(matches!(
            store.save_atomic(&sample_record("alice", 1000), false),
            Err(StoreError::AlreadyExists { .. })
        ));
        store
            .save_atomic(&sample_record("alice", 1000), true)
            .unwrap();
    }

    /// L11-3: an unreadable record makes `status` list mode exit non-zero, matching the
    /// `status --user` policy, so a broken store is not mistaken for a healthy one.
    #[test]
    fn status_list_reports_unreadable_records_as_failure() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, store) = tempdir_store();
        store
            .save_atomic(&sample_record("alice", 1000), false)
            .unwrap();
        // A record whose name is a valid username but whose content is not JSON.
        let bad = store.credentials_dir().join("bob.json");
        std::fs::write(&bad, b"not a credential record").unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            status_with_store(&store, None).unwrap(),
            EXIT_FAIL,
            "an unreadable record must make list mode fail"
        );
        // `--user` bails (exit 1 via `main`) for the same bad-record state.
        assert!(status_with_store(&store, Some("bob".into())).is_err());
    }

    /// SR-20: removing one user never touches another user's record.
    #[test]
    fn unregister_removes_only_the_named_user() {
        let (_dir, store) = tempdir_store();
        store
            .save_atomic(&sample_record("alice", 1000), false)
            .unwrap();
        store
            .save_atomic(&sample_record("bob", 1001), false)
            .unwrap();

        assert!(store.remove("alice").unwrap());
        assert!(matches!(
            store.load("alice"),
            Err(StoreError::NotFound { .. })
        ));
        assert!(store.load("bob").is_ok(), "bob's record must survive");
        // Removing a missing user is a no-op, not an error.
        assert!(!store.remove("carol").unwrap());
    }

    // ---- verify self-test ----

    #[test]
    fn verify_self_test_passes() {
        assert_eq!(cmd_verify().unwrap(), EXIT_OK);
    }
}
