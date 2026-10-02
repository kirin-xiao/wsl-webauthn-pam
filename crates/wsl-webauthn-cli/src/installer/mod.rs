//! The `install` / `uninstall` implementation.
//!
//! This module is the **only** place that writes system paths. It is written as pure
//! Rust (no shell) and every mutation goes through [`crate::fsutil`], which refuses
//! symlinks and installs files atomically (temp file in the same directory +
//! `rename(2)`).
//!
//! # Testability seam: [`InstallPaths`]
//!
//! Every system path the installer touches (`/etc/wsl_webauthn`, `/etc/pam.d`,
//! `/usr/share/pam-configs`, the module search roots, even the expected owner uid) is
//! carried in [`InstallPaths`]. Production uses [`InstallPaths::system`]; tests build
//! a fully tempdir-backed value so **no test ever touches `/etc`**.
//!
//! # Injection seams
//!
//! Four small traits keep the logic unit-testable:
//! * [`InteropRunner`] — runs Windows helper programs (`cmd.exe`, `whoami.exe`) through
//!   `wsl-webauthn-runner`'s [`wsl_webauthn_runner::InteropCommand`].
//! * [`CommandRunner`] — runs Linux helpers (`pam-auth-update`) with an argument array.
//! * [`Prompter`] — asks the operator yes/no questions.
//! * [`Enroller`] — runs the in-process enrollment offer.
//!
//! # Install order (lockout safety)
//!
//! 1. Provision the Windows bridge exe (needed before enrollment can pin it).
//! 2. Write `/etc/wsl_webauthn/config` (`0600`) and `credentials/` (`0700`).
//! 3. Install the CLI itself to `/usr/local/bin`, then the new `pam_wsl_webauthn.so` and
//!    the `pam-configs` profile, then **verify** the module/profile. The rollback is
//!    **committed** here.
//! 4. Only then offer legacy cleanup: rewrite `/etc/pam.d` references *before*
//!    removing the old `.so`, `pam-auth-update --remove wsl-hello`, remove the old
//!    module/config dirs. The legacy PEM is **never** imported.
//! 5. Offer to set up Windows Hello as a **single** action: enroll the invoking user and,
//!    only once a credential is verified, enable the profile
//!    (`pam-auth-update --enable wsl-webauthn`). A failure anywhere in setup leaves the
//!    profile **disabled** and prints the exact recovery commands; lockout guidance is
//!    printed only on the not-enabled paths. `install` never enables before a credential
//!    exists, and never before the fail-safe `[success=end default=ignore]` control is in
//!    place.
//!
//! Any step *up to and including verification* that fails rolls back exactly what *this
//! run* wrote: new files and directories are removed and any file this run *overwrote*
//! is restored from a pre-write snapshot (so an upgrade/re-install failure cannot delete
//! a working module/config). Nothing after verification is rolled back: committing before
//! migration means a failure can never remove the module/profile or un-rewrite a
//! `/etc/pam.d` file back into a stale `pam_wsl_hello` reference.

use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow, bail};

use wsl_webauthn_store::{CONFIG_MODE, Config, Store};

use crate::confparse;
use crate::fsutil;
// Shared CLI constants (single definitions in the crate root, `main.rs`).
use crate::{DEFAULT_WIN_MNT, EXIT_FAIL, EXIT_OK, WHOAMI_DEADLINE};

/// The `pam-auth-update` profile text, embedded from the repository's single source of
/// truth (`pam-config` at the workspace root). This path is relative to this file
/// (`crates/wsl-webauthn-cli/src/installer/mod.rs`) and is asserted byte-for-byte
/// against the file on disk by a test, so the two can never drift.
pub(crate) const PROFILE_TEXT: &str = include_str!("../../../../pam-config");

/// Name of the `pam-configs` profile.
pub(crate) const PROFILE_NAME: &str = "wsl-webauthn";
/// Name of the legacy `pam-configs` profile (WSL-Hello-sudo).
pub(crate) const LEGACY_PROFILE_NAME: &str = "wsl-hello";
/// Our PAM module file name.
pub(crate) const MODULE_NAME: &str = "pam_wsl_webauthn.so";
/// The legacy module file name we detect and offer to remove.
pub(crate) const LEGACY_MODULE_NAME: &str = "pam_wsl_hello.so";
/// The legacy module *stem*, used for `/etc/pam.d` text replacement.
pub(crate) const LEGACY_MODULE_STEM: &[u8] = b"pam_wsl_hello";
/// The new module *stem*.
pub(crate) const MODULE_STEM: &[u8] = b"pam_wsl_webauthn";
/// Windows bridge executable name.
pub(crate) const BRIDGE_EXE: &str = "WSLWebAuthnBridge.exe";
/// Sub-path under `%LOCALAPPDATA%` where the bridge is installed.
pub(crate) const WIN_BRIDGE_SUBPATH: &[&str] = &["Programs", "wsl-webauthn-pam"];
/// Our own CLI binary name, installed to [`InstallPaths::bin_dir`] by `install`.
pub(crate) const CLI_NAME: &str = "wsl-webauthn-pam";
/// Mode of the installed CLI (`root:root`, executable).
pub(crate) const CLI_MODE: u32 = 0o755;

/// Mode of the installed module and profile (`root:root`).
pub(crate) const MODULE_MODE: u32 = 0o644;
/// Mode of the installed profile.
pub(crate) const PROFILE_MODE: u32 = 0o644;
/// Mode of the Windows bridge exe on DrvFs (informational; DrvFs ignores it).
pub(crate) const BRIDGE_MODE: u32 = 0o755;
/// Directory mode for `credentials/`.
pub(crate) const DIR_MODE: u32 = 0o700;

/// Deadline for the `cmd.exe` invocation that resolves `%LOCALAPPDATA%`.
const LOCALAPPDATA_DEADLINE: Duration = Duration::from_secs(5);
/// Hard cap on a Linux helper invocation (`pam-auth-update`). It is generous because an
/// *interactive* debconf run still needs the operator, but it guarantees a helper can
/// never block the installer forever.
const HELPER_TIMEOUT: Duration = Duration::from_secs(300);
/// The environment variable that makes debconf clients (`pam-auth-update`) non-blocking.
const DEBIAN_FRONTEND: &str = "DEBIAN_FRONTEND";

// `DEFAULT_WIN_MNT`, `WHOAMI_DEADLINE`, `EXIT_OK`, and `EXIT_FAIL` are not declared here:
// the CLI carries each of these exactly once. They are imported from the crate root
// (`main.rs`), which in turn re-exports
// `wsl_webauthn_store::Config::DEFAULT_WIN_MNT`.

// ---------------------------------------------------------------------------
// System paths
// ---------------------------------------------------------------------------

/// Every system path the installer mutates, plus the expected owner uid.
///
/// Tests build this with tempdir roots and the current euid, so no test ever writes to
/// `/etc`.
#[derive(Debug, Clone)]
pub(crate) struct InstallPaths {
    /// `/etc/wsl_webauthn`.
    pub etc_wsl_webauthn: PathBuf,
    /// `/etc/wsl.conf` (parsed for the `[automount] root=`).
    pub etc_wsl_conf: PathBuf,
    /// `/etc/pam.d`.
    pub pam_d: PathBuf,
    /// `/usr/share/pam-configs`.
    pub pam_configs: PathBuf,
    /// `/usr/local/bin` — where `install` copies the running CLI.
    pub bin_dir: PathBuf,
    /// `/etc/pam_wsl_hello` (legacy config dir; never removed by uninstall).
    pub legacy_config_dir: PathBuf,
    /// Roots scanned for `<root>/security` and `<root>/<triplet>/security`
    /// (`/usr/lib`, `/usr/lib64`, `/lib`, `/lib64`).
    pub module_search_roots: Vec<PathBuf>,
    /// Expected owner uid of installed files (0 in production).
    pub owner_uid: u32,
}

impl InstallPaths {
    /// The production paths.
    pub(crate) fn system() -> InstallPaths {
        InstallPaths {
            etc_wsl_webauthn: PathBuf::from(wsl_webauthn_store::SYSTEM_BASE),
            etc_wsl_conf: PathBuf::from("/etc/wsl.conf"),
            pam_d: PathBuf::from("/etc/pam.d"),
            pam_configs: PathBuf::from("/usr/share/pam-configs"),
            bin_dir: PathBuf::from("/usr/local/bin"),
            legacy_config_dir: PathBuf::from("/etc/pam_wsl_hello"),
            module_search_roots: vec![
                PathBuf::from("/usr/lib"),
                PathBuf::from("/usr/lib64"),
                PathBuf::from("/lib"),
                PathBuf::from("/lib64"),
            ],
            owner_uid: 0,
        }
    }

    /// `<etc_wsl_webauthn>/config`.
    pub(crate) fn config_path(&self) -> PathBuf {
        self.etc_wsl_webauthn.join("config")
    }

    /// `<etc_wsl_webauthn>/credentials`.
    pub(crate) fn credentials_dir(&self) -> PathBuf {
        self.etc_wsl_webauthn.join("credentials")
    }

    /// `<pam_configs>/wsl-webauthn`.
    pub(crate) fn profile_path(&self) -> PathBuf {
        self.pam_configs.join(PROFILE_NAME)
    }

    /// `<pam_configs>/wsl-hello`.
    pub(crate) fn legacy_profile_path(&self) -> PathBuf {
        self.pam_configs.join(LEGACY_PROFILE_NAME)
    }
}

// ---------------------------------------------------------------------------
// Injection seams
// ---------------------------------------------------------------------------

/// Runs a Windows program via WSL interop and returns its captured output.
pub(crate) trait InteropRunner {
    /// Run `program` with `args` in `win_mnt`, capturing stdout/stderr within `deadline`.
    fn run(
        &self,
        program: &str,
        args: &[&str],
        win_mnt: &Path,
        deadline: Duration,
    ) -> Result<std::process::Output, String>;
}

/// Production interop runner, backed by [`wsl_webauthn_runner::InteropCommand`].
pub(crate) struct RealInterop;

impl InteropRunner for RealInterop {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        win_mnt: &Path,
        deadline: Duration,
    ) -> Result<std::process::Output, String> {
        wsl_webauthn_runner::InteropCommand::run(program, args, win_mnt, deadline)
            .map_err(|e| e.to_string())
    }
}

/// Exit status of an external helper command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommandStatus {
    /// Whether the process exited 0.
    pub success: bool,
    /// The exit code, if the process exited normally.
    pub code: Option<i32>,
}

/// Runs a Linux helper program with an argument array (no shell).
pub(crate) trait CommandRunner {
    /// Run `program` with `args`.
    ///
    /// When `non_interactive` is set the implementation must not let the helper prompt on
    /// the terminal: it applies `DEBIAN_FRONTEND=noninteractive` and a hard timeout, so a
    /// debconf client such as `pam-auth-update` can never block the installer.
    fn run(
        &self,
        program: &str,
        args: &[&str],
        non_interactive: bool,
    ) -> Result<CommandStatus, String>;

    /// Whether `program` can be executed (found on `PATH`).
    ///
    /// The installer uses this up front to decide between driving `pam-auth-update` and
    /// printing manual `/etc/pam.d` instructions.
    fn available(&self, program: &str) -> bool;
}

/// Production command runner.
pub(crate) struct RealCommands;

/// Build the child command for a Linux helper, applying `DEBIAN_FRONTEND=noninteractive`
/// when the installer is non-interactive.
fn helper_command(program: &str, args: &[&str], non_interactive: bool) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    command.args(args);
    if non_interactive {
        command.env(DEBIAN_FRONTEND, "noninteractive");
    }
    command
}

impl CommandRunner for RealCommands {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        non_interactive: bool,
    ) -> Result<CommandStatus, String> {
        let mut child = helper_command(program, args, non_interactive)
            .spawn()
            .map_err(|e| format!("could not run {program}: {e}"))?;
        let deadline = Instant::now() + HELPER_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Ok(CommandStatus {
                        success: status.success(),
                        code: status.code(),
                    });
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(format!(
                            "{program} did not finish within {}s and was killed; run it by \
                             hand once the terminal is interactive",
                            HELPER_TIMEOUT.as_secs()
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(format!("could not wait for {program}: {e}")),
            }
        }
    }

    fn available(&self, program: &str) -> bool {
        let Ok(path) = std::env::var("PATH") else {
            return false;
        };
        std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
    }
}

/// Runs the post-install enrollment (in-process).
///
/// Abstracted so install tests never invoke the real enrollment logic (which would read
/// the real `/etc/wsl_webauthn`). Production uses [`RealEnroller`].
pub(crate) trait Enroller {
    /// Enroll the invoking user; `allow_unattested` selects the attestation policy.
    fn enroll(&self, allow_unattested: bool) -> anyhow::Result<i32>;
}

/// Production enroller: reuses the CLI's `enroll` implementation.
pub(crate) struct RealEnroller;

impl Enroller for RealEnroller {
    fn enroll(&self, allow_unattested: bool) -> anyhow::Result<i32> {
        crate::cmd_enroll(false, allow_unattested, None, None, None)
    }
}

/// Asks the operator yes/no questions.
pub(crate) trait Prompter {
    /// Ask `question` and return the answer; `default` is used for an empty line and in
    /// non-interactive mode.
    fn confirm(&self, question: &str, default: bool) -> anyhow::Result<bool>;
}

/// The production prompter: reads from stdin unless `--yes`/`--non-interactive`.
pub(crate) struct StdPrompter {
    /// `--yes`: answer yes to every question.
    pub assume_yes: bool,
    /// `--non-interactive`: never read stdin; use the question's default.
    pub non_interactive: bool,
}

impl Prompter for StdPrompter {
    fn confirm(&self, question: &str, default: bool) -> anyhow::Result<bool> {
        if self.assume_yes {
            println!("{question} [yes]");
            return Ok(true);
        }
        if self.non_interactive {
            println!("{question} [{}]", if default { "yes" } else { "no" });
            return Ok(default);
        }
        loop {
            print!("{question} [{}] ", if default { "Y/n" } else { "y/N" });
            std::io::stdout().flush().ok();
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line)? == 0 {
                return Ok(default);
            }
            match line.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                "" => return Ok(default),
                _ => continue,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Options for [`install_with`].
#[derive(Debug, Clone, Default)]
pub(crate) struct InstallOptions {
    /// Admit self/`none` attestation at enrollment (`--allow-unattested`).
    pub allow_unattested: bool,
    /// Skip the post-install setup: neither enroll nor enable (`--skip-enroll`).
    pub skip_enroll: bool,
    /// Override the module directory (skip detection).
    pub module_dir: Option<PathBuf>,
    /// Override the Windows mount root (skip `/etc/wsl.conf`).
    pub win_mnt: Option<PathBuf>,
    /// Explicit artifact directory (`--artifact-dir`), else `$WSL_WEBAUTHN_ARTIFACTS`,
    /// else a search around the executable.
    pub artifact_dir: Option<PathBuf>,
    /// `--dry-run`: resolve everything and print the planned mutations, writing nothing.
    pub dry_run: bool,
    /// `--non-interactive`: pass `DEBIAN_FRONTEND=noninteractive` to helper processes so
    /// a debconf prompt cannot block.
    pub non_interactive: bool,
}

/// Options for [`uninstall_all`].
#[derive(Debug, Clone, Default)]
pub(crate) struct UninstallOptions {
    /// Override the Windows mount root.
    pub win_mnt: Option<PathBuf>,
    /// Override the module directory (skip detection).
    pub module_dir: Option<PathBuf>,
    /// `--non-interactive`: pass `DEBIAN_FRONTEND=noninteractive` to helper processes.
    pub non_interactive: bool,
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

/// One reversible action recorded during install.
///
/// Provisioning overwrites destinations (temp file + `rename(2)`), so a rollback cannot
/// simply delete a path: a file this run *created* is removed, while a file it
/// *overwrote* is restored from the bytes+mode snapshotted just before the write.
enum Action {
    /// A file this run created; removing it undoes the action.
    NewFile(PathBuf),
    /// A directory tree this run created; the exe inside is removed recursively.
    NewDir(PathBuf),
    /// A file this run overwrote; restoring the snapshot undoes the action.
    Restore {
        /// The overwritten path.
        path: PathBuf,
        /// The pre-write bytes.
        bytes: Vec<u8>,
        /// The pre-write mode (low 12 bits).
        mode: u32,
    },
}

/// Records what this run wrote so a failure can undo exactly that.
struct Rollback {
    actions: Vec<Action>,
    committed: bool,
}

impl Rollback {
    fn new() -> Rollback {
        Rollback {
            actions: Vec::new(),
            committed: false,
        }
    }

    fn push(&mut self, action: Action) {
        self.actions.push(action);
    }

    fn created_dir(&mut self, path: PathBuf) {
        self.actions.push(Action::NewDir(path));
    }

    /// Disarm the rollback: the install is complete and verified.
    fn commit(&mut self) {
        self.committed = true;
    }

    /// Undo recorded actions, most-recent first.
    fn rollback(&mut self) {
        for action in self.actions.drain(..).rev() {
            match action {
                Action::NewFile(path) => {
                    if let Err(e) = fsutil::remove_file(&path) {
                        eprintln!("warning: rollback could not remove {}: {e}", path.display());
                    }
                }
                Action::NewDir(path) => {
                    if let Err(e) = fsutil::remove_tree(&path) {
                        eprintln!("warning: rollback could not remove {}: {e}", path.display());
                    }
                }
                Action::Restore { path, bytes, mode } => {
                    if let Err(e) = fsutil::atomic_write(&path, &bytes, mode) {
                        eprintln!(
                            "warning: rollback could not restore {}: {e}",
                            path.display()
                        );
                    }
                }
            }
        }
    }
}

/// Snapshot how to undo a write to `path`, *before* the write happens.
///
/// Returns a [`Action::Restore`] carrying the existing bytes+mode when `path` is an
/// existing regular file, or [`Action::NewFile`] when it does not exist yet. Returns
/// `None` when the destination is a symlink or a non-file (the subsequent atomic write
/// refuses those anyway, so there is nothing to undo).
///
/// Callers must only register the returned action after the write actually succeeded.
fn prepare_write(path: &Path) -> anyhow::Result<Option<Action>> {
    match fsutil::lstat_opt(path)? {
        None => Ok(Some(Action::NewFile(path.to_path_buf()))),
        Some(md) if md.file_type().is_symlink() => Ok(None),
        Some(md) if md.is_file() => {
            let bytes = fsutil::read_nofollow(path)
                .with_context(|| format!("snapshotting {} before overwrite", path.display()))?;
            Ok(Some(Action::Restore {
                path: path.to_path_buf(),
                bytes,
                mode: fsutil::mode_of(&md),
            }))
        }
        Some(_) => Ok(None),
    }
}

impl Drop for Rollback {
    fn drop(&mut self) {
        if !self.committed {
            self.rollback();
        }
    }
}

// ---------------------------------------------------------------------------
// Artifact resolution
// ---------------------------------------------------------------------------

/// The two build artifacts the installer ships.
#[derive(Debug, Clone)]
struct Artifacts {
    /// The PAM module (`.so`).
    module: PathBuf,
    /// The Windows bridge exe.
    bridge: PathBuf,
}

/// Candidate directories to search for artifacts, nearest-first.
///
/// Only directories derived from the running executable are considered. The current
/// working directory is deliberately **not** searched: the module is installed as a
/// root PAM object, and a non-root invoker controls the cwd, so a `.so` planted there
/// (or a `./build/release` tree) could otherwise be installed. A source checkout runs
/// the CLI from `target/<profile>/`, whose directory is therefore already a candidate.
fn candidate_artifact_dirs() -> Vec<PathBuf> {
    // No executable directory (or no parent) yields no implicit candidates, so the
    // caller reports the build/`--artifact-dir` hint rather than searching anywhere
    // untrusted.
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    else {
        return Vec::new();
    };
    artifact_dirs_from_exe_dir(&dir)
}

/// The search roots implied by running the CLI from `dir` (the executable's directory).
fn artifact_dirs_from_exe_dir(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    dirs.push(dir.to_path_buf());
    if let Some(target) = ancestor_named(dir, "target") {
        dirs.push(target.join("release"));
        if let Ok(entries) = std::fs::read_dir(&target) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path.join("release"));
                }
            }
        }
    }
    let mut cur = dir;
    for _ in 0..4 {
        let Some(parent) = cur.parent() else { break };
        dirs.push(parent.to_path_buf());
        dirs.push(parent.join("build"));
        dirs.push(parent.join("build/release"));
        dirs.push(parent.join("release"));
        cur = parent;
    }
    let mut seen = Vec::new();
    dirs.retain(|d| {
        if seen.contains(d) {
            false
        } else {
            seen.push(d.clone());
            true
        }
    });
    dirs
}

/// Find the first ancestor of `dir` (inclusive) whose file name is `name`.
fn ancestor_named(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut cur = Some(dir);
    while let Some(path) = cur {
        if path.file_name().and_then(|n| n.to_str()) == Some(name) {
            return Some(path.to_path_buf());
        }
        cur = path.parent();
    }
    None
}

fn find_in(dirs: &[PathBuf], names: &[&str]) -> Option<PathBuf> {
    for dir in dirs {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Resolve the module and bridge artifacts.
///
/// Order: an explicit `--artifact-dir` (or `$WSL_WEBAUTHN_ARTIFACTS`) is authoritative
/// and must contain both files; otherwise only the executable's own directory and its
/// `build/`/`target/` ancestors are searched (release-tarball and cargo layouts). The
/// invoking user's current directory is never searched (see
/// [`candidate_artifact_dirs`]).
fn resolve_artifacts(explicit: Option<&Path>) -> anyhow::Result<Artifacts> {
    let env_dir = std::env::var_os("WSL_WEBAUTHN_ARTIFACTS").map(PathBuf::from);
    let explicit = explicit.map(Path::to_path_buf).or(env_dir);
    let dirs = match explicit {
        Some(dir) => vec![dir],
        None => candidate_artifact_dirs(),
    };
    let module = find_in(&dirs, &[MODULE_NAME, "libpam_wsl_webauthn.so"]).ok_or_else(|| {
        anyhow!(
            "could not find {MODULE_NAME} (or libpam_wsl_webauthn.so); build the workspace \
             (`make all`) or pass --artifact-dir <DIR> / set WSL_WEBAUTHN_ARTIFACTS"
        )
    })?;
    let bridge = find_in(&dirs, &[BRIDGE_EXE]).ok_or_else(|| {
        anyhow!(
            "could not find {BRIDGE_EXE}; build the bridge (`make bridge`) or pass \
             --artifact-dir <DIR> / set WSL_WEBAUTHN_ARTIFACTS"
        )
    })?;
    Ok(Artifacts { module, bridge })
}

// ---------------------------------------------------------------------------
// Module directory detection
// ---------------------------------------------------------------------------

/// Detect the PAM security directory by finding the one that contains `pam_unix.so`.
///
/// `roots` are library roots such as `/usr/lib`; both `<root>/security` and
/// `<root>/<triplet>/security` are probed. Deterministic (sorted) so tests are stable.
pub(crate) fn detect_module_dir(roots: &[PathBuf]) -> Option<PathBuf> {
    for root in roots {
        let direct = root.join("security");
        if direct.join("pam_unix.so").is_file() {
            return Some(direct);
        }
        if let Ok(entries) = std::fs::read_dir(root) {
            let mut subdirs: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            subdirs.sort();
            for subdir in subdirs {
                let security = subdir.join("security");
                if security.join("pam_unix.so").is_file() {
                    return Some(security);
                }
            }
        }
    }
    None
}

/// Resolve the destination module directory: explicit flag, detection, fallback, error.
fn resolve_module_dir(paths: &InstallPaths, explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(dir) = explicit {
        let md = fsutil::lstat_opt(dir)?
            .ok_or_else(|| anyhow!("module directory does not exist: {}", dir.display()))?;
        if md.file_type().is_symlink() {
            bail!(
                "refusing to use a symlinked module directory: {}",
                dir.display()
            );
        }
        if !md.is_dir() {
            bail!("module directory is not a directory: {}", dir.display());
        }
        return Ok(dir.to_path_buf());
    }
    if let Some(detected) = detect_module_dir(&paths.module_search_roots) {
        return Ok(detected);
    }
    for fallback in [
        "/usr/lib/security",
        "/usr/lib64/security",
        "/lib/security",
        "/lib64/security",
    ] {
        let dir = Path::new(fallback);
        if dir.is_dir() {
            return Ok(dir.to_path_buf());
        }
    }
    bail!(
        "could not locate the PAM module directory (no pam_unix.so found under {:?}); \
         pass --module-dir <DIR> (e.g. /usr/lib/x86_64-linux-gnu/security)",
        paths.module_search_roots
    )
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// The `[base]/config` contents for `bridge_path`/`win_mnt`, serialized by the store.
///
/// The on-disk format is owned by [`wsl_webauthn_store::Config::to_toml`] (the writer
/// counterpart to the store's `deny_unknown_fields` parser). `timeout_secs` is `None`
/// because the installer does not set an auth deadline override.
fn config_toml(bridge_path: &Path, win_mnt: &Path) -> String {
    Config {
        bridge_path: bridge_path.to_path_buf(),
        win_mnt: win_mnt.to_path_buf(),
        timeout_secs: None,
    }
    .to_toml()
}

/// A unique backup path for `path`. The marker is also skipped when scanning `/etc/pam.d`
/// on uninstall.
fn backup_path(path: &Path) -> PathBuf {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    path.with_file_name(format!("{name}{}.{secs}", fsutil::BACKUP_MARKER))
}

/// The fail-safe PAM control used when a legacy line's control would gate `sudo`/`su`.
///
/// `success=end` makes a successful WebAuthn authentication end the stack; `default=ignore`
/// makes a failed/skipped one fall through to the password modules below. This mirrors the
/// shipped `pam-config` profile and is the only control under which replacing a legacy
/// `required`/`requisite` line is lockout-safe.
const CANONICAL_CONTROL: &str = "[success=end default=ignore]";

/// Control keywords/modifiers that are already fail-safe: a failed WebAuthn attempt still
/// falls through to the next PAM module.
fn control_is_safe(control: &str) -> bool {
    matches!(control, "sufficient" | "optional")
        || (control.starts_with('[') && control.contains("success="))
}

/// Rewrite the legacy module stem in one `/etc/pam.d` line, normalizing an unsafe control.
///
/// A blind byte substitution would turn `auth required pam_wsl_hello.so` into
/// `auth required pam_wsl_webauthn.so`, converting a working password fallback into a
/// Hello-gated required line (lockout). When the control is not fail-safe this replaces the
/// whole control field with [`CANONICAL_CONTROL`] and records the original control in
/// `unsafe_controls` so the caller can demand an explicit second confirmation.
///
/// Comment/blank/unparseable lines fall back to a plain stem substitution.
fn rewrite_legacy_line(line: &[u8], unsafe_controls: &mut Vec<String>) -> Vec<u8> {
    // Split off the line terminator (preserving CRLF) so tokenization is not confused.
    let (content, ending): (&[u8], &[u8]) = if let Some(rest) = line.strip_suffix(b"\r\n") {
        (rest, b"\r\n")
    } else if let Some(rest) = line.strip_suffix(b"\n") {
        (rest, b"\n")
    } else {
        (line, b"")
    };
    let simple = || {
        let mut out = replace_all(content, LEGACY_MODULE_STEM, MODULE_STEM);
        out.extend_from_slice(ending);
        out
    };
    let Ok(text) = std::str::from_utf8(content) else {
        return simple();
    };
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return simple();
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 2 {
        return simple();
    }
    // Find the extent of the control field: a single token, or a bracketed `[...]` that may
    // contain spaces.
    let mut ctrl_end = 1usize;
    if tokens[1].starts_with('[') {
        while ctrl_end + 1 < tokens.len() && !tokens[ctrl_end].ends_with(']') {
            ctrl_end += 1;
        }
    }
    let control = tokens[1..=ctrl_end.min(tokens.len() - 1)].join(" ");
    if control_is_safe(&control) {
        return simple();
    }
    unsafe_controls.push(control);
    // Rebuild: leading whitespace + auth-type + canonical control + remaining fields.
    let leading = content
        .iter()
        .take_while(|b| b.is_ascii_whitespace())
        .count();
    let mut rest = Vec::new();
    for (i, token) in tokens[ctrl_end + 1..].iter().enumerate() {
        if i > 0 {
            rest.push(b' ');
        }
        rest.extend_from_slice(token.as_bytes());
    }
    let rest = replace_all(&rest, LEGACY_MODULE_STEM, MODULE_STEM);
    let mut out = Vec::with_capacity(line.len() + CANONICAL_CONTROL.len());
    out.extend_from_slice(&content[..leading]);
    out.extend_from_slice(tokens[0].as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(CANONICAL_CONTROL.as_bytes());
    if !rest.is_empty() {
        out.push(b' ');
        out.extend_from_slice(&rest);
    }
    out.extend_from_slice(ending);
    out
}

/// Apply [`rewrite_legacy_line`] to every line, collecting unsafe original controls.
fn rewrite_legacy_references(original: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut out = Vec::with_capacity(original.len());
    let mut unsafe_controls = Vec::new();
    for line in original.split_inclusive(|&b| b == b'\n') {
        if line
            .windows(LEGACY_MODULE_STEM.len())
            .any(|w| w == LEGACY_MODULE_STEM)
        {
            out.extend_from_slice(&rewrite_legacy_line(line, &mut unsafe_controls));
        } else {
            out.extend_from_slice(line);
        }
    }
    (out, unsafe_controls)
}

/// Replace every non-overlapping occurrence of `needle` in `haystack`.
fn replace_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

fn resolve_win_mnt(paths: &InstallPaths, explicit: Option<&Path>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir.to_path_buf();
    }
    if let Ok(bytes) = fsutil::read_nofollow(&paths.etc_wsl_conf)
        && let Ok(text) = std::str::from_utf8(&bytes)
        && let Some(parsed) = confparse::parse_win_mnt(text)
    {
        return parsed;
    }
    PathBuf::from(DEFAULT_WIN_MNT)
}

/// Resolve `%LOCALAPPDATA%` through `cmd.exe` (cwd = `win_mnt`, CRLF-stripped, 5 s).
fn resolve_local_appdata(interop: &dyn InteropRunner, win_mnt: &Path) -> anyhow::Result<String> {
    let output = interop
        .run(
            "cmd.exe",
            &["/c", "echo", "%LOCALAPPDATA%"],
            win_mnt,
            LOCALAPPDATA_DEADLINE,
        )
        .map_err(|e| anyhow!("could not resolve %LOCALAPPDATA% via cmd.exe: {e}"))?;
    if !output.status.success() {
        bail!(
            "cmd.exe /c echo %LOCALAPPDATA% exited with {:?}",
            output.status.code()
        );
    }
    confparse::parse_local_appdata(&output.stdout).ok_or_else(|| {
        anyhow!("%LOCALAPPDATA% resolved to an unusable value (undefined variable?)")
    })
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

/// Ensure a directory exists with a safe owner/mode, refusing symlinks, and record the
/// highest newly created directory for rollback.
///
/// A pre-existing Linux directory is validated, not trusted: when `owner_uid` is
/// `Some`, it must be owned by that uid and must not be group/other-writable. A too-open
/// mode is tightened in place (with a warning); wrong ownership is refused, since this
/// process may not be able to `chown` it and silently reusing another owner's directory
/// on the root install path would violate the "root-owned" invariant. `owner_uid` is
/// `None` for the Windows bridge directory on DrvFs, where ownership and mode are
/// synthesized and neither check is meaningful.
fn ensure_dir(
    dir: &Path,
    mode: u32,
    owner_uid: Option<u32>,
    rollback: &mut Rollback,
    what: &str,
) -> anyhow::Result<()> {
    if let Some(md) = fsutil::lstat_opt(dir)? {
        if md.file_type().is_symlink() {
            bail!("refusing to use a symlinked {what}: {}", dir.display());
        }
        if !md.is_dir() {
            bail!("{what} is not a directory: {}", dir.display());
        }
        if let Some(expected) = owner_uid {
            if md.uid() != expected {
                bail!(
                    "refusing to reuse {what} {}: owned by uid {}, expected uid {}",
                    dir.display(),
                    md.uid(),
                    expected
                );
            }
            // Remove any permission bit not present in the requested mode, but never
            // *add* bits: an existing 0777 credentials dir becomes 0700, while a
            // deliberately stricter 0750 config dir is left alone.
            let current = fsutil::mode_of(&md);
            if current & !mode != 0 {
                eprintln!(
                    "warning: {what} {} has mode {current:o}, more permissive than the \
                     intended {mode:o}; tightening",
                    dir.display()
                );
                fsutil::set_mode(dir, mode).with_context(|| {
                    format!("tightening mode on existing {what} {}", dir.display())
                })?;
            }
        }
        return Ok(());
    }
    // Find the first existing ancestor so a create that makes several components can be
    // rolled back by removing only the top-most new directory.
    let mut first_missing: Option<PathBuf> = None;
    let mut cur = Some(dir);
    while let Some(path) = cur {
        match fsutil::lstat_opt(path)? {
            Some(_) => break,
            None => first_missing = Some(path.to_path_buf()),
        }
        cur = path.parent();
    }
    fsutil::create_dir_all(dir).with_context(|| format!("creating {what} {}", dir.display()))?;
    fsutil::set_mode(dir, mode)
        .with_context(|| format!("setting mode on {what} {}", dir.display()))?;
    if let Some(root) = first_missing {
        rollback.created_dir(root);
    }
    Ok(())
}

/// Copy the bridge into `%LOCALAPPDATA%\Programs\wsl-webauthn-pam\` and return its WSL path.
fn provision_bridge(
    interop: &dyn InteropRunner,
    win_mnt: &Path,
    source: &Path,
    rollback: &mut Rollback,
) -> anyhow::Result<PathBuf> {
    let local = resolve_local_appdata(interop, win_mnt)?;
    let dest_win = confparse::windows_join(&local, WIN_BRIDGE_SUBPATH);
    let dest_win = confparse::windows_join(&dest_win, &[BRIDGE_EXE]);
    let dest = confparse::windows_to_wsl(&dest_win, win_mnt);

    fsutil::refuse_symlink(&dest, "bridge destination")?;
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow!("bridge destination has no parent: {}", dest.display()))?;
    // DrvFs synthesizes ownership/mode, so only the symlink/dir checks apply here.
    ensure_dir(parent, 0o755, None, rollback, "bridge directory")?;

    let undo = prepare_write(&dest)?;
    fsutil::copy_file_atomic(source, &dest, BRIDGE_MODE)
        .with_context(|| format!("installing the bridge to {}", dest.display()))?;
    if let Some(action) = undo {
        rollback.push(action);
    }

    let hash = fsutil::sha256_hex_file(&dest)
        .with_context(|| format!("hashing the installed bridge at {}", dest.display()))?;
    println!(
        "  bridge:      {} (sha256 {})",
        dest.display(),
        fsutil::short_hash(&hash)
    );
    Ok(dest)
}

/// Write `/etc/wsl_webauthn/config` and create `credentials/` (`0700`).
fn provision_config(
    paths: &InstallPaths,
    win_mnt: &Path,
    bridge_path: &Path,
    rollback: &mut Rollback,
) -> anyhow::Result<()> {
    ensure_dir(
        &paths.etc_wsl_webauthn,
        0o755,
        Some(paths.owner_uid),
        rollback,
        "config directory",
    )?;
    let toml = config_toml(bridge_path, win_mnt);
    let config = paths.config_path();
    let undo = prepare_write(&config)?;
    fsutil::atomic_write(&config, toml.as_bytes(), CONFIG_MODE)
        .with_context(|| format!("writing {}", config.display()))?;
    if let Some(action) = undo {
        rollback.push(action);
    }
    println!("  config:      {}", config.display());

    let creds = paths.credentials_dir();
    ensure_dir(
        &creds,
        DIR_MODE,
        Some(paths.owner_uid),
        rollback,
        "credentials directory",
    )?;
    println!("  credentials: {}", creds.display());
    Ok(())
}

/// Install `pam_wsl_webauthn.so` with mode `0644`.
fn provision_module(
    module_dir: &Path,
    source: &Path,
    rollback: &mut Rollback,
) -> anyhow::Result<PathBuf> {
    let dest = module_dir.join(MODULE_NAME);
    let undo = prepare_write(&dest)?;
    fsutil::copy_file_atomic(source, &dest, MODULE_MODE)
        .with_context(|| format!("installing the module to {}", dest.display()))?;
    if let Some(action) = undo {
        rollback.push(action);
    }
    println!("  module:      {}", dest.display());
    Ok(dest)
}

/// Install the `pam-configs` profile with the embedded bytes.
fn provision_profile(paths: &InstallPaths, rollback: &mut Rollback) -> anyhow::Result<PathBuf> {
    ensure_dir(
        &paths.pam_configs,
        0o755,
        Some(paths.owner_uid),
        rollback,
        "pam-configs directory",
    )?;
    let dest = paths.profile_path();
    let undo = prepare_write(&dest)?;
    fsutil::atomic_write(&dest, PROFILE_TEXT.as_bytes(), PROFILE_MODE)
        .with_context(|| format!("installing the profile to {}", dest.display()))?;
    if let Some(action) = undo {
        rollback.push(action);
    }
    println!("  profile:     {}", dest.display());
    Ok(dest)
}

/// Ensure the CLI directory exists, without rewriting an existing mode.
///
/// `/usr/local/bin` is a normal system directory that may pre-exist with a distro-chosen
/// mode (e.g. setgid and group-writable), so an existing directory is only validated —
/// real directory, not a symlink, owned by `owner_uid` — and its mode is left untouched.
/// A directory this run creates is `root:root 0755` and is removed on rollback.
fn ensure_bin_dir(
    dir: &Path,
    owner_uid: u32,
    rollback: &mut Rollback,
    what: &str,
) -> anyhow::Result<()> {
    if let Some(md) = fsutil::lstat_opt(dir)? {
        if md.file_type().is_symlink() {
            bail!("refusing to use a symlinked {what}: {}", dir.display());
        }
        if !md.is_dir() {
            bail!("{what} is not a directory: {}", dir.display());
        }
        if md.uid() != owner_uid {
            bail!(
                "refusing to reuse {what} {}: owned by uid {}, expected uid {}",
                dir.display(),
                md.uid(),
                owner_uid
            );
        }
        return Ok(());
    }
    // Missing: create it through `ensure_dir` for the same rollback bookkeeping.
    ensure_dir(dir, 0o755, Some(owner_uid), rollback, what)
}

/// Install the CLI itself to `bin_dir` with mode `0755`.
///
/// The source is the running executable, the one the operator invoked. Runs before
/// [`Rollback::commit`], so an overwritten CLI is restored (or a new one removed) if a
/// later provisioning step fails, exactly like the module and profile.
fn provision_cli(
    paths: &InstallPaths,
    source: &Path,
    rollback: &mut Rollback,
) -> anyhow::Result<PathBuf> {
    ensure_bin_dir(&paths.bin_dir, paths.owner_uid, rollback, "bin directory")?;
    let dest = paths.bin_dir.join(CLI_NAME);
    let undo = prepare_write(&dest)?;
    fsutil::copy_file_atomic(source, &dest, CLI_MODE)
        .with_context(|| format!("installing the CLI to {}", dest.display()))?;
    if let Some(action) = undo {
        rollback.push(action);
    }
    // `copy_file_atomic` pins the mode at creation, but assert it as the module/profile
    // helpers do: an installed CLI that is not executable is unusable.
    let md = fsutil::lstat_opt(&dest)?
        .ok_or_else(|| anyhow!("verification failed: CLI missing at {}", dest.display()))?;
    if !md.is_file() || fsutil::mode_of(&md) != CLI_MODE {
        bail!(
            "verification failed: {} has mode {:o}, expected {:o}",
            dest.display(),
            fsutil::mode_of(&md),
            CLI_MODE
        );
    }
    println!("  cli:         {}", dest.display());
    Ok(dest)
}

/// Verify the freshly written artifacts: profile bytes, module bytes+type+mode, config.
fn verify_installed(
    paths: &InstallPaths,
    module_dir: &Path,
    module_src: &Path,
    profile: &Path,
    bridge: &Path,
) -> anyhow::Result<()> {
    let installed = fsutil::read_nofollow(profile)
        .with_context(|| format!("re-reading {}", profile.display()))?;
    if installed != PROFILE_TEXT.as_bytes() {
        bail!(
            "verification failed: {} does not match the embedded pam-config",
            profile.display()
        );
    }
    let module = module_dir.join(MODULE_NAME);
    let md = fsutil::lstat_opt(&module)?.ok_or_else(|| {
        anyhow!(
            "verification failed: module missing at {}",
            module.display()
        )
    })?;
    if !md.is_file() {
        bail!(
            "verification failed: {} is not a regular file",
            module.display()
        );
    }
    if fsutil::mode_of(&md) != MODULE_MODE {
        bail!(
            "verification failed: {} has mode {:o}, expected {:o}",
            module.display(),
            fsutil::mode_of(&md),
            MODULE_MODE
        );
    }
    // A regular file with the right mode is not enough: a truncated/zero-byte/partial
    // copy would install "successfully" and only fail at dlopen on the root path. The
    // copy is a byte-for-byte `copy_file_atomic`, so assert equality with the source.
    let installed_module = fsutil::read_nofollow(&module)
        .with_context(|| format!("re-reading {}", module.display()))?;
    let source_module = fsutil::read_nofollow(module_src)
        .with_context(|| format!("re-reading source {}", module_src.display()))?;
    if installed_module != source_module {
        bail!(
            "verification failed: {} ({} bytes) does not match its source {} ({} bytes)",
            module.display(),
            installed_module.len(),
            module_src.display(),
            source_module.len()
        );
    }
    if !installed_module.starts_with(b"\x7fELF") {
        bail!(
            "verification failed: {} is not an ELF shared object (bad magic)",
            module.display()
        );
    }
    if fsutil::lstat_opt(bridge)?.is_none() {
        bail!(
            "verification failed: bridge missing at {}",
            bridge.display()
        );
    }
    let store = Store::with_owner(&paths.etc_wsl_webauthn, paths.owner_uid);
    store.load_config().map_err(|e| {
        anyhow!(
            "verification failed: {} is not a valid store config: {e}",
            paths.config_path().display()
        )
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy migration
// ---------------------------------------------------------------------------

/// A detected legacy WSL-Hello-sudo installation.
#[derive(Debug, Default, Clone)]
pub(crate) struct Legacy {
    /// Legacy module files found.
    pub modules: Vec<PathBuf>,
    /// The legacy config directory, if present.
    pub config_dir: Option<PathBuf>,
    /// The legacy `pam-configs` profile, if present.
    pub profile: Option<PathBuf>,
}

impl Legacy {
    fn is_present(&self) -> bool {
        !self.modules.is_empty() || self.config_dir.is_some() || self.profile.is_some()
    }
}

/// Detect the legacy module in every candidate security directory.
pub(crate) fn detect_legacy(paths: &InstallPaths) -> Legacy {
    let mut modules = Vec::new();
    let mut push = |dir: &Path| {
        let candidate = dir.join(LEGACY_MODULE_NAME);
        if fsutil::lstat_opt(&candidate).ok().flatten().is_some() {
            modules.push(candidate);
        }
    };
    for root in &paths.module_search_roots {
        push(&root.join("security"));
        if let Ok(entries) = std::fs::read_dir(root) {
            let mut subdirs: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            subdirs.sort();
            for subdir in subdirs {
                push(&subdir.join("security"));
            }
        }
    }
    modules.sort();
    modules.dedup();

    Legacy {
        modules,
        config_dir: fsutil::lstat_opt(&paths.legacy_config_dir)
            .ok()
            .flatten()
            .map(|_| paths.legacy_config_dir.clone()),
        profile: fsutil::lstat_opt(&paths.legacy_profile_path())
            .ok()
            .flatten()
            .map(|_| paths.legacy_profile_path()),
    }
}

/// Rewrite `/etc/pam.d/*` references from `pam_wsl_hello` to `pam_wsl_webauthn.so`.
///
/// Runs **before** any old-module removal (a stale reference means a load failure and a
/// lockout). Each file is confirmed individually, a timestamped copy is made first
/// (mode-preserved), and the rewrite is atomic. Symlinked files are skipped with a
/// warning (never edited through a link). Idempotent: a second run finds no legacy
/// references and does nothing.
///
/// A legacy line whose control is not fail-safe (`sufficient`/`optional`/`[success=…]`)
/// would become a Hello-gated `required`/`requisite` line after a naive stem swap, so the
/// control is normalized to [`CANONICAL_CONTROL`] behind an explicit second confirmation.
///
/// This runs *after* [`Rollback::commit`], so a later failure can never roll the rewrite
/// back into the stale `pam_wsl_hello` state.
fn migrate_rewrite_pam_d(paths: &InstallPaths, prompter: &dyn Prompter) -> anyhow::Result<usize> {
    if !paths.pam_d.is_dir() {
        return Ok(0);
    }
    let entries = std::fs::read_dir(&paths.pam_d)
        .with_context(|| format!("reading {}", paths.pam_d.display()))?;
    let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    files.sort();

    let mut rewritten = 0usize;
    for path in files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.contains(fsutil::TEMP_MARKER) || name.contains(fsutil::BACKUP_MARKER) {
            continue;
        }
        let Some(md) = fsutil::lstat_opt(&path)? else {
            continue;
        };
        if md.file_type().is_symlink() {
            println!("  skipping symlinked pam.d file {}", path.display());
            continue;
        }
        if !md.is_file() {
            continue;
        }
        let original = match fsutil::read_nofollow(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("warning: could not read {}: {e}", path.display());
                continue;
            }
        };
        if !original
            .windows(LEGACY_MODULE_STEM.len())
            .any(|w| w == LEGACY_MODULE_STEM)
        {
            continue;
        }
        let (updated, unsafe_controls) = rewrite_legacy_references(&original);
        if updated == original {
            continue;
        }
        let question = format!(
            "Rewrite pam_wsl_hello references in {} to pam_wsl_webauthn.so?",
            path.display()
        );
        if !prompter.confirm(&question, true)? {
            println!("  left {} unchanged", path.display());
            continue;
        }
        if !unsafe_controls.is_empty() {
            eprintln!();
            eprintln!(
                "WARNING: {} contains an unsafe PAM control ({}) on a pam_wsl_hello line.",
                path.display(),
                unsafe_controls.join(", ")
            );
            eprintln!("         Keeping `required`/`requisite` would gate sudo/su on Hello");
            eprintln!("         with no password fallback. The control will be normalized to");
            eprintln!("         `{CANONICAL_CONTROL}` (fail-safe) instead.");
            let normalize = prompter.confirm(
                &format!(
                    "Replace the unsafe control in {} with the fail-safe `{CANONICAL_CONTROL}`?",
                    path.display()
                ),
                true,
            )?;
            if !normalize {
                println!(
                    "  left {} unchanged: its unsafe control needs manual repair",
                    path.display()
                );
                continue;
            }
        }
        let mode = fsutil::mode_of(&md);
        let backup = backup_path(&path);
        fsutil::atomic_write(&backup, &original, mode)
            .with_context(|| format!("writing backup {}", backup.display()))?;
        fsutil::atomic_write(&path, &updated, mode)
            .with_context(|| format!("rewriting {}", path.display()))?;
        println!("  rewrote {} (backup {})", path.display(), backup.display());
        rewritten += 1;
    }
    Ok(rewritten)
}

/// Remove the legacy profile (`pam-auth-update --remove wsl-hello`), module files, and
/// config directory, each behind a confirmation. The legacy PEM is never imported.
fn migrate_remove_legacy(
    legacy: &Legacy,
    commands: &dyn CommandRunner,
    prompter: &dyn Prompter,
    pam_auth_update: bool,
    non_interactive: bool,
) -> anyhow::Result<()> {
    if legacy.profile.is_some() {
        if !pam_auth_update {
            println!(
                "  `pam-auth-update` not found; deregister the legacy profile by removing \
                 its file below (or by hand)."
            );
        } else if prompter.confirm(
            "Run `pam-auth-update --remove wsl-hello` to deregister the legacy profile?",
            true,
        )? {
            match commands.run(
                "pam-auth-update",
                &["--remove", LEGACY_PROFILE_NAME],
                non_interactive,
            ) {
                Ok(status) if status.success => {
                    println!("  pam-auth-update --remove wsl-hello: done");
                }
                Ok(status) => eprintln!(
                    "warning: pam-auth-update --remove wsl-hello exited {:?}",
                    status.code
                ),
                Err(e) => eprintln!("warning: {e}"),
            }
        }
    }
    if let Some(profile) = &legacy.profile
        && fsutil::lstat_opt(profile)?.is_some()
        && prompter.confirm(
            &format!("Remove the legacy profile file {}?", profile.display()),
            true,
        )?
    {
        match fsutil::remove_file(profile) {
            Ok(()) => println!("  removed {}", profile.display()),
            Err(e) => eprintln!("warning: could not remove {}: {e}", profile.display()),
        }
    }
    for module in &legacy.modules {
        if prompter.confirm(
            &format!("Remove the legacy module {}?", module.display()),
            true,
        )? {
            match fsutil::remove_file(module) {
                Ok(()) => println!("  removed {}", module.display()),
                Err(e) => eprintln!("warning: could not remove {}: {e}", module.display()),
            }
        }
    }
    if let Some(dir) = &legacy.config_dir
        && prompter.confirm(
            &format!("Remove the legacy config directory {}?", dir.display()),
            true,
        )?
    {
        match fsutil::remove_tree(dir) {
            Ok(()) => println!("  removed {}", dir.display()),
            Err(e) => eprintln!("warning: could not remove {}: {e}", dir.display()),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Post-install guidance
// ---------------------------------------------------------------------------

/// The manual enable instructions (one line per element), used when `pam-auth-update`
/// is not installed (e.g. RHEL/Fedora).
fn manual_enable_steps(paths: &InstallPaths) -> Vec<String> {
    vec![
        "`pam-auth-update` was not found on this system; enable the module by hand:".to_string(),
        "  add this line to /etc/pam.d/common-auth (Debian/Ubuntu) or to the relevant".to_string(),
        "  service (e.g. /etc/pam.d/sudo, /etc/pam.d/su), above any password line:".to_string(),
        "      auth sufficient pam_wsl_webauthn.so".to_string(),
        format!(
            "  (the profile installed at {} documents the same line)",
            paths.profile_path().display()
        ),
    ]
}

/// Print [`manual_enable_steps`].
fn print_manual_enable_steps(paths: &InstallPaths) {
    for line in manual_enable_steps(paths) {
        println!("{line}");
    }
}

/// Enable the profile with `pam-auth-update --enable wsl-webauthn`.
///
/// Shared by `install` (after a successful enrollment) and standalone `enroll`. This
/// is the single code path that mutates the PAM configuration: on a host without
/// `pam-auth-update` it only prints the manual `/etc/pam.d` instructions (there is
/// nothing it can run), and otherwise it runs the helper and reports whether the
/// profile is now active.
///
/// Returns `Ok(true)` when the profile is active, `Ok(false)` when it could not be
/// enabled (helper absent, or a non-zero exit), so the caller can decide what to
/// print. Enabling is only ever called after a credential has been verified, so the
/// fail-safe `[success=end default=ignore]` control still falls through to the
/// password line if the credential is later unusable.
pub(crate) fn enable_profile(
    paths: &InstallPaths,
    commands: &dyn CommandRunner,
    pam_auth_update: bool,
    non_interactive: bool,
) -> anyhow::Result<bool> {
    if !pam_auth_update {
        print_manual_enable_steps(paths);
        return Ok(false);
    }
    match commands.run(
        "pam-auth-update",
        &["--enable", PROFILE_NAME],
        non_interactive,
    ) {
        Ok(status) if status.success => {
            println!("Enabled the PAM profile (`pam-auth-update --enable wsl-webauthn`).");
            Ok(true)
        }
        Ok(status) => {
            eprintln!(
                "warning: pam-auth-update --enable wsl-webauthn exited {:?}; \
                 the profile is not enabled",
                status.code
            );
            Ok(false)
        }
        Err(e) => {
            eprintln!("warning: {e}");
            Ok(false)
        }
    }
}

/// Print lockout-recovery guidance when the profile was NOT enabled.
///
/// WSL has no virtual console to fall back to, so the recovery path is a Windows-side
/// root shell; for non-WSL Linux the classic TTY route is offered too.
fn print_lockout_guidance(enroll_cmd: &str) {
    println!();
    println!("Lockout safety:");
    println!("  * Keep at least one of `sudo`/`su` working with a password while you test.");
    println!("  * The profile is not enabled yet; run `sudo pam-auth-update` and");
    println!("    select \"WSL WebAuthn authentication\" when you are ready.");
    println!("  * Enroll a credential before relying on the module: `sudo {enroll_cmd} enroll`");
    println!("  * Manual alternative (add to /etc/pam.d/common-auth above the password line):");
    println!("        auth sufficient pam_wsl_webauthn.so");
    println!("  * If sudo/su breaks, recover WITHOUT relying on the broken login:");
    println!("      WSL: from a Windows terminal, open a root shell for this distro and");
    println!("           remove the module line:");
    println!("             wsl.exe -d <distro> -u root");
    println!("             # then edit /etc/pam.d/* (or run");
    println!("             #   pam-auth-update --remove wsl-webauthn)");
    println!("      Other Linux: sign in on another TTY/console (Ctrl-Alt-F2) and");
    println!("           remove that line.");
}

/// Print the one-line success message after enrollment and a successful enable.
fn print_enable_success(enroll_cmd: &str) {
    println!();
    println!("Done. `sudo` now uses Windows Hello.");
    println!("  If you decline the Hello prompt, sudo falls back to your password.");
    println!("  Test it:  sudo -k; sudo true");
    println!("  Add another user later:  sudo {enroll_cmd} enroll");
}

/// Enable the PAM profile after a successful standalone `enroll`.
///
/// The `enroll` subcommand calls this so it shares exactly one enable code path with
/// `install`; `cmd_enroll` itself stays a pure ceremony-and-record unit that never touches
/// PAM configuration. The system paths match the store `cmd_enroll` just wrote to.
pub(crate) fn enable_after_enroll(
    commands: &dyn CommandRunner,
    pam_auth_update: bool,
) -> anyhow::Result<()> {
    let paths = InstallPaths::system();
    let enabled = enable_profile(&paths, commands, pam_auth_update, false)?;
    if enabled {
        let enroll_cmd = paths.bin_dir.join(CLI_NAME);
        print_enable_success(&enroll_cmd.display().to_string());
    } else if pam_auth_update {
        // enable_profile's helper call failed (non-zero exit or spawn error), or the
        // profile is not registered with pam-auth-update (e.g. a manual install).
        println!();
        println!("The credential is enrolled, but the PAM profile is not enabled.");
        println!("Enable it with `sudo pam-auth-update --enable wsl-webauthn`, or add");
        println!("`auth sufficient pam_wsl_webauthn.so` to the relevant /etc/pam.d service.");
    }
    // When `pam-auth-update` is absent, enable_profile already printed the manual
    // `/etc/pam.d` steps.
    Ok(())
}

/// Print the planned mutations for `--dry-run` without touching the system.
fn print_dry_run(paths: &InstallPaths, module_dir: &Path, pam_auth_update: bool) {
    println!("Dry run: resolved everything; nothing will be written.");
    println!(
        "  bridge:      %LOCALAPPDATA%\\Programs\\wsl-webauthn-pam\\{BRIDGE_EXE} (would copy)"
    );
    println!("  config:      {} (0600)", paths.config_path().display());
    println!(
        "  credentials: {} (0700)",
        paths.credentials_dir().display()
    );
    println!(
        "  module:      {} (0644)",
        module_dir.join(MODULE_NAME).display()
    );
    println!("  profile:     {} (0644)", paths.profile_path().display());

    let legacy = detect_legacy(paths);
    if legacy.is_present() {
        println!("  legacy cleanup would be offered (old credentials are never imported):");
        for module in &legacy.modules {
            println!("    remove {}", module.display());
        }
        if let Some(dir) = &legacy.config_dir {
            println!("    remove {}", dir.display());
        }
        if let Some(profile) = &legacy.profile {
            println!("    deregister/remove {}", profile.display());
        }
        println!("    rewrite pam_wsl_hello -> pam_wsl_webauthn in /etc/pam.d (per file)");
    } else {
        println!("  legacy cleanup: none detected");
    }

    if pam_auth_update {
        println!(
            "  enable step: `pam-auth-update --enable {PROFILE_NAME}` \
             (after a successful enrollment)"
        );
    } else {
        print_manual_enable_steps(paths);
    }
    // Name the installed CLI so a `--dry-run` shows the real post-install command.
    println!("  cli:         {}", paths.bin_dir.join(CLI_NAME).display());
}

/// The lines of post-install guidance (pure, so the text is testable).
///
/// `enroll_cmd` is the installed CLI's absolute path, so the instruction is runnable even
/// when `/usr/local/bin` is not on the shell's `PATH`.
fn next_steps_lines(enroll_cmd: &str, enrolled: bool, pam_auth_update: bool) -> Vec<String> {
    if enrolled {
        // A credential exists but the profile is not active (enable failed or the helper
        // is absent): point at the enable step.
        let mut lines =
            vec!["A credential is enrolled, but the PAM profile is not enabled.".to_string()];
        if pam_auth_update {
            lines.push("Enable it:  sudo pam-auth-update --enable wsl-webauthn".to_string());
            lines.push(
                "  (or add `auth sufficient pam_wsl_webauthn.so` to /etc/pam.d/sudo)".to_string(),
            );
        } else {
            lines.push(
                "  add `auth sufficient pam_wsl_webauthn.so` to the relevant /etc/pam.d service"
                    .to_string(),
            );
        }
        lines
    } else {
        vec![
            "Installation complete, but no credential is enrolled yet.".to_string(),
            format!("Enroll one (this also enables it):  sudo {enroll_cmd} enroll"),
            "  (add --allow-unattested only on machines without a TPM-backed Hello)".to_string(),
        ]
    }
}

/// Print what the operator must do next.
fn print_next_steps(enroll_cmd: &str, enrolled: bool, pam_auth_update: bool) {
    println!();
    for line in next_steps_lines(enroll_cmd, enrolled, pam_auth_update) {
        println!("{line}");
    }
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

/// Execute the install flow against `paths` with the injected seams.
pub(crate) fn install_with(
    paths: &InstallPaths,
    interop: &dyn InteropRunner,
    commands: &dyn CommandRunner,
    prompter: &dyn Prompter,
    enroller: &dyn Enroller,
    opts: &InstallOptions,
) -> anyhow::Result<i32> {
    let win_mnt = resolve_win_mnt(paths, opts.win_mnt.as_deref());
    let artifacts = resolve_artifacts(opts.artifact_dir.as_deref())?;
    let module_dir = resolve_module_dir(paths, opts.module_dir.as_deref())?;

    println!("wsl-webauthn-pam installer");
    println!("  win_mnt:     {}", win_mnt.display());
    println!("  module dir:  {}", module_dir.display());
    println!("  module src:  {}", artifacts.module.display());
    println!("  bridge src:  {}", artifacts.bridge.display());
    println!();

    // Detect `pam-auth-update` up front (it may be absent on RHEL/Fedora), so the flow
    // can print manual `/etc/pam.d` steps instead of a bare warning.
    let pam_auth_update = commands.available("pam-auth-update");

    if opts.dry_run {
        print_dry_run(paths, &module_dir, pam_auth_update);
        return Ok(EXIT_OK);
    }

    let mut rollback = Rollback::new();

    // 1. Windows bridge (must exist before enrollment, which pins it).
    // A `whoami.exe` sanity check: warn, do not abort — some hosts have
    // interop enabled but a restricted whoami.
    if let Err(e) = interop.run("whoami.exe", &[], &win_mnt, WHOAMI_DEADLINE) {
        eprintln!("warning: interop sanity check (`whoami.exe`) failed: {e}");
        eprintln!("         (continuing; the same interop is used for the bridge at enroll time)");
    }
    let bridge_dest = provision_bridge(interop, &win_mnt, &artifacts.bridge, &mut rollback)?;
    // 2. Linux config + credentials dir.
    provision_config(paths, &win_mnt, &bridge_dest, &mut rollback)?;
    // 3. Our own CLI, so the guidance printed later names a command that exists. The
    // running executable is the binary the operator invoked.
    let running_cli =
        std::env::current_exe().context("resolving the running CLI to install it to PATH")?;
    let cli_dest = provision_cli(paths, &running_cli, &mut rollback)?;
    // 4. New module and profile FIRST (a stale reference would mean lockout).
    let module_dest = provision_module(&module_dir, &artifacts.module, &mut rollback)?;
    let profile_dest = provision_profile(paths, &mut rollback)?;
    // 5. Verify before touching anything legacy.
    verify_installed(
        paths,
        &module_dir,
        &artifacts.module,
        &profile_dest,
        &bridge_dest,
    )?;
    println!();
    println!("Installed and verified {}.", module_dest.display());

    // The provisioning is complete and verified. Commit the rollback here: every step
    // after this point (legacy cleanup, prompts, enrollment) must never be undone by
    // removing the module/profile we just installed.
    rollback.commit();
    // The CLI is installed to an absolute path, so the printed guidance is runnable even
    // when `/usr/local/bin` is not on the shell's `PATH`.
    let enroll_cmd = cli_dest.display().to_string();

    // 6. Legacy migration, only after our module/profile are verified.
    let legacy = detect_legacy(paths);
    if legacy.is_present() {
        println!();
        println!("Legacy WSL-Hello-sudo installation detected:");
        for module in &legacy.modules {
            println!("  legacy module: {}", module.display());
        }
        if let Some(dir) = &legacy.config_dir {
            println!("  legacy config: {}", dir.display());
        }
        if let Some(profile) = &legacy.profile {
            println!("  legacy profile: {}", profile.display());
        }
        println!("The legacy PEM trust anchor is NEVER imported; a fresh enrollment is required.");
        // (a) rewrite /etc/pam.d references BEFORE any old-module removal.
        let rewritten = migrate_rewrite_pam_d(paths, prompter)?;
        if rewritten > 0 {
            println!("Rewrote {rewritten} pam.d file(s).");
        }
        // (b)/(c) deregister the profile and remove the old module/config.
        migrate_remove_legacy(
            &legacy,
            commands,
            prompter,
            pam_auth_update,
            opts.non_interactive,
        )?;
        println!();
        println!("Legacy cleanup complete. A FRESH enrollment is required (old credentials");
        println!("are not migrated): run `sudo {enroll_cmd}`.");
    }

    // 7. Offer to set up Windows Hello (enroll + enable) as a single action.
    //
    // The profile is enabled only AFTER a credential is verified, in the same step. That
    // is what makes `sudo` actually use Hello with no follow-up command, and it is
    // fail-safe: the profile's `[success=end default=ignore]` control falls through to the
    // password line if the credential is later unusable.
    if opts.skip_enroll {
        // Provision only; a later `enroll` enables the profile on success.
        print_lockout_guidance(&enroll_cmd);
        print_next_steps(&enroll_cmd, false, pam_auth_update);
        return Ok(EXIT_OK);
    }

    println!();
    let enroll_now = prompter.confirm(
        "Set up Windows Hello for sudo now (enroll a credential and enable it)?",
        true,
    )?;
    if !enroll_now {
        print_lockout_guidance(&enroll_cmd);
        print_next_steps(&enroll_cmd, false, pam_auth_update);
        return Ok(EXIT_OK);
    }

    // Invoke the enrollment logic in-process. The config and bridge installed above are
    // what `cmd_enroll` resolves.
    println!();
    match enroller.enroll(opts.allow_unattested) {
        Ok(EXIT_OK) => {
            // Enable only now that a credential exists. If enabling fails, the profile
            // stays off and the manual steps below are the fix.
            let enabled = enable_profile(paths, commands, pam_auth_update, opts.non_interactive)?;
            if enabled {
                print_enable_success(&enroll_cmd);
                Ok(EXIT_OK)
            } else {
                print_lockout_guidance(&enroll_cmd);
                print_next_steps(&enroll_cmd, true, pam_auth_update);
                Ok(EXIT_OK)
            }
        }
        Ok(code) => {
            // Enrollment reported an operational failure (it prints its own reason).
            eprintln!("warning: enrollment did not complete; the profile is left disabled.");
            print_lockout_guidance(&enroll_cmd);
            print_next_steps(&enroll_cmd, false, pam_auth_update);
            Ok(code)
        }
        Err(error) => {
            eprintln!("warning: enrollment failed: {error:#}");
            print_lockout_guidance(&enroll_cmd);
            print_next_steps(&enroll_cmd, false, pam_auth_update);
            Ok(EXIT_FAIL)
        }
    }
}

/// Production entry point for `install`.
pub(crate) fn cmd_install(
    opts: InstallOptions,
    assume_yes: bool,
    non_interactive: bool,
) -> anyhow::Result<i32> {
    crate::require_root("install")?;
    let paths = InstallPaths::system();
    let prompter = StdPrompter {
        assume_yes,
        non_interactive,
    };
    install_with(
        &paths,
        &RealInterop,
        &RealCommands,
        &prompter,
        &RealEnroller,
        &opts,
    )
}

// ---------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------

/// Remove one user's credential record (shared by `unregister` and `uninstall`).
///
/// Never touches another user's record. Returns [`EXIT_OK`] if a record was
/// removed, [`EXIT_FAIL`] if there was nothing to do.
pub(crate) fn uninstall_user(
    store: &Store,
    name: &str,
    yes: bool,
    prompter: &dyn Prompter,
) -> anyhow::Result<i32> {
    let existing = match store.load(name) {
        Ok(record) => Some(record),
        Err(wsl_webauthn_store::StoreError::NotFound { .. }) => None,
        Err(error) => {
            eprintln!("warning: could not read the existing record: {error}");
            None
        }
    };
    if existing.is_none() && !yes {
        bail!("no credential record for \"{name}\"");
    }

    println!("About to remove the credential for \"{name}\".");
    if let Some(record) = &existing {
        if let Some(identity) = &record.windows_identity
            && !identity.account.is_empty()
        {
            println!("  windows account: {}", identity.account);
        }
        println!("  enrolled at:     {}", record.enrolled_at);
    } else {
        println!("  (no readable record; removal will be a no-op if absent)");
    }

    if !prompter.confirm("Remove this credential?", false)? {
        println!("Aborted.");
        return Ok(EXIT_FAIL);
    }
    match store.remove(name) {
        Ok(true) => {
            println!("Removed the credential for \"{name}\".");
            Ok(EXIT_OK)
        }
        Ok(false) => {
            println!("No credential record for \"{name}\" (nothing to do).");
            Ok(EXIT_FAIL)
        }
        Err(error) => bail!("failed to remove credential: {error}"),
    }
}

/// Find installed copies of our module under the module search roots.
fn find_installed_modules(paths: &InstallPaths, explicit: Option<&Path>) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut probe = |dir: &Path| {
        let candidate = dir.join(MODULE_NAME);
        if fsutil::lstat_opt(&candidate).ok().flatten().is_some() {
            found.push(candidate);
        }
    };
    if let Some(dir) = explicit {
        probe(dir);
    }
    for root in &paths.module_search_roots {
        probe(&root.join("security"));
        if let Ok(entries) = std::fs::read_dir(root) {
            let mut subdirs: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            subdirs.sort();
            for subdir in subdirs {
                probe(&subdir.join("security"));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Resolve the Windows bridge directory (`%LOCALAPPDATA%\Programs\wsl-webauthn-pam`).
fn win_bridge_dir(interop: &dyn InteropRunner, win_mnt: &Path) -> anyhow::Result<PathBuf> {
    let local = resolve_local_appdata(interop, win_mnt)?;
    let dest_win = confparse::windows_join(&local, WIN_BRIDGE_SUBPATH);
    Ok(confparse::windows_to_wsl(&dest_win, win_mnt))
}

/// Derive the original path from a timestamped backup
/// (`<dir>/<name>.wsl-webauthn-bak.<secs>` → `<dir>/<name>`).
fn original_from_backup(backup: &Path) -> Option<PathBuf> {
    let name = backup.file_name()?.to_string_lossy();
    let idx = name.find(fsutil::BACKUP_MARKER)?;
    let original = &name[..idx];
    if original.is_empty() {
        return None;
    }
    Some(backup.with_file_name(original))
}

/// Restore the `/etc/pam.d` originals that migration backed up.
///
/// `migrate_rewrite_pam_d` copies each legacy service file to a timestamped
/// `*.wsl-webauthn-bak.*` sibling before rewriting `pam_wsl_hello` → `pam_wsl_webauthn`.
/// Uninstall must reverse that: after our module is gone, a service file that still
/// references it is a libpam load failure on the root path, and the fix (the original
/// file) is sitting right next to it. Each backup is restored behind a confirmation,
/// then removed, so the operation is idempotent (a second run finds no backups).
///
/// Returns the number of files restored.
fn restore_pam_d_backups(paths: &InstallPaths, prompter: &dyn Prompter) -> anyhow::Result<usize> {
    if !paths.pam_d.is_dir() {
        return Ok(0);
    }
    let entries = std::fs::read_dir(&paths.pam_d)
        .with_context(|| format!("reading {}", paths.pam_d.display()))?;
    let mut backups: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().contains(fsutil::BACKUP_MARKER))
                .unwrap_or(false)
        })
        .collect();
    backups.sort();

    let mut restored = 0usize;
    for backup in backups {
        let Some(md) = fsutil::lstat_opt(&backup)? else {
            continue;
        };
        if md.file_type().is_symlink() || !md.is_file() {
            continue;
        }
        let Some(original) = original_from_backup(&backup) else {
            continue;
        };
        let bytes = match fsutil::read_nofollow(&backup) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("warning: could not read backup {}: {e}", backup.display());
                continue;
            }
        };
        if !prompter.confirm(
            &format!(
                "Restore {} from backup {}?",
                original.display(),
                backup.display()
            ),
            true,
        )? {
            println!("  left backup {} in place", backup.display());
            continue;
        }
        if let Some(omd) = fsutil::lstat_opt(&original)?
            && omd.file_type().is_symlink()
        {
            eprintln!(
                "warning: not restoring {} (it is a symlink); backup left at {}",
                original.display(),
                backup.display()
            );
            continue;
        }
        let mode = fsutil::mode_of(&md);
        if let Err(e) = fsutil::atomic_write(&original, &bytes, mode) {
            eprintln!("warning: could not restore {}: {e}", original.display());
            continue;
        }
        if let Err(e) = fsutil::remove_file(&backup) {
            eprintln!(
                "warning: restored {} but could not remove backup {}: {e}",
                original.display(),
                backup.display()
            );
        }
        println!(
            "  restored {} (from {})",
            original.display(),
            backup.display()
        );
        restored += 1;
    }
    Ok(restored)
}

/// Warn (never edit) if `/etc/pam.d` still references our module.
fn warn_pam_d_references(paths: &InstallPaths) {
    if !paths.pam_d.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&paths.pam_d) else {
        return;
    };
    let mut hits: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(md) = fsutil::lstat_opt(&path).ok().flatten() else {
            continue;
        };
        if !md.is_file() || md.file_type().is_symlink() {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.contains(fsutil::BACKUP_MARKER) || name.contains(fsutil::TEMP_MARKER) {
            continue;
        }
        if let Ok(bytes) = fsutil::read_nofollow(&path)
            && bytes.windows(MODULE_STEM.len()).any(|w| w == MODULE_STEM)
        {
            hits.push(path);
        }
    }
    if !hits.is_empty() {
        eprintln!();
        eprintln!("WARNING: /etc/pam.d still references pam_wsl_webauthn.so:");
        for path in hits {
            eprintln!("  {}", path.display());
        }
        eprintln!("Fix these by hand (or run `pam-auth-update`) before relying on sudo/su.");
    }
}

/// Execute a full uninstall against `paths`.
pub(crate) fn uninstall_all(
    paths: &InstallPaths,
    interop: &dyn InteropRunner,
    commands: &dyn CommandRunner,
    prompter: &dyn Prompter,
    opts: &UninstallOptions,
) -> anyhow::Result<i32> {
    let win_mnt = resolve_win_mnt(paths, opts.win_mnt.as_deref());
    println!("wsl-webauthn-pam uninstaller");
    println!("This removes the PAM profile, module, Linux config, Windows bridge, and the CLI.");

    if !prompter.confirm(
        "Remove ALL wsl-webauthn-pam components? This cannot be undone.",
        false,
    )? {
        println!("Aborted.");
        return Ok(EXIT_FAIL);
    }

    // 1. Profile: pam-auth-update --remove, then the file.
    let profile = paths.profile_path();
    if fsutil::lstat_opt(&profile)?.is_some() {
        if prompter.confirm("Run `pam-auth-update --remove wsl-webauthn`?", true)? {
            match commands.run(
                "pam-auth-update",
                &["--remove", PROFILE_NAME],
                opts.non_interactive,
            ) {
                Ok(status) if status.success => {
                    println!("  pam-auth-update --remove wsl-webauthn: done");
                }
                Ok(status) => eprintln!(
                    "warning: pam-auth-update --remove wsl-webauthn exited {:?}",
                    status.code
                ),
                Err(e) => eprintln!("warning: {e}"),
            }
        }
        if fsutil::lstat_opt(&profile)?.is_some() {
            fsutil::remove_file(&profile)?;
            println!("  removed {}", profile.display());
        }
    } else {
        println!("  profile not installed");
    }

    // 2. Restore /etc/pam.d originals that migration backed up, BEFORE removing the
    // module they reference (a dangling reference is a libpam load failure).
    let restored = restore_pam_d_backups(paths, prompter)?;
    if restored > 0 {
        println!("Restored {restored} pam.d file(s) from backups.");
    }

    // 3. Module(s).
    for module in find_installed_modules(paths, opts.module_dir.as_deref()) {
        if prompter.confirm(&format!("Remove {}?", module.display()), true)? {
            fsutil::remove_file(&module)?;
            println!("  removed {}", module.display());
        }
    }

    // 4. Linux config dir.
    if fsutil::lstat_opt(&paths.etc_wsl_webauthn)?.is_some()
        && prompter.confirm(
            &format!(
                "Remove the Linux config directory {} (including credentials)?",
                paths.etc_wsl_webauthn.display()
            ),
            true,
        )?
    {
        fsutil::remove_tree(&paths.etc_wsl_webauthn)?;
        println!("  removed {}", paths.etc_wsl_webauthn.display());
    }

    // 5. Windows bridge directory (best effort; report failures).
    match win_bridge_dir(interop, &win_mnt) {
        Ok(dir) => {
            if fsutil::lstat_opt(&dir)?.is_some() {
                if prompter.confirm(
                    &format!("Remove the Windows bridge directory {}?", dir.display()),
                    true,
                )? {
                    match fsutil::remove_tree(&dir) {
                        Ok(()) => println!("  removed {}", dir.display()),
                        Err(e) => eprintln!(
                            "warning: could not remove the Windows bridge directory {}: {e}",
                            dir.display()
                        ),
                    }
                }
            } else {
                println!("  Windows bridge directory not present");
            }
        }
        Err(e) => eprintln!("warning: could not resolve the Windows bridge directory: {e}"),
    }

    // 6. The CLI installed to /usr/local/bin (if any). Removing it is safe even when it is
    // the currently-running binary: Linux permits unlink while executing, and the process
    // keeps its inode until it exits.
    let cli = paths.bin_dir.join(CLI_NAME);
    if fsutil::lstat_opt(&cli)?.is_some() {
        if prompter.confirm(
            &format!("Remove the installed CLI {}?", cli.display()),
            true,
        )? {
            match fsutil::remove_file(&cli) {
                Ok(()) => println!("  removed {}", cli.display()),
                Err(e) => eprintln!("warning: could not remove {}: {e}", cli.display()),
            }
        }
    } else {
        println!("  installed CLI not present");
    }

    // 7. Fallback: migrations may not have left a backup (or the file was edited by
    // hand). Never blind-edit /etc/pam.d on uninstall; warn about leftover references.
    warn_pam_d_references(paths);

    // 8. The legacy /etc/pam_wsl_hello is NEVER removed (it is not ours).
    println!();
    println!("Done. The legacy /etc/pam_wsl_hello (if any) was left untouched.");
    Ok(EXIT_OK)
}

/// Production entry point for `uninstall`.
pub(crate) fn cmd_uninstall(
    user: Option<String>,
    all: bool,
    yes: bool,
    win_mnt: Option<PathBuf>,
    module_dir: Option<PathBuf>,
    non_interactive: bool,
) -> anyhow::Result<i32> {
    crate::require_root("uninstall")?;
    let prompter = StdPrompter {
        assume_yes: yes,
        non_interactive,
    };
    if all {
        let paths = InstallPaths::system();
        let opts = UninstallOptions {
            win_mnt,
            module_dir,
            non_interactive,
        };
        uninstall_all(&paths, &RealInterop, &RealCommands, &prompter, &opts)
    } else {
        let target = crate::resolve_target_user(user)?;
        uninstall_user(&Store::system(), &target.name, yes, &prompter)
    }
}

// ---------------------------------------------------------------------------
// helpers shared with tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
