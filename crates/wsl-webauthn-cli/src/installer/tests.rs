//! Installer integration tests (tempdir-backed; `/etc` is never touched).
//!
//! Every test builds an [`InstallPaths`] rooted in a [`tempfile::TempDir`] and injects
//! mock interop/commands/prompter/enroller seams, so no test performs a real system
//! install.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;

use super::*;

/// Byte contents standing in for a built PAM module. Starts with the real ELF magic
/// (`\x7fELF`) so the artifact passes `verify_installed`'s magic and byte-equality
/// checks; it is never dlopened by the tests.
const MODULE_FIXTURE_BYTES: &[u8] = b"\x7fELF-fake-module-bytes";

// ---------------------------------------------------------------------------
// Mock seams
// ---------------------------------------------------------------------------

/// Mock interop: returns a canned stdout (or an error) for `cmd.exe`.
struct MockInterop {
    cmd_stdout: Vec<u8>,
    fail: bool,
}

impl MockInterop {
    fn local_appdata(value: &str) -> MockInterop {
        MockInterop {
            cmd_stdout: format!("{value}\r\n").into_bytes(),
            fail: false,
        }
    }

    fn failing() -> MockInterop {
        MockInterop {
            cmd_stdout: Vec::new(),
            fail: true,
        }
    }
}

impl InteropRunner for MockInterop {
    fn run(
        &self,
        _program: &str,
        _args: &[&str],
        _win_mnt: &Path,
        _deadline: Duration,
    ) -> Result<std::process::Output, String> {
        if self.fail {
            return Err("mock interop failure".to_string());
        }
        use std::os::unix::process::ExitStatusExt as _;
        Ok(std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: self.cmd_stdout.clone(),
            stderr: Vec::new(),
        })
    }
}

/// Mock command runner: records invocations and returns a configurable status.
struct MockCommands {
    calls: RefCell<Vec<(String, Vec<String>)>>,
    /// Recorded `non_interactive` flag of each invocation.
    non_interactive: RefCell<Vec<bool>>,
    success: bool,
    /// Whether `pam-auth-update` is reported as available.
    available: bool,
}

impl Default for MockCommands {
    fn default() -> MockCommands {
        MockCommands {
            calls: RefCell::new(Vec::new()),
            non_interactive: RefCell::new(Vec::new()),
            success: false,
            // Debian/Ubuntu-style host: `pam-auth-update` is reported available.
            available: true,
        }
    }
}

impl CommandRunner for MockCommands {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        non_interactive: bool,
    ) -> Result<CommandStatus, String> {
        self.calls.borrow_mut().push((
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));
        self.non_interactive.borrow_mut().push(non_interactive);
        Ok(CommandStatus {
            success: self.success,
            code: Some(if self.success { 0 } else { 1 }),
        })
    }

    fn available(&self, program: &str) -> bool {
        program == "pam-auth-update" && self.available
    }
}

/// Scripted prompter: pops answers in order (falling back to the question's default) and
/// records the questions asked. `always(Some(x))` answers `x` to every question.
struct ScriptedPrompter {
    always: Option<bool>,
    answers: RefCell<VecDeque<bool>>,
    questions: RefCell<Vec<String>>,
}

impl ScriptedPrompter {
    fn always(answer: bool) -> ScriptedPrompter {
        ScriptedPrompter {
            always: Some(answer),
            answers: RefCell::new(VecDeque::new()),
            questions: RefCell::new(Vec::new()),
        }
    }

    fn with_answers(answers: &[bool]) -> ScriptedPrompter {
        ScriptedPrompter {
            always: None,
            answers: RefCell::new(answers.iter().copied().collect()),
            questions: RefCell::new(Vec::new()),
        }
    }

    fn questions(&self) -> Vec<String> {
        self.questions.borrow().clone()
    }
}

impl Prompter for ScriptedPrompter {
    fn confirm(&self, question: &str, default: bool) -> anyhow::Result<bool> {
        self.questions.borrow_mut().push(question.to_string());
        if let Some(answer) = self.always {
            return Ok(answer);
        }
        Ok(self.answers.borrow_mut().pop_front().unwrap_or(default))
    }
}

/// Records that enrollment was (not) invoked.
#[derive(Default)]
struct MockEnroller {
    called: RefCell<Vec<bool>>,
    code: i32,
}

impl Enroller for MockEnroller {
    fn enroll(&self, allow_unattested: bool) -> anyhow::Result<i32> {
        self.called.borrow_mut().push(allow_unattested);
        Ok(self.code)
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    _tmp: TempDir,
    paths: InstallPaths,
    module_dir: PathBuf,
    art_dir: PathBuf,
    win_mnt: PathBuf,
    local_appdata: String,
}

fn write(path: &Path, bytes: &[u8], mode: u32) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(bytes).unwrap();
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .unwrap();
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

impl Harness {
    fn new() -> Harness {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Module-dir fixture: `<root>/usr/lib/<triplet>/security/pam_unix.so`.
        let module_dir = root.join("usr/lib/x86_64-linux-gnu/security");
        write(&module_dir.join("pam_unix.so"), b"fake pam_unix", 0o644);

        // Artifact fixtures. The module carries real ELF magic so the installed
        // artifact passes the magic check in `verify_installed`.
        let art_dir = root.join("artifacts");
        write(
            &art_dir.join(MODULE_NAME),
            MODULE_FIXTURE_BYTES,
            MODULE_MODE,
        );
        write(&art_dir.join(BRIDGE_EXE), b"MZ-fake-bridge-bytes", 0o755);

        let win_mnt = root.join("mnt/c");
        std::fs::create_dir_all(&win_mnt).unwrap();

        let etc_wsl_conf = root.join("etc/wsl.conf");
        write(&etc_wsl_conf, b"[automount]\nroot=/mnt/c\n", 0o644);

        let paths = InstallPaths {
            etc_wsl_webauthn: root.join("etc/wsl_webauthn"),
            etc_wsl_conf,
            pam_d: root.join("etc/pam.d"),
            pam_configs: root.join("usr/share/pam-configs"),
            legacy_config_dir: root.join("etc/pam_wsl_hello"),
            module_search_roots: vec![root.join("usr/lib"), root.join("lib")],
            owner_uid: wsl_webauthn_store::current_euid(),
        };
        std::fs::create_dir_all(&paths.pam_d).unwrap();

        Harness {
            _tmp: tmp,
            paths,
            module_dir,
            art_dir,
            win_mnt,
            local_appdata: "C:\\Users\\tester\\AppData\\Local".to_string(),
        }
    }

    fn interop(&self) -> MockInterop {
        MockInterop::local_appdata(&self.local_appdata)
    }

    fn bridge_dest(&self) -> PathBuf {
        self.win_mnt
            .join("Users/tester/AppData/Local/Programs/wsl-webauthn-pam")
            .join(BRIDGE_EXE)
    }

    fn opts(&self) -> InstallOptions {
        InstallOptions {
            allow_unattested: false,
            skip_enroll: true,
            module_dir: Some(self.module_dir.clone()),
            win_mnt: Some(self.win_mnt.clone()),
            artifact_dir: Some(self.art_dir.clone()),
            dry_run: false,
            non_interactive: false,
        }
    }

    fn run_install(
        &self,
        prompter: &dyn Prompter,
        enroller: &dyn Enroller,
        commands: &dyn CommandRunner,
        opts: &InstallOptions,
    ) -> anyhow::Result<i32> {
        let interop = self.interop();
        install_with(&self.paths, &interop, commands, prompter, enroller, opts)
    }
}

// ---------------------------------------------------------------------------
// Profile fidelity
// ---------------------------------------------------------------------------

#[test]
fn embedded_profile_matches_repo_file_byte_for_byte() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../pam-config");
    let on_disk = std::fs::read(&repo).unwrap();
    assert_eq!(
        PROFILE_TEXT.as_bytes(),
        on_disk.as_slice(),
        "the embedded profile drifted from {}",
        repo.display()
    );
    // The exact profile content.
    assert!(PROFILE_TEXT.contains("Name: WSL WebAuthn authentication"));
    assert!(PROFILE_TEXT.contains("Default: no"));
    assert!(PROFILE_TEXT.contains("Priority: 260"));
    assert!(PROFILE_TEXT.contains("Auth-Type: Primary"));
    assert!(PROFILE_TEXT.contains("[success=end default=ignore]    pam_wsl_webauthn.so"));
}

// ---------------------------------------------------------------------------
// win_mnt / LOCALAPPDATA
// ---------------------------------------------------------------------------

#[test]
fn install_reads_win_mnt_from_wsl_conf() {
    let h = Harness::new();
    // Point wsl.conf at a drive root *inside the harness tempdir* (final component `d`,
    // so it stands in for `/mnt/d`) and have LOCALAPPDATA report a D: path. A real `/mnt/d`
    // would make the installer create the bridge outside the tempdir — unwritable on CI
    // (EACCES), and on a dev box with a real DrvFs mount it would pollute the host.
    let win_mnt = h.win_mnt.parent().unwrap().join("d");
    write(
        &h.paths.etc_wsl_conf,
        format!("[automount]\r\nroot = {}/\r\n", win_mnt.display()).as_bytes(),
        0o644,
    );
    std::fs::create_dir_all(&win_mnt).unwrap();

    let interop = MockInterop::local_appdata("D:\\Users\\tester\\AppData\\Local");
    let mut opts = h.opts();
    opts.win_mnt = None; // exercise parsing of wsl.conf
    let commands = MockCommands::default();
    install_with(
        &h.paths,
        &interop,
        &commands,
        &ScriptedPrompter::always(true),
        &MockEnroller::default(),
        &opts,
    )
    .unwrap();

    let store = Store::with_owner(&h.paths.etc_wsl_webauthn, h.paths.owner_uid);
    let config = store.load_config().unwrap();
    assert_eq!(config.win_mnt, win_mnt);
    assert_eq!(
        config.bridge_path,
        win_mnt
            .join("Users/tester/AppData/Local/Programs/wsl-webauthn-pam")
            .join(BRIDGE_EXE)
    );
}

#[test]
fn resolve_local_appdata_strips_crlf_and_rejects_unexpanded() {
    let win_mnt = Path::new("/mnt/c");
    let ok = MockInterop::local_appdata("C:\\Users\\x\\AppData\\Local");
    assert_eq!(
        resolve_local_appdata(&ok, win_mnt).unwrap(),
        "C:\\Users\\x\\AppData\\Local"
    );
    let bad = MockInterop {
        cmd_stdout: b"%LOCALAPPDATA%\r\n".to_vec(),
        fail: false,
    };
    assert!(resolve_local_appdata(&bad, win_mnt).is_err());
    let err = MockInterop::failing();
    assert!(resolve_local_appdata(&err, win_mnt).is_err());
}

// ---------------------------------------------------------------------------
// Module-dir detection
// ---------------------------------------------------------------------------

#[test]
fn detect_module_dir_finds_triplet_and_falls_back() {
    let h = Harness::new();
    let detected = detect_module_dir(&h.paths.module_search_roots).unwrap();
    assert_eq!(detected, h.module_dir);
    // No pam_unix.so anywhere -> no detection.
    assert!(detect_module_dir(&[h._tmp.path().join("empty")]).is_none());
}

#[test]
fn detect_module_dir_finds_lib64() {
    let h = Harness::new();
    // RHEL/Fedora layout: `pam_unix.so` in `/usr/lib64/security`, no triplet.
    std::fs::remove_file(h.module_dir.join("pam_unix.so")).unwrap();
    let lib64_security = h._tmp.path().join("usr/lib64/security");
    write(&lib64_security.join("pam_unix.so"), b"fake pam_unix", 0o644);
    let roots = vec![h._tmp.path().join("usr/lib64")];
    assert_eq!(detect_module_dir(&roots).unwrap(), lib64_security);

    // The production roots must include the lib64 root.
    assert!(
        InstallPaths::system()
            .module_search_roots
            .contains(&PathBuf::from("/usr/lib64")),
        "module_search_roots must include /usr/lib64"
    );
}

#[test]
fn resolve_module_dir_prefers_explicit_flag() {
    let h = Harness::new();
    let other = h._tmp.path().join("other-security");
    std::fs::create_dir_all(&other).unwrap();
    assert_eq!(resolve_module_dir(&h.paths, Some(&other)).unwrap(), other);
    // A symlinked explicit dir is refused.
    let link = h._tmp.path().join("link-security");
    symlink(&other, &link).unwrap();
    assert!(resolve_module_dir(&h.paths, Some(&link)).is_err());
}

// ---------------------------------------------------------------------------
// Artifact resolution
// ---------------------------------------------------------------------------

#[test]
fn install_prefers_exe_dir_over_cwd() {
    // The implicit artifact search is rooted at the running executable only.
    // Two unrelated trees stand in for the executable's directory and an
    // attacker-controlled cwd; the search derived from the exe dir must never touch
    // the cwd tree, even though the latter has the tempting `build/release` layout a
    // `.so` would be planted in.
    let tmp_exe = TempDir::new().unwrap();
    let tmp_cwd = TempDir::new().unwrap();
    let exe_dir = tmp_exe.path().join("build/release");
    std::fs::create_dir_all(&exe_dir).unwrap();
    let cwd = tmp_cwd.path().to_path_buf();
    std::fs::create_dir_all(cwd.join("build/release")).unwrap();

    let dirs = artifact_dirs_from_exe_dir(&exe_dir);
    assert!(
        dirs.contains(&exe_dir),
        "the executable's directory must be searched: {dirs:?}"
    );
    assert!(
        !dirs.contains(&cwd),
        "the current working directory must not be searched: {dirs:?}"
    );
    for suffix in ["build", "build/release", "release"] {
        assert!(
            !dirs.contains(&cwd.join(suffix)),
            "cwd/{suffix} must not be an implicit artifact root: {dirs:?}"
        );
    }

    // And the real search is a subset of the exe-dir-derived roots (never cwd).
    let real_exe_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let real_cwd = std::env::current_dir().unwrap();
    assert!(
        candidate_artifact_dirs().contains(&real_exe_dir),
        "the real executable dir must be searched"
    );
    if real_exe_dir != real_cwd {
        assert!(
            !candidate_artifact_dirs().contains(&real_cwd),
            "the real cwd must never be an implicit artifact root"
        );
    }
}

// ---------------------------------------------------------------------------
// Directory hardening
// ---------------------------------------------------------------------------

#[test]
fn install_fixes_or_refuses_world_writable_credentials_dir() {
    // A pre-existing credentials/ directory must not be reused with an unsafe
    // owner/mode.
    let h = Harness::new();
    std::fs::create_dir_all(h.paths.credentials_dir()).unwrap();
    std::fs::set_permissions(
        h.paths.credentials_dir(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();

    // A world-writable directory owned by us is tightened back to 0700.
    h.run_install(
        &ScriptedPrompter::always(true),
        &MockEnroller::default(),
        &MockCommands::default(),
        &h.opts(),
    )
    .unwrap();
    assert_eq!(
        mode_of(&h.paths.credentials_dir()),
        DIR_MODE,
        "a world-writable credentials dir must be tightened"
    );

    // A directory owned by a different uid is refused rather than silently reused.
    let other = h._tmp.path().join("other-owner");
    std::fs::create_dir_all(&other).unwrap();
    let mut rollback = Rollback::new();
    let err = ensure_dir(
        &other,
        DIR_MODE,
        Some(h.paths.owner_uid.wrapping_add(1)),
        &mut rollback,
        "credentials directory",
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("owned by uid"), "{err:#}");
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn install_provisions_everything() {
    let h = Harness::new();
    let commands = MockCommands::default();
    let enroller = MockEnroller::default();
    // Decline the (optional) enable offer; skip_enroll means no other prompts.
    let code = h
        .run_install(
            &ScriptedPrompter::with_answers(&[false]),
            &enroller,
            &commands,
            &h.opts(),
        )
        .unwrap();
    assert_eq!(code, EXIT_OK);
    assert!(
        enroller.called.borrow().is_empty(),
        "skip_enroll must not enroll"
    );

    // Config file: exact fields, mode 0600, parseable by the store.
    let config_path = h.paths.config_path();
    assert_eq!(mode_of(&config_path), CONFIG_MODE);
    let store = Store::with_owner(&h.paths.etc_wsl_webauthn, h.paths.owner_uid);
    let config = store.load_config().unwrap();
    assert_eq!(config.bridge_path, h.bridge_dest());
    assert_eq!(config.win_mnt, h.win_mnt);
    assert!(config.timeout_secs.is_none());

    // Credentials dir: 0700.
    assert_eq!(mode_of(&h.paths.credentials_dir()), DIR_MODE);

    // Module: contents preserved, mode 0644.
    let module = h.module_dir.join(MODULE_NAME);
    assert_eq!(std::fs::read(&module).unwrap(), MODULE_FIXTURE_BYTES);
    assert_eq!(mode_of(&module), MODULE_MODE);

    // Profile: exact bytes, mode 0644.
    assert_eq!(
        std::fs::read(h.paths.profile_path()).unwrap(),
        PROFILE_TEXT.as_bytes()
    );
    assert_eq!(mode_of(&h.paths.profile_path()), PROFILE_MODE);

    // Bridge: copied with contents preserved.
    assert_eq!(
        std::fs::read(h.bridge_dest()).unwrap(),
        b"MZ-fake-bridge-bytes"
    );

    // The profile is not enabled unless confirmed.
    assert!(
        commands
            .calls
            .borrow()
            .iter()
            .all(|(p, _)| p != "pam-auth-update"),
        "no pam-auth-update call expected when not enabling"
    );
}

/// The config bytes the installer writes must come from the store's serializer
/// (`Config::to_toml`) and round-trip through the store's `deny_unknown_fields` parser.
#[test]
fn provision_config_writes_store_serialized_toml() {
    let h = Harness::new();
    // `provision_config` needs the config directory's parent to exist; the harness root does.
    let mut rollback = Rollback::new();
    provision_config(&h.paths, &h.win_mnt, &h.bridge_dest(), &mut rollback).unwrap();

    let expected = wsl_webauthn_store::Config {
        bridge_path: h.bridge_dest(),
        win_mnt: h.win_mnt.clone(),
        timeout_secs: None,
    }
    .to_toml();
    assert_eq!(
        std::fs::read_to_string(h.paths.config_path()).unwrap(),
        expected,
        "config bytes must be the store serializer output"
    );
    // And the store parses them back (the deny_unknown_fields contract).
    let store = Store::with_owner(&h.paths.etc_wsl_webauthn, h.paths.owner_uid);
    let parsed = store.load_config().unwrap();
    assert_eq!(parsed.bridge_path, h.bridge_dest());
    assert_eq!(parsed.win_mnt, h.win_mnt);
    assert_eq!(parsed.timeout_secs, None);
}

#[test]
fn install_offers_and_runs_enrollment_when_confirmed() {
    let h = Harness::new();
    let mut opts = h.opts();
    opts.skip_enroll = false;
    // Answer yes to the enrollment offer (and to enabling the profile).
    let prompter = ScriptedPrompter::always(true);
    let enroller = MockEnroller::default();
    let code = h
        .run_install(&prompter, &enroller, &MockCommands::default(), &opts)
        .unwrap();
    assert_eq!(code, EXIT_OK);
    assert_eq!(enroller.called.borrow().as_slice(), &[false]);
    // The enrollment question must be asked last.
    let questions = prompter.questions();
    assert!(questions.last().unwrap().contains("Enroll"));
}

#[test]
fn install_does_not_enroll_when_declined() {
    let h = Harness::new();
    let mut opts = h.opts();
    opts.skip_enroll = false;
    // Answer no to enabling the profile and no to the enrollment offer.
    let prompter = ScriptedPrompter::with_answers(&[false, false]);
    let enroller = MockEnroller::default();
    let code = h
        .run_install(&prompter, &enroller, &MockCommands::default(), &opts)
        .unwrap();
    assert_eq!(code, EXIT_OK);
    assert!(enroller.called.borrow().is_empty());
}

#[test]
fn install_passes_allow_unattested_to_enroller() {
    let h = Harness::new();
    let mut opts = h.opts();
    opts.skip_enroll = false;
    opts.allow_unattested = true;
    let enroller = MockEnroller::default();
    h.run_install(
        &ScriptedPrompter::always(true),
        &enroller,
        &MockCommands::default(),
        &opts,
    )
    .unwrap();
    assert_eq!(enroller.called.borrow().as_slice(), &[true]);
}

#[test]
fn install_enable_offer_invokes_pam_auth_update() {
    let h = Harness::new();
    let commands = MockCommands {
        success: true,
        ..MockCommands::default()
    };
    // Enable -> true, then skip enrollment.
    let prompter = ScriptedPrompter::with_answers(&[true, false]);
    h.run_install(&prompter, &MockEnroller::default(), &commands, &h.opts())
        .unwrap();
    let calls = commands.calls.borrow();
    assert!(calls.iter().any(|(p, a)| {
        p == "pam-auth-update" && a == &["--enable".to_string(), PROFILE_NAME.to_string()]
    }));
}

#[test]
fn install_dry_run_writes_nothing() {
    let h = Harness::new();
    let mut opts = h.opts();
    opts.dry_run = true;
    opts.skip_enroll = false;
    let commands = MockCommands {
        success: true,
        ..MockCommands::default()
    };
    let enroller = MockEnroller::default();
    // No prompts should be reached; any prompt would consume this scripted answer.
    let prompter = ScriptedPrompter::always(true);
    let code = h
        .run_install(&prompter, &enroller, &commands, &opts)
        .unwrap();
    assert_eq!(code, EXIT_OK);

    // Nothing on disk changed.
    assert!(
        !h.paths.etc_wsl_webauthn.exists(),
        "config dir must not exist"
    );
    assert!(!h.paths.profile_path().exists(), "profile must not exist");
    assert!(
        !h.module_dir.join(MODULE_NAME).exists(),
        "module must not exist"
    );
    assert!(!h.bridge_dest().exists(), "bridge must not be copied");
    assert!(
        !h.bridge_dest().parent().unwrap().exists(),
        "bridge dir must not exist"
    );
    // No helpers ran and no enrollment happened.
    assert!(
        commands.calls.borrow().is_empty(),
        "no helper calls in dry-run"
    );
    assert!(prompter.questions().is_empty(), "no prompts in dry-run");
    assert!(
        enroller.called.borrow().is_empty(),
        "no enrollment in dry-run"
    );
}

#[test]
fn install_non_interactive_sets_debian_frontend() {
    let h = Harness::new();
    let mut opts = h.opts();
    opts.non_interactive = true;
    let commands = MockCommands {
        success: true,
        ..MockCommands::default()
    };
    // Enable -> true.
    let prompter = ScriptedPrompter::with_answers(&[true]);
    h.run_install(&prompter, &MockEnroller::default(), &commands, &opts)
        .unwrap();

    // The helper saw the non-interactive flag...
    let flags = commands.non_interactive.borrow();
    assert!(
        !flags.is_empty(),
        "pam-auth-update should have been invoked"
    );
    assert!(
        flags.iter().all(|&f| f),
        "all helper calls must be non-interactive: {flags:?}"
    );
    // ...and the child command carries DEBIAN_FRONTEND=noninteractive.
    let envs: Vec<(String, Option<String>)> = helper_command("pam-auth-update", &[], true)
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert!(
        envs.iter()
            .any(|(k, v)| k == DEBIAN_FRONTEND && v.as_deref() == Some("noninteractive")),
        "DEBIAN_FRONTEND must be set: {envs:?}"
    );
    // The interactive command must not force the env.
    assert!(
        helper_command("pam-auth-update", &[], false)
            .get_envs()
            .all(|(k, _)| k != std::ffi::OsStr::new(DEBIAN_FRONTEND)),
        "interactive helpers must keep their own DEBIAN_FRONTEND"
    );
}

#[test]
fn install_without_pam_auth_update_prints_manual_steps() {
    let h = Harness::new();
    let commands = MockCommands {
        success: true,
        available: false,
        ..MockCommands::default()
    };
    // skip_enroll means no other prompt; the absent pam-auth-update must not prompt.
    let prompter = ScriptedPrompter::always(true);
    let code = h
        .run_install(&prompter, &MockEnroller::default(), &commands, &h.opts())
        .unwrap();
    assert_eq!(code, EXIT_OK);
    assert!(
        commands
            .calls
            .borrow()
            .iter()
            .all(|(p, _)| p != "pam-auth-update"),
        "pam-auth-update must not be invoked when absent"
    );
    // The flow prints exactly these manual steps.
    let steps = manual_enable_steps(&h.paths);
    let joined = steps.join("\n");
    assert!(joined.contains("/etc/pam.d/common-auth"), "{joined}");
    assert!(joined.contains("pam_wsl_webauthn.so"), "{joined}");
}

// ---------------------------------------------------------------------------
// Symlink refusal
// ---------------------------------------------------------------------------

#[test]
fn install_refuses_symlinked_config_destination() {
    let h = Harness::new();
    std::fs::create_dir_all(&h.paths.etc_wsl_webauthn).unwrap();
    let outside = h._tmp.path().join("outside-config");
    write(&outside, b"keep", 0o600);
    symlink(&outside, h.paths.config_path()).unwrap();

    let err = h
        .run_install(
            &ScriptedPrompter::always(true),
            &MockEnroller::default(),
            &MockCommands::default(),
            &h.opts(),
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    // The bridge written earlier in the run must have been rolled back.
    assert!(!h.bridge_dest().exists(), "bridge must be rolled back");
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
}

#[test]
fn install_refuses_symlinked_profile_destination() {
    let h = Harness::new();
    std::fs::create_dir_all(&h.paths.pam_configs).unwrap();
    let outside = h._tmp.path().join("outside-profile");
    write(&outside, b"keep", 0o644);
    symlink(&outside, h.paths.profile_path()).unwrap();

    let err = h
        .run_install(
            &ScriptedPrompter::always(true),
            &MockEnroller::default(),
            &MockCommands::default(),
            &h.opts(),
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    assert!(
        !h.paths.config_path().exists(),
        "config must be rolled back"
    );
}

#[test]
fn install_refuses_symlinked_module_destination() {
    let h = Harness::new();
    let outside = h._tmp.path().join("outside-module");
    write(&outside, b"keep", 0o644);
    symlink(&outside, h.module_dir.join(MODULE_NAME)).unwrap();

    let err = h
        .run_install(
            &ScriptedPrompter::always(true),
            &MockEnroller::default(),
            &MockCommands::default(),
            &h.opts(),
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    // Everything written before the module must be gone.
    assert!(!h.paths.config_path().exists());
    assert!(!h.paths.credentials_dir().exists());
    assert!(!h.bridge_dest().exists());
}

#[test]
fn install_refuses_symlinked_bridge_destination() {
    let h = Harness::new();
    // Pre-create the whole chain, with the exe itself a symlink.
    let dest = h.bridge_dest();
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let outside = h._tmp.path().join("outside-bridge");
    write(&outside, b"keep", 0o755);
    symlink(&outside, &dest).unwrap();

    let err = h
        .run_install(
            &ScriptedPrompter::always(true),
            &MockEnroller::default(),
            &MockCommands::default(),
            &h.opts(),
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    assert!(!h.paths.config_path().exists());
}

// ---------------------------------------------------------------------------
// Atomicity / failure injection
// ---------------------------------------------------------------------------

#[test]
fn install_fails_cleanly_when_bridge_artifact_missing() {
    let h = Harness::new();
    std::fs::remove_file(h.art_dir.join(BRIDGE_EXE)).unwrap();
    let err = h
        .run_install(
            &ScriptedPrompter::always(true),
            &MockEnroller::default(),
            &MockCommands::default(),
            &h.opts(),
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains(BRIDGE_EXE), "{err:#}");
    // Nothing was written at all.
    assert!(!h.paths.etc_wsl_webauthn.exists());
    assert!(!h.win_mnt.join("Users").exists());
}

#[test]
fn install_fails_when_module_artifact_is_truncated() {
    // A truncated module artifact must not be installed as "verified": the installer
    // compares the installed bytes against the source, not just the type+mode.
    let h = Harness::new();
    // A normal install + verify succeeds.
    h.run_install(
        &ScriptedPrompter::always(true),
        &MockEnroller::default(),
        &MockCommands::default(),
        &h.opts(),
    )
    .unwrap();

    // Simulate a partial/interrupted copy: the destination is a prefix of the source
    // (still a regular file with the right mode and ELF magic).
    let dest = h.module_dir.join(MODULE_NAME);
    let full = std::fs::read(&dest).unwrap();
    assert!(full.len() > 2);
    write(&dest, &full[..full.len() - 2], MODULE_MODE);

    let err = verify_installed(
        &h.paths,
        &h.module_dir,
        &h.art_dir.join(MODULE_NAME),
        &h.paths.profile_path(),
        &h.bridge_dest(),
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("does not match its source"),
        "{err:#}"
    );
}

#[test]
fn install_rolls_back_partial_state_on_module_failure() {
    let h = Harness::new();
    // Make the module source a symlink so the copy fails *after* the bridge and config
    // have already been written.
    let real = h.art_dir.join("real-module");
    write(&real, b"module", 0o644);
    std::fs::remove_file(h.art_dir.join(MODULE_NAME)).unwrap();
    symlink(&real, h.art_dir.join(MODULE_NAME)).unwrap();

    // Sanity: artifact resolution finds the symlink (a file), so failure happens later.
    let err = h
        .run_install(
            &ScriptedPrompter::always(true),
            &MockEnroller::default(),
            &MockCommands::default(),
            &h.opts(),
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("symlink"), "{err:#}");

    // Pre-state == post-state: no config, no credentials dir, no bridge, no partial dirs.
    assert!(!h.paths.etc_wsl_webauthn.exists());
    assert!(!h.bridge_dest().exists());
    assert!(
        !h.bridge_dest().parent().unwrap().exists(),
        "the created bridge directory must be rolled back"
    );
}

#[test]
fn install_overwrite_failure_restores_previous_module_and_config() {
    let h = Harness::new();
    // Simulate an upgrade/re-install over an already-working install: the module and
    // config already exist with known bytes (the module carries ELF magic).
    let old_module = b"\x7fELF-OLD-WORKING-MODULE-BYTES".to_vec();
    let old_config = b"bridge_path = \"/old/bridge.exe\"\nwin_mnt = \"/mnt/old\"\n".to_vec();
    write(&h.module_dir.join(MODULE_NAME), &old_module, MODULE_MODE);
    write(&h.paths.config_path(), &old_config, CONFIG_MODE);

    // Force a *later* step (provision_profile) to fail: its destination is a directory,
    // so the atomic write is refused.
    std::fs::create_dir_all(h.paths.profile_path()).unwrap();

    let err = h
        .run_install(
            &ScriptedPrompter::always(true),
            &MockEnroller::default(),
            &MockCommands::default(),
            &h.opts(),
        )
        .unwrap_err();
    assert!(format!("{err:#}").contains("profile"), "{err:#}");

    // The pre-existing artifacts must be restored byte-for-byte, not deleted.
    assert_eq!(
        std::fs::read(h.module_dir.join(MODULE_NAME)).unwrap(),
        old_module,
        "the previous module must be restored, not deleted"
    );
    assert_eq!(
        std::fs::read(h.paths.config_path()).unwrap(),
        old_config,
        "the previous config must be restored, not deleted"
    );
    // Files this run genuinely created before the failure are still rolled back.
    assert!(!h.bridge_dest().exists(), "new bridge must be rolled back");
}

// ---------------------------------------------------------------------------
// Legacy migration
// ---------------------------------------------------------------------------

fn install_legacy_fixture(h: &Harness) {
    write(&h.module_dir.join(LEGACY_MODULE_NAME), b"legacy so", 0o644);
    write(
        &h.paths.legacy_config_dir.join("config"),
        b"legacy config",
        0o600,
    );
    write(&h.paths.legacy_profile_path(), b"legacy profile", 0o644);
}

fn write_pam_d_file(h: &Harness, name: &str, body: &str) -> PathBuf {
    let path = h.paths.pam_d.join(name);
    write(&path, body.as_bytes(), 0o644);
    path
}

/// The timestamped `/etc/pam.d` backups migration leaves behind, sorted.
fn pam_d_backups(h: &Harness) -> Vec<PathBuf> {
    let mut backups: Vec<PathBuf> = std::fs::read_dir(&h.paths.pam_d)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().contains(fsutil::BACKUP_MARKER))
                .unwrap_or(false)
        })
        .collect();
    backups.sort();
    backups
}

#[test]
fn detect_legacy_finds_fixtures() {
    let h = Harness::new();
    install_legacy_fixture(&h);
    let legacy = detect_legacy(&h.paths);
    assert!(legacy.is_present());
    assert_eq!(legacy.modules, vec![h.module_dir.join(LEGACY_MODULE_NAME)]);
    assert_eq!(
        legacy.config_dir.as_deref(),
        Some(h.paths.legacy_config_dir.as_path())
    );
    assert_eq!(
        legacy.profile.as_deref(),
        Some(h.paths.legacy_profile_path().as_path())
    );
}

#[test]
fn detect_legacy_absent_is_empty() {
    let h = Harness::new();
    let legacy = detect_legacy(&h.paths);
    assert!(!legacy.is_present());
}

#[test]
fn migration_rewrites_pam_d_with_backup_and_is_idempotent() {
    let h = Harness::new();
    install_legacy_fixture(&h);
    let body = "auth required pam_unix.so\nauth sufficient pam_wsl_hello.so debug\nsession required pam_systemd.so\n";
    let pam_file = write_pam_d_file(&h, "common-auth", body);

    let commands = MockCommands {
        success: true,
        ..MockCommands::default()
    };
    // Answer yes to everything.
    let prompter = ScriptedPrompter::always(true);
    h.run_install(&prompter, &MockEnroller::default(), &commands, &h.opts())
        .unwrap();

    // The reference was rewritten, unrelated lines untouched.
    let rewritten = std::fs::read_to_string(&pam_file).unwrap();
    assert!(rewritten.contains("pam_wsl_webauthn.so"));
    assert!(!rewritten.contains("pam_wsl_hello"));
    assert!(rewritten.contains("auth required pam_unix.so"));
    assert!(rewritten.contains("session required pam_systemd.so"));
    // Mode preserved.
    assert_eq!(mode_of(&pam_file), 0o644);

    // A timestamped backup exists with the original bytes.
    let backups: Vec<PathBuf> = std::fs::read_dir(&h.paths.pam_d)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().contains(fsutil::BACKUP_MARKER))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(backups.len(), 1, "exactly one backup expected");
    assert_eq!(std::fs::read(&backups[0]).unwrap(), body.as_bytes());

    // pam-auth-update --remove wsl-hello was attempted.
    assert!(commands.calls.borrow().iter().any(|(p, a)| {
        p == "pam-auth-update" && a == &["--remove".to_string(), LEGACY_PROFILE_NAME.to_string()]
    }));

    // The legacy module and config dir were removed; the *new* module survives.
    assert!(!h.module_dir.join(LEGACY_MODULE_NAME).exists());
    assert!(!h.paths.legacy_config_dir.exists());
    assert!(h.module_dir.join(MODULE_NAME).exists());

    // Idempotent: a second install run finds no legacy refs and does not re-rewrite.
    let before = std::fs::read(&pam_file).unwrap();
    let commands2 = MockCommands::default();
    let legacy2 = detect_legacy(&h.paths);
    assert!(!legacy2.is_present(), "legacy artifacts should be gone");
    h.run_install(
        &ScriptedPrompter::always(true),
        &MockEnroller::default(),
        &commands2,
        &h.opts(),
    )
    .unwrap();
    assert_eq!(std::fs::read(&pam_file).unwrap(), before);
    // No additional backup.
    let backups2: Vec<PathBuf> = std::fs::read_dir(&h.paths.pam_d)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().contains(fsutil::BACKUP_MARKER))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(backups2.len(), 1);
}

#[test]
fn migration_rewrite_runs_before_legacy_module_removal() {
    let h = Harness::new();
    install_legacy_fixture(&h);
    write_pam_d_file(&h, "common-auth", "auth sufficient pam_wsl_hello.so\n");

    let commands = MockCommands {
        success: true,
        ..MockCommands::default()
    };
    let prompter = ScriptedPrompter::always(true);
    h.run_install(&prompter, &MockEnroller::default(), &commands, &h.opts())
        .unwrap();

    // The confirmation order must be: rewrite pam.d -> remove profile -> remove module.
    let questions = prompter.questions();
    let rewrite_idx = questions
        .iter()
        .position(|q| q.contains("Rewrite pam_wsl_hello"))
        .expect("rewrite question");
    let remove_idx = questions
        .iter()
        .position(|q| q.contains("Remove the legacy module"))
        .expect("module removal question");
    assert!(
        rewrite_idx < remove_idx,
        "pam.d must be rewritten before the old module is removed: {questions:?}"
    );
}

#[test]
fn migration_skips_symlinked_pam_d_file() {
    let h = Harness::new();
    install_legacy_fixture(&h);
    let outside = h._tmp.path().join("outside-pam");
    write(&outside, b"auth sufficient pam_wsl_hello.so\n", 0o644);
    symlink(&outside, h.paths.pam_d.join("common-auth")).unwrap();

    let prompter = ScriptedPrompter::always(true);
    h.run_install(
        &prompter,
        &MockEnroller::default(),
        &MockCommands::default(),
        &h.opts(),
    )
    .unwrap();

    // The real target was never edited.
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"auth sufficient pam_wsl_hello.so\n"
    );
    assert!(
        prompter
            .questions()
            .iter()
            .all(|q| !q.contains("Rewrite pam_wsl_hello")),
        "a symlinked pam.d file must not even be offered"
    );
}

#[test]
fn migration_declining_rewrite_leaves_file_unchanged() {
    let h = Harness::new();
    install_legacy_fixture(&h);
    let body = "auth sufficient pam_wsl_hello.so\n";
    let pam_file = write_pam_d_file(&h, "common-auth", body);

    // Decline every question.
    let prompter = ScriptedPrompter::always(false);
    h.run_install(
        &prompter,
        &MockEnroller::default(),
        &MockCommands::default(),
        &h.opts(),
    )
    .unwrap();
    assert_eq!(std::fs::read(&pam_file).unwrap(), body.as_bytes());
    // The legacy files remain (we declined).
    assert!(h.module_dir.join(LEGACY_MODULE_NAME).exists());
}

#[test]
fn migration_normalizes_unsafe_required_legacy_line() {
    let h = Harness::new();
    install_legacy_fixture(&h);
    // A legacy `required` control: a blind stem swap would gate sudo/su on Hello with no
    // password fallback.
    let pam_file = write_pam_d_file(&h, "sudo", "auth required pam_wsl_hello.so\n");

    let prompter = ScriptedPrompter::always(true);
    h.run_install(
        &prompter,
        &MockEnroller::default(),
        &MockCommands {
            success: true,
            ..MockCommands::default()
        },
        &h.opts(),
    )
    .unwrap();

    let rewritten = std::fs::read_to_string(&pam_file).unwrap();
    assert!(!rewritten.contains("pam_wsl_hello"), "{rewritten}");
    assert!(
        !rewritten.contains("auth required"),
        "the unsafe control must not be preserved: {rewritten}"
    );
    assert_eq!(
        rewritten,
        "auth [success=end default=ignore] pam_wsl_webauthn.so\n"
    );
    // The fail-safe normalization demanded an explicit second confirmation.
    assert!(
        prompter.questions().iter().any(|q| q.contains("fail-safe")),
        "expected a second confirmation about the unsafe control: {:?}",
        prompter.questions()
    );
}

#[test]
fn migration_keeps_sufficient_legacy_line_without_second_confirmation() {
    let h = Harness::new();
    install_legacy_fixture(&h);
    let pam_file = write_pam_d_file(&h, "sudo", "auth sufficient pam_wsl_hello.so\n");

    let prompter = ScriptedPrompter::always(true);
    h.run_install(
        &prompter,
        &MockEnroller::default(),
        &MockCommands {
            success: true,
            ..MockCommands::default()
        },
        &h.opts(),
    )
    .unwrap();

    // A sufficient control is already fail-safe: only the stem changes.
    assert_eq!(
        std::fs::read_to_string(&pam_file).unwrap(),
        "auth sufficient pam_wsl_webauthn.so\n"
    );
    assert!(
        prompter
            .questions()
            .iter()
            .all(|q| !q.contains("fail-safe")),
        "no normalization prompt expected for a safe control"
    );
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

#[test]
fn uninstall_user_removes_only_that_record() {
    let h = Harness::new();
    let store = Store::with_owner(&h.paths.etc_wsl_webauthn, h.paths.owner_uid);
    std::fs::create_dir_all(store.credentials_dir()).unwrap();
    std::fs::set_permissions(
        store.credentials_dir(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    for (user, uid) in [("alice", 1000u32), ("bob", 1001u32)] {
        write(
            &store.credentials_dir().join(format!("{user}.json")),
            sample_record_json(user, uid).as_bytes(),
            0o600,
        );
    }

    let prompter = ScriptedPrompter::always(true);
    let code = uninstall_user(&store, "alice", false, &prompter).unwrap();
    assert_eq!(code, EXIT_OK);

    assert!(matches!(
        store.load("alice"),
        Err(wsl_webauthn_store::StoreError::NotFound { .. })
    ));
    assert!(
        store.load("bob").is_ok(),
        "bob's record must survive (SR-20)"
    );
}

#[test]
fn uninstall_all_removes_provisioned_artifacts_but_not_legacy() {
    let h = Harness::new();
    // Provision a full install first.
    h.run_install(
        &ScriptedPrompter::always(true),
        &MockEnroller::default(),
        &MockCommands::default(),
        &h.opts(),
    )
    .unwrap();
    assert!(h.paths.config_path().exists());

    // Leave a legacy dir that uninstall must never touch.
    write(&h.paths.legacy_config_dir.join("config"), b"legacy", 0o600);
    // And a leftover pam.d reference to *our* module (must warn, never edit).
    let leftover = write_pam_d_file(&h, "leftover", "auth sufficient pam_wsl_webauthn.so\n");

    let interop = h.interop();
    let commands = MockCommands {
        success: true,
        ..MockCommands::default()
    };
    let opts = UninstallOptions {
        win_mnt: Some(h.win_mnt.clone()),
        module_dir: Some(h.module_dir.clone()),
        non_interactive: false,
    };
    let code = uninstall_all(
        &h.paths,
        &interop,
        &commands,
        &ScriptedPrompter::always(true),
        &opts,
    )
    .unwrap();
    assert_eq!(code, EXIT_OK);

    assert!(!h.paths.profile_path().exists(), "profile removed");
    assert!(!h.module_dir.join(MODULE_NAME).exists(), "module removed");
    assert!(!h.paths.etc_wsl_webauthn.exists(), "config dir removed");
    assert!(
        !h.bridge_dest().parent().unwrap().exists(),
        "bridge dir removed"
    );

    // Legacy untouched. A *bare* pam.d reference with no migration backup is still
    // warn-only on uninstall (the restore path is covered by
    // `uninstall_restores_rewritten_pam_d_from_backup`).
    assert!(h.paths.legacy_config_dir.exists(), "legacy must survive");
    assert!(pam_d_backups(&h).is_empty(), "no backup to restore here");
    assert!(leftover.exists());
    assert_eq!(
        std::fs::read(&leftover).unwrap(),
        b"auth sufficient pam_wsl_webauthn.so\n"
    );
}

#[test]
fn uninstall_restores_rewritten_pam_d_from_backup() {
    let h = Harness::new();
    install_legacy_fixture(&h);
    let body = "auth sufficient pam_unix.so\nauth sufficient pam_wsl_hello.so debug\n";
    let pam_file = write_pam_d_file(&h, "common-auth", body);

    // Install migrates `pam_wsl_hello` → `pam_wsl_webauthn` and leaves a backup.
    h.run_install(
        &ScriptedPrompter::always(true),
        &MockEnroller::default(),
        &MockCommands {
            success: true,
            ..MockCommands::default()
        },
        &h.opts(),
    )
    .unwrap();
    assert!(
        std::fs::read_to_string(&pam_file)
            .unwrap()
            .contains("pam_wsl_webauthn.so")
    );
    assert_eq!(pam_d_backups(&h).len(), 1, "one migration backup expected");

    // Uninstall restores the original before removing our module, then consumes the
    // backup (idempotent).
    let code = uninstall_all(
        &h.paths,
        &h.interop(),
        &MockCommands {
            success: true,
            ..MockCommands::default()
        },
        &ScriptedPrompter::always(true),
        &UninstallOptions {
            win_mnt: Some(h.win_mnt.clone()),
            module_dir: Some(h.module_dir.clone()),
            non_interactive: false,
        },
    )
    .unwrap();
    assert_eq!(code, EXIT_OK);
    assert_eq!(
        std::fs::read(&pam_file).unwrap(),
        body.as_bytes(),
        "the original pam_wsl_hello line must be restored"
    );
    assert!(pam_d_backups(&h).is_empty(), "backup must be consumed");
    assert!(
        !h.module_dir.join(MODULE_NAME).exists(),
        "our module must be removed"
    );
}

#[test]
fn uninstall_all_aborts_when_declined() {
    let h = Harness::new();
    h.run_install(
        &ScriptedPrompter::always(true),
        &MockEnroller::default(),
        &MockCommands::default(),
        &h.opts(),
    )
    .unwrap();
    let interop = h.interop();
    let code = uninstall_all(
        &h.paths,
        &interop,
        &MockCommands::default(),
        &ScriptedPrompter::always(false),
        &UninstallOptions {
            win_mnt: Some(h.win_mnt.clone()),
            module_dir: Some(h.module_dir.clone()),
            non_interactive: false,
        },
    )
    .unwrap();
    assert_eq!(code, EXIT_FAIL);
    assert!(h.paths.config_path().exists(), "nothing removed");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// A minimal valid credential record JSON for uninstall fixtures.
fn sample_record_json(user: &str, uid: u32) -> String {
    format!(
        r#"{{
            "schema_version": 1,
            "rp_id": "io.github.kirin-xiao.wsl-webauthn-pam",
            "origin": "io.github.kirin-xiao.wsl-webauthn-pam",
            "linux_user": "{user}",
            "linux_uid": {uid},
            "credential_id": "AAAA",
            "cose_public_key": "AAAA",
            "alg": -7,
            "aaguid": "9ddd1817-af5a-4672-a2b9-3e3dd95000a9",
            "attestation": {{"format":"packed","mode":"strict","verified":true,"leaf_sha256":null}},
            "windows_identity": null,
            "enrolled_at": "2026-10-01T00:00:00Z",
            "sign_count": 0,
            "bridge_path": "/mnt/c/bridge.exe",
            "bridge_sha256": "00"
        }}"#
    )
}
