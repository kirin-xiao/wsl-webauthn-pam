//! PAM module integration suite, driven end-to-end through the real runner against
//! the `pam-test-fake-bridge` double and the real verifier against genuine ES256
//! assertions.
//!
//! The success path is a *real* cryptographic assertion: the test generates a P-256 key,
//! signs `authenticatorData || SHA-256(clientDataJSON)`, enrolls the COSE key, and lets the
//! module verify it. No part of the verifier is mocked.

mod support;

use std::time::Duration;

use support::*;

use pam_wsl_webauthn::ModuleArgs;
use pam_wsl_webauthn::logic::{AuthOutcome, FAIL_DELAY_USEC, authenticate, run};
use pam_wsl_webauthn::seam::SeamError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_basic(seam: &mut FakeSeam, deps: &TestDeps, flags: i32, args: &[&str]) -> i32 {
    // An integration test links the library without `cfg(test)`, so the in-process
    // recorder must be opted into explicitly.
    install_capture();
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run(seam, deps, flags, &owned)
}

/// [`authenticate`] with the in-process audit recorder enabled.
fn authenticate_basic(seam: &mut FakeSeam, deps: &TestDeps) -> AuthOutcome {
    install_capture();
    authenticate(seam, deps, 0, &ModuleArgs::default())
}

/// A happy-path fixture with a random ES256 key, enrolled record and config.
fn happy() -> (Fixture, FakeSeam, TestDeps) {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let seam = FakeSeam::for_user("alice");
    let deps = fixture.deps(store, vec![fixture.success_script(false)]);
    (fixture, seam, deps)
}

// ---------------------------------------------------------------------------
// Success
// ---------------------------------------------------------------------------

#[test]
fn success_es256_without_echo() {
    let (_f, mut seam, deps) = happy();
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_SUCCESS);
    assert!(seam.fail_delays.is_empty(), "success must not fail-delay");
}

#[test]
fn success_es256_with_echo() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let deps = fixture.deps(store, vec![fixture.success_script(true)]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_SUCCESS);
}

#[test]
fn success_is_authenticated_under_pam_silent() {
    let (_f, mut seam, deps) = happy();
    assert_eq!(run_basic(&mut seam, &deps, PAM_SILENT, &[]), PAM_SUCCESS);
}

/// The module's audit lines go to the in-process recorder rather than `syslog(3)`, so this
/// cannot write synthetic events into the real auth journal. The captured success line is
/// the same text production logs.
#[test]
fn run_captures_audit_lines_without_touching_syslog() {
    use pam_wsl_webauthn::logger::{begin_capture, captured};

    let (_f, mut seam, deps) = happy();
    install_capture();
    begin_capture();
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_SUCCESS);
    let records = captured();
    assert!(
        records
            .iter()
            .any(|(_, msg)| msg.contains("authentication succeeded for user alice")),
        "the success audit line must be captured in-process: {records:?}"
    );
}

// ---------------------------------------------------------------------------
// Username → PAM_USER_UNKNOWN
// ---------------------------------------------------------------------------

#[test]
fn null_user_is_user_unknown() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    seam.user = Err(SeamError::NullUser);
    let deps = fixture.deps(store, vec![]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_USER_UNKNOWN);
}

#[test]
fn empty_user_is_user_unknown() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    seam.user = Ok(String::new());
    let deps = fixture.deps(store, vec![]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_USER_UNKNOWN);
}

#[test]
fn get_user_failure_is_user_unknown() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    seam.user = Err(SeamError::GetUser(19));
    let deps = fixture.deps(store, vec![]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_USER_UNKNOWN);
}

#[test]
fn invalid_username_is_user_unknown() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    seam.user = Ok("../../etc/passwd".to_string());
    let deps = fixture.deps(store, vec![]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_USER_UNKNOWN);
}

#[test]
fn no_record_is_user_unknown() {
    let fixture = Fixture::new();
    // Config present, record absent.
    let store = temp_store(fixture.tmp.path());
    let bridge_digest = hash_file(std::path::Path::new(FAKE_BRIDGE)).unwrap();
    let cfg_record = record_for(
        "alice",
        &fixture.bundle,
        &fixture.key.cose,
        std::path::Path::new(FAKE_BRIDGE),
        &bridge_digest,
        0,
    );
    let cfg = config_for(
        std::path::Path::new(cfg_record.bridge_path.as_str()),
        fixture.tmp.path(),
    );
    write_config(&store, &cfg);
    let mut seam = FakeSeam::for_user("alice");
    let deps = fixture.deps(store, vec![]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_USER_UNKNOWN);
}

// ---------------------------------------------------------------------------
// Config / store → PAM_AUTHINFO_UNAVAIL
// ---------------------------------------------------------------------------

#[test]
fn config_missing_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.store = None;
    deps.config = ConfigReply::Missing;
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

#[test]
fn config_invalid_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.store = None;
    deps.config = ConfigReply::Other("bad toml".to_string());
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

#[test]
fn store_error_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.store = None;
    deps.config = ConfigReply::Ok(dummy_config());
    deps.record = RecordReply::Other("io".to_string());
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

/// A store failure is logged by its stable *kind*, never the full `Display`. The
/// record path embeds the username, so the audit reason must not leak the leaf or the
/// `/etc/wsl_webauthn/...` layout into `authpriv`.
#[test]
fn corrupt_store_reason_is_kind_only_and_has_no_username_or_path() {
    let (_f, mut seam, mut deps) = happy();
    deps.store = None;
    deps.config = ConfigReply::Ok(dummy_config());
    deps.record = RecordReply::Corrupt(std::path::PathBuf::from(
        "/etc/wsl_webauthn/credentials/alice.json",
    ));
    let outcome = authenticate_basic(&mut seam, &deps);
    match outcome {
        AuthOutcome::Failure { code, reason } => {
            assert_eq!(code, PAM_AUTHINFO_UNAVAIL);
            assert!(
                reason.contains("record_corrupt"),
                "the stable kind must be present: {reason}"
            );
            assert!(!reason.contains("alice"), "username leaked: {reason}");
            assert!(!reason.contains(".json"), "path leaf leaked: {reason}");
            assert!(
                !reason.contains("/etc/wsl_webauthn"),
                "store layout leaked: {reason}"
            );
        }
        AuthOutcome::Success => panic!("a corrupt store must not authenticate"),
    }
}

#[test]
fn record_rp_id_mismatch_is_authinfo_unavail() {
    let fixture = Fixture::new();
    let mut record = fixture.record("alice", 0);
    // A record enrolled under a different RP ID can never satisfy this build.
    record.rp_id = "io.example.other".to_string();
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let deps = fixture.deps(store, vec![fixture.success_script(false)]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

/// A dummy config used only by reply-based tests.
fn dummy_config() -> wsl_webauthn_store::Config {
    config_for(
        std::path::Path::new("/mnt/c/WSLWebAuthnBridge.exe"),
        std::path::Path::new("/mnt/c"),
    )
}

// ---------------------------------------------------------------------------
// Bridge pin
// ---------------------------------------------------------------------------

#[test]
fn pin_mismatch_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.sha256 = Sha256Behavior::Fixed([0u8; 32]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

#[test]
fn pin_unreadable_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.sha256 = Sha256Behavior::Err("permission denied".to_string());
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

/// The pin cannot be disabled from the argument surface, and an untrusted
/// (group/other-writable or symlinked) bridge path is refused before the hash.
/// The production check is exercised against a tempdir it will accept.
#[test]
fn untrusted_bridge_path_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.trust = TrustBehavior::Untrusted;
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

/// A stray `noverifypin` token is an unknown argument: it must not re-enable a
/// pin-check bypass. With the pin intentionally mismatched, the run must still fail.
#[test]
fn noverifypin_token_no_longer_bypasses_a_pin_mismatch() {
    let (_f, mut seam, mut deps) = happy();
    deps.sha256 = Sha256Behavior::Fixed([0u8; 32]);
    assert_eq!(
        run_basic(&mut seam, &deps, 0, &["noverifypin"]),
        PAM_AUTHINFO_UNAVAIL
    );
}

/// The production trust check accepts a regular, non-symlinked bridge file inside a
/// root-owned win_mnt, and rejects a symlink at the bridge path.
#[test]
fn production_trust_check_accepts_regular_file_and_rejects_symlink() {
    use pam_wsl_webauthn::logic::bridge_path_is_trusted;
    let dir = tempfile::TempDir::new().expect("tempdir");
    let real = dir.path().join("Bridge.exe");
    std::fs::write(&real, b"exe").unwrap();
    assert!(
        bridge_path_is_trusted(&real, dir.path()).is_ok(),
        "a regular file under win_mnt is trusted by the production check"
    );

    let link = dir.path().join("Link.exe");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(
        bridge_path_is_trusted(&link, dir.path()).is_err(),
        "a symlinked bridge path must be refused"
    );

    // A group/other-writable regular file is refused on a non-DrvFs mount.
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(
        bridge_path_is_trusted(&real, dir.path()).is_err(),
        "a group/other-writable bridge must be refused"
    );
}

// ---------------------------------------------------------------------------
// Runner transport errors → PAM_AUTHINFO_UNAVAIL
// ---------------------------------------------------------------------------

#[test]
fn bridge_missing_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.runner.mode = RunnerMode::MissingBridge;
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

#[test]
fn interop_unavailable_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.runner.mode = RunnerMode::InteropUnavailable;
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

#[test]
fn timeout_is_authinfo_unavail() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let mut deps = fixture.deps(store, vec!["sleep=1000".to_string()]);
    deps.deadline_cap = Some(Duration::from_millis(200));
    let start = std::time::Instant::now();
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "timeout must fire promptly"
    );
}

#[test]
fn bridge_nonzero_exit_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.runner.args = vec!["exit=3".to_string()];
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

#[test]
fn transport_garbage_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.runner.args = vec!["garbage=1".to_string()];
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

#[test]
fn transport_empty_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.runner.args = vec!["empty=1".to_string()];
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

// ---------------------------------------------------------------------------
// Bridge ceremony taxonomy
// ---------------------------------------------------------------------------

#[test]
fn user_cancelled_is_auth_err() {
    let (_f, mut seam, mut deps) = happy();
    deps.runner.args = vec!["err=user_cancelled".to_string()];
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTH_ERR);
}

#[test]
fn other_bridge_errors_are_authinfo_unavail() {
    for taxonomy in [
        "not_available",
        "not_supported",
        "timeout",
        "busy",
        "invalid_parameter",
        "internal",
    ] {
        let (_f, mut seam, mut deps) = happy();
        deps.runner.args = vec![format!("err={taxonomy}")];
        assert_eq!(
            run_basic(&mut seam, &deps, 0, &[]),
            PAM_AUTHINFO_UNAVAIL,
            "taxonomy {taxonomy}"
        );
    }
}

// ---------------------------------------------------------------------------
// Verification failures → PAM_AUTH_ERR
// ---------------------------------------------------------------------------

#[test]
fn tampered_signature_is_auth_err() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let mut bundle = fixture.bundle.clone();
    bundle.signature[0] ^= 0xff;
    let deps = fixture.deps(store, vec![script_success(&bundle, false)]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTH_ERR);
}

#[test]
fn wrong_challenge_is_auth_err() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let mut deps = fixture.deps(store, vec![fixture.success_script(false)]);
    // The module mints a different challenge than the assertion signed over.
    deps.random = [0xABu8; 32];
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTH_ERR);
}

#[test]
fn bad_rpid_hash_is_auth_err() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let bundle = build_assertion_with(
        &fixture.key,
        fixture.challenge,
        &fixture.credential_id,
        0,
        "wrong.rp.id",
        0x01 | 0x04,
    );
    let deps = fixture.deps(store, vec![script_success(&bundle, false)]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTH_ERR);
}

#[test]
fn uv_zero_is_auth_err() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    // UP=1, UV=0.
    let mut bundle = fixture.bundle.clone();
    bundle.auth_data = build_assertion_with(
        &fixture.key,
        fixture.challenge,
        &fixture.credential_id,
        0,
        wsl_webauthn_protocol::RP_ID,
        0x01,
    )
    .auth_data;
    let deps = fixture.deps(store, vec![script_success(&bundle, false)]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTH_ERR);
}

#[test]
fn counter_regression_is_auth_err() {
    let fixture = Fixture::new();
    // Store says the counter was 5; the assertion reports 0 → clone signal.
    let record = fixture.record("alice", 5);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let deps = fixture.deps(store, vec![fixture.success_script(false)]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTH_ERR);
}

#[test]
fn echo_mismatch_is_auth_err() {
    use wsl_webauthn_protocol::{Response, b64u_encode};
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    // A well-signed assertion whose echo claims different clientDataJSON.
    let response = Response::assertion(
        b64u_encode(&fixture.bundle.auth_data),
        b64u_encode(&fixture.bundle.signature),
        b64u_encode(&fixture.credential_id),
        Some(b64u_encode(b"{\"type\":\"webauthn.get\"}")),
    );
    let deps = fixture.deps(store, vec![script_response(&response)]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTH_ERR);
}

#[test]
fn credential_id_mismatch_is_auth_err() {
    use wsl_webauthn_protocol::{Response, b64u_encode};
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let response = Response::assertion(
        b64u_encode(&fixture.bundle.auth_data),
        b64u_encode(&fixture.bundle.signature),
        b64u_encode(b"a-different-credential"),
        None,
    );
    let deps = fixture.deps(store, vec![script_response(&response)]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTH_ERR);
}

/// A `Probe`/`Enroll` response arriving where an `Assert` was requested is an
/// unexpected variant and must fail closed with `PAM_AUTH_ERR` — never authenticate.
#[test]
fn unexpected_response_variant_is_auth_err() {
    for script in [script_probe(), script_enroll()] {
        let (_f, mut seam, mut deps) = happy();
        deps.runner.args = vec![script.clone()];
        assert_eq!(
            run_basic(&mut seam, &deps, 0, &[]),
            PAM_AUTH_ERR,
            "script {script}"
        );
    }
}

/// A record with the correct `rp_id` but a mismatched `origin` is refused
/// before the bridge runs (defence in depth).
#[test]
fn record_origin_mismatch_is_authinfo_unavail() {
    let fixture = Fixture::new();
    let mut record = fixture.record("alice", 0);
    record.origin = "https://evil.example".to_string();
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let deps = fixture.deps(store, vec![fixture.success_script(false)]);
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTHINFO_UNAVAIL);
}

// ---------------------------------------------------------------------------
// Panic containment
// ---------------------------------------------------------------------------

#[test]
fn injected_panic_returns_pam_abort() {
    let (_f, mut seam, mut deps) = happy();
    deps.panic = true;
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_ABORT);
    assert!(
        seam.fail_delays.is_empty(),
        "a panic must not request a fail delay"
    );
}

// ---------------------------------------------------------------------------
// Entropy failure → PAM_AUTHINFO_UNAVAIL (not PAM_ABORT)
// ---------------------------------------------------------------------------

/// An entropy failure must be classified as an unavailable service, not a module
/// bug: the state machine returns the UNAVAIL outcome and does not panic.
#[test]
fn entropy_failure_outcome_is_authinfo_unavail() {
    let (_f, mut seam, mut deps) = happy();
    deps.random_error = Some("getrandom: no entropy".to_string());
    let outcome = authenticate_basic(&mut seam, &deps);
    match outcome {
        AuthOutcome::Failure { code, reason } => {
            assert_eq!(code, PAM_AUTHINFO_UNAVAIL);
            assert!(reason.contains("entropy"), "reason: {reason}");
        }
        AuthOutcome::Success => panic!("entropy failure must not authenticate"),
    }
}

/// Through [`run`], the entropy failure maps to `PAM_AUTHINFO_UNAVAIL`, requests the
/// standard fail delay, and never reaches the `PAM_ABORT` panic path.
#[test]
fn entropy_failure_returns_pam_authinfo_unavail_and_no_abort() {
    let (_f, mut seam, mut deps) = happy();
    deps.random_error = Some("getrandom: no entropy".to_string());
    let code = run_basic(&mut seam, &deps, 0, &[]);
    assert_eq!(code, PAM_AUTHINFO_UNAVAIL);
    assert_ne!(
        code, PAM_ABORT,
        "entropy failure must not abort the PAM stack"
    );
    assert_eq!(
        seam.fail_delays,
        vec![FAIL_DELAY_USEC],
        "an entropy failure is a normal failure path and must request the fail delay"
    );
}

// ---------------------------------------------------------------------------
// fail delay + conversation behaviour
// ---------------------------------------------------------------------------

#[test]
fn failure_requests_two_second_fail_delay() {
    let fixture = Fixture::new();
    let record = fixture.record("alice", 0);
    let store = fixture.enrolled_store(&record);
    let mut seam = FakeSeam::for_user("alice");
    let mut deps = fixture.deps(store, vec!["err=user_cancelled".to_string()]);
    deps.sha256 = Sha256Behavior::OfFile;
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_AUTH_ERR);
    assert_eq!(seam.fail_delays, vec![FAIL_DELAY_USEC]);
}

#[test]
fn conv_message_sent_when_not_silent() {
    let (_f, mut seam, deps) = happy();
    seam.conv_available = true;
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_SUCCESS);
    assert_eq!(seam.messages.len(), 1);
    let (style, text) = &seam.messages[0];
    assert_eq!(*style, PAM_TEXT_INFO);
    assert!(text.contains("sudo"), "{text}");
    assert!(text.contains("alice"), "{text}");
}

/// An action cue is emitted even under `PAM_SILENT` (as `sudo` passes) **when** the
/// transaction has a controlling terminal, so an interactive user learns the Windows
/// prompt is waiting.
#[test]
fn conv_message_sent_under_pam_silent_with_tty() {
    let (_f, mut seam, deps) = happy();
    seam.conv_available = true;
    seam.tty = true;
    assert_eq!(run_basic(&mut seam, &deps, PAM_SILENT, &[]), PAM_SUCCESS);
    assert_eq!(seam.messages.len(), 1);
    assert_eq!(seam.messages[0].0, PAM_TEXT_INFO);
}

/// Without a terminal (scripted/cron `sudo`), `PAM_SILENT` is honored and nothing is
/// emitted.
#[test]
fn conv_message_suppressed_under_pam_silent_without_tty() {
    let (_f, mut seam, deps) = happy();
    seam.conv_available = true;
    assert_eq!(run_basic(&mut seam, &deps, PAM_SILENT, &[]), PAM_SUCCESS);
    assert!(seam.messages.is_empty());
}

/// The `quiet` module argument forces silence everywhere, including an interactive
/// terminal without `PAM_SILENT`.
#[test]
fn conv_message_suppressed_by_quiet_argument() {
    let (_f, mut seam, deps) = happy();
    seam.conv_available = true;
    seam.tty = true;
    assert_eq!(run_basic(&mut seam, &deps, 0, &["quiet"]), PAM_SUCCESS);
    assert!(seam.messages.is_empty());
    assert_eq!(
        run_basic(&mut seam, &deps, PAM_SILENT, &["quiet"]),
        PAM_SUCCESS
    );
    assert!(seam.messages.is_empty());
}

/// A conversation is only emitted when the application installed one, regardless of
/// `PAM_SILENT`/tty.
#[test]
fn conv_message_needs_a_conversation() {
    let (_f, mut seam, deps) = happy();
    seam.conv_available = false;
    seam.tty = true;
    assert_eq!(run_basic(&mut seam, &deps, PAM_SILENT, &[]), PAM_SUCCESS);
    assert!(seam.messages.is_empty());
}

#[test]
fn conv_failure_is_nonfatal() {
    let (_f, mut seam, deps) = happy();
    seam.conv_available = true;
    seam.conv_result = Err(SeamError::Conv(19));
    assert_eq!(run_basic(&mut seam, &deps, 0, &[]), PAM_SUCCESS);
}

// ---------------------------------------------------------------------------
// Non-authentication export wrappers
// ---------------------------------------------------------------------------

#[test]
fn non_auth_exports_return_expected_codes() {
    use std::ptr;
    let null: *mut pam_wsl_webauthn::pam_handle_t = ptr::null_mut();
    let null_argv: *const *const std::ffi::c_char = ptr::null();
    assert_eq!(
        pam_wsl_webauthn::pam_sm_setcred(null, 0, 0, null_argv),
        PAM_SUCCESS
    );
    assert_eq!(
        pam_wsl_webauthn::pam_sm_acct_mgmt(null, 0, 0, null_argv),
        PAM_IGNORE
    );
    assert_eq!(
        pam_wsl_webauthn::pam_sm_open_session(null, 0, 0, null_argv),
        PAM_IGNORE
    );
    assert_eq!(
        pam_wsl_webauthn::pam_sm_close_session(null, 0, 0, null_argv),
        PAM_IGNORE
    );
    assert_eq!(
        pam_wsl_webauthn::pam_sm_chauthtok(null, 0, 0, null_argv),
        PAM_IGNORE
    );
}
