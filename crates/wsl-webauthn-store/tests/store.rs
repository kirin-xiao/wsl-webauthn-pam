//! Store integration tests (plan §6).
//!
//! These run as whatever uid the test process has: when run as root (CI) files are
//! root-owned and the production `Store::system` expectations hold; when run as a normal
//! user the store is constructed with `Store::with_owner(base, current_euid())`. This is
//! the parameterization the plan requires so the same suite passes in both environments.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use wsl_webauthn_store::{
    AttestationRecord, BASE_MODE, CONFIG_MODE, Config, CredentialRecord, DIR_MODE, FILE_MODE,
    MODE_STRICT, MODE_UNATTESTED_OPT_IN, Store, StoreError, WindowsIdentity, current_euid,
    validate_username,
};

/// Byte-for-byte golden encoding of [`sample_record("alice")`] (schema version 1).
///
/// The on-disk JSON strings are an API: the shared-enum follow-up for `attestation.mode`
/// (see `record.rs`) must not change them, so this literal pins the format.
const GOLDEN_STRICT_JSON: &str = r#"{"schema_version":1,"rp_id":"io.github.kirin-xiao.wsl-webauthn-pam","origin":"io.github.kirin-xiao.wsl-webauthn-pam","linux_user":"alice","linux_uid":1000,"credential_id":"Zm9vYmFy","cose_public_key":"AAECAw","alg":-7,"aaguid":"08987058-cadc-4b81-b6e1-30de50dcbe96","attestation":{"format":"packed","mode":"strict","verified":true,"leaf_sha256":"abababababababababababababababababababababababababababababababab"},"windows_identity":{"account":"HOST\\alice","sid":"S-1-5-21-1-2-3"},"enrolled_at":"2026-10-01T12:34:56Z","sign_count":0,"bridge_path":"/mnt/c/Users/alice/WSLWebAuthnBridge.exe","bridge_sha256":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}"#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn store_for(base: &Path) -> Store {
    Store::with_owner(base, current_euid())
}

fn fresh() -> (TempDir, Store) {
    let dir = TempDir::new().expect("tempdir");
    // tempfile creates base 0700; make it explicit and deterministic.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let store = store_for(dir.path());
    (dir, store)
}

fn sample_record(user: &str) -> CredentialRecord {
    CredentialRecord {
        schema_version: 1,
        rp_id: "io.github.kirin-xiao.wsl-webauthn-pam".into(),
        origin: "io.github.kirin-xiao.wsl-webauthn-pam".into(),
        linux_user: user.into(),
        linux_uid: 1000,
        credential_id: "Zm9vYmFy".into(),
        cose_public_key: "AAECAw".into(),
        alg: -7,
        aaguid: "08987058-cadc-4b81-b6e1-30de50dcbe96".into(),
        attestation: AttestationRecord {
            format: "packed".into(),
            mode: MODE_STRICT.into(),
            verified: true,
            leaf_sha256: Some("ab".repeat(32)),
        },
        windows_identity: Some(WindowsIdentity {
            account: "HOST\\alice".into(),
            sid: "S-1-5-21-1-2-3".into(),
        }),
        enrolled_at: "2026-10-01T12:34:56Z".into(),
        sign_count: 0,
        bridge_path: "/mnt/c/Users/alice/WSLWebAuthnBridge.exe".into(),
        bridge_sha256: "cd".repeat(32),
    }
}

/// Write a private file (0600, current owner) with raw bytes.
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn write_record_json(path: &Path, record: &CredentialRecord) {
    let bytes = serde_json::to_vec(record).unwrap();
    write_private(path, &bytes);
}

fn no_temp_files(dir: &Path) -> bool {
    fs::read_dir(dir).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".tmp-")
    })
}

// ---------------------------------------------------------------------------
// Username validation
// ---------------------------------------------------------------------------

#[test]
fn validate_username_accepts_normal_names() {
    for ok in ["alice", "bob_2", "_svc", "a", "A.B-c_d", &"a".repeat(32)] {
        assert!(validate_username(ok).is_ok(), "expected {ok:?} to be valid");
    }
}

#[test]
fn validate_username_rejects_bad_names() {
    for bad in [
        "",
        "../x",
        "a/b",
        "a\\b",
        "9lead",
        ".hidden",
        "-dash",
        "a b",
        "a\0b",
        "über",
        &"a".repeat(33),
        "a..b/../c",
    ] {
        assert!(
            matches!(validate_username(bad), Err(StoreError::InvalidUsername)),
            "expected {bad:?} to be rejected"
        );
    }
}

#[test]
fn load_rejects_invalid_username_before_touching_fs() {
    let (_d, store) = fresh();
    for bad in ["../x", "a/b", "", &"a".repeat(33), "9lead"] {
        assert!(matches!(store.load(bad), Err(StoreError::InvalidUsername)));
    }
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

#[test]
fn save_load_list_remove_round_trip() {
    let (_d, store) = fresh();
    let rec = sample_record("alice");

    store.save_atomic(&rec, false).expect("save");
    assert!(no_temp_files(&store.credentials_dir()));

    let loaded = store.load("alice").expect("load");
    assert_eq!(loaded, rec);

    assert_eq!(store.list().unwrap(), vec!["alice".to_string()]);

    // A second user, to exercise sorting.
    let mut bob = sample_record("bob");
    bob.linux_user = "bob".into();
    store.save_atomic(&bob, false).unwrap();
    assert_eq!(
        store.list().unwrap(),
        vec!["alice".to_string(), "bob".to_string()]
    );

    assert!(store.remove("alice").unwrap());
    assert!(!store.remove("alice").unwrap());
    assert!(store.load("alice").is_err());
    assert_eq!(store.list().unwrap(), vec!["bob".to_string()]);
}

#[test]
fn strict_record_json_is_byte_identical_to_golden() {
    // The on-disk JSON strings are an API (the verifier and PAM both parse them); pin the
    // exact bytes so the enum follow-up for `attestation.mode` cannot silently rename them.
    assert_eq!(
        serde_json::to_string(&sample_record("alice")).unwrap(),
        GOLDEN_STRICT_JSON
    );
}

#[test]
fn golden_json_round_trips_through_store() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&dir.join("alice.json"), GOLDEN_STRICT_JSON.as_bytes());
    assert_eq!(store.load("alice").unwrap(), sample_record("alice"));
}

#[test]
fn load_missing_record_is_not_found() {
    let (_d, store) = fresh();
    assert!(matches!(
        store.load("ghost"),
        Err(StoreError::NotFound { .. })
    ));
}

#[test]
fn save_twice_without_replace_is_already_exists() {
    let (_d, store) = fresh();
    let rec = sample_record("alice");
    store.save_atomic(&rec, false).unwrap();
    assert!(matches!(
        store.save_atomic(&rec, false),
        Err(StoreError::AlreadyExists { .. })
    ));
    assert!(no_temp_files(&store.credentials_dir()));
}

#[test]
fn save_with_replace_overwrites() {
    let (_d, store) = fresh();
    let mut rec = sample_record("alice");
    store.save_atomic(&rec, false).unwrap();
    rec.sign_count = 42;
    rec.alg = -257;
    store.save_atomic(&rec, true).expect("replace");
    let loaded = store.load("alice").unwrap();
    assert_eq!(loaded.sign_count, 42);
    assert_eq!(loaded.alg, -257);
    assert!(no_temp_files(&store.credentials_dir()));
}

#[test]
fn save_creates_credentials_dir_0700() {
    let (_d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    let meta = fs::metadata(store.credentials_dir()).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, DIR_MODE);
}

#[test]
fn save_writes_record_0600() {
    let (_d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    let meta = fs::metadata(store.credentials_dir().join("alice.json")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, FILE_MODE);
}

#[test]
fn save_rejects_invalid_record_user() {
    let (_d, store) = fresh();
    let mut rec = sample_record("alice");
    rec.linux_user = "../evil".into();
    assert!(matches!(
        store.save_atomic(&rec, false),
        Err(StoreError::InvalidUsername)
    ));
}

// ---------------------------------------------------------------------------
// Symlink hardening
// ---------------------------------------------------------------------------

#[test]
fn load_refuses_symlinked_record() {
    let (d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    let target = store.credentials_dir().join("alice.json");
    let other = d.path().join("other.json");
    write_private(&other, b"{}");
    fs::remove_file(&target).unwrap();
    symlink(&other, &target).unwrap();
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::SymlinkedPath { .. })
    ));
}

#[test]
fn load_refuses_symlinked_credentials_dir() {
    let (d, store) = fresh();
    let real = d.path().join("real-creds");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&real, store.credentials_dir()).unwrap();
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::SymlinkedPath { .. })
    ));
}

#[test]
fn save_refuses_symlinked_base() {
    let d = TempDir::new().unwrap();
    let real_base = d.path().join("real");
    fs::create_dir(&real_base).unwrap();
    let link_base = d.path().join("link");
    symlink(&real_base, &link_base).unwrap();
    let store = store_for(&link_base);
    assert!(matches!(
        store.save_atomic(&sample_record("alice"), false),
        Err(StoreError::SymlinkedPath { .. })
    ));
}

#[test]
fn remove_refuses_symlinked_record() {
    let (d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let other = d.path().join("other.json");
    write_private(&other, b"{}");
    symlink(&other, dir.join("alice.json")).unwrap();
    assert!(matches!(
        store.remove("alice"),
        Err(StoreError::SymlinkedPath { .. })
    ));
}

// ---------------------------------------------------------------------------
// Ownership / mode hardening
// ---------------------------------------------------------------------------

#[test]
fn load_rejects_wrong_base_owner() {
    let (d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    // Expect a uid that is definitely not ours (wrapping is fine); the base dir itself is
    // checked first, so this fails at the base rather than the record.
    let wrong = Store::with_owner(d.path(), current_euid().wrapping_add(1));
    assert!(matches!(
        wrong.load("alice"),
        Err(StoreError::InsecureBase { .. })
    ));
}

#[test]
fn group_writable_base_dir_is_refused() {
    let (d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    // No exact-mode requirement, but group/other-writable is refused on both paths.
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::InsecureBase { .. })
    ));
    assert!(matches!(
        store.save_atomic(&sample_record("bob"), false),
        Err(StoreError::InsecureBase { .. })
    ));
}

#[test]
fn other_writable_base_dir_is_refused() {
    let (d, store) = fresh();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o702)).unwrap();
    assert!(matches!(
        store.save_atomic(&sample_record("alice"), false),
        Err(StoreError::InsecureBase { .. })
    ));
}

#[test]
fn read_only_base_dir_is_allowed() {
    // A non-writable-but-owner-controlled base (e.g. 0755) is fine; only the
    // group/other *write* bits are the hazard.
    let (d, store) = fresh();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    assert_eq!(store.load("alice").unwrap().linux_user, "alice");
}

#[test]
fn insecure_base_is_refused_by_list_and_remove() {
    // `list`/`remove` do not re-check the `credentials` dir owner/mode, so the base
    // check is their only guard against a swapped-in attacker-controlled directory.
    let (d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(store.list(), Err(StoreError::InsecureBase { .. })));
    assert!(matches!(
        store.remove("alice"),
        Err(StoreError::InsecureBase { .. })
    ));
}

#[test]
fn missing_base_lists_empty_and_removes_nothing() {
    // A base that is absent is not an *insecure* base: preserve the prior behaviour of
    // treating it as "nothing enrolled" rather than erroring.
    let d = TempDir::new().unwrap();
    let missing = d.path().join("does-not-exist");
    let store = Store::with_owner(&missing, current_euid());
    assert!(store.list().unwrap().is_empty());
    assert!(!store.remove("alice").unwrap());
}

#[test]
fn load_rejects_bad_credentials_dir_mode() {
    let (_d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    fs::set_permissions(store.credentials_dir(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::BadOwnership { .. })
    ));
}

#[test]
fn load_rejects_bad_record_mode() {
    let (_d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    let path = store.credentials_dir().join("alice.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::BadOwnership { .. })
    ));
}

#[test]
fn save_refuses_existing_dir_with_bad_mode() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        store.save_atomic(&sample_record("alice"), false),
        Err(StoreError::BadOwnership { .. })
    ));
}

// ---------------------------------------------------------------------------
// Corrupt / oversized / mismatched content
// ---------------------------------------------------------------------------

#[test]
fn load_corrupt_json_is_corrupt() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&dir.join("alice.json"), b"{not json");
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn load_unsupported_schema_is_corrupt() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut rec = sample_record("alice");
    rec.schema_version = 2;
    write_record_json(&dir.join("alice.json"), &rec);
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn load_rejects_unknown_attestation_mode_as_corrupt() {
    // L16-7 = L6-6: a hand-edited `"mode"` must not load clean.
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut rec = sample_record("alice");
    rec.attestation.mode = "anything".into();
    write_record_json(&dir.join("alice.json"), &rec);
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn load_rejects_strict_record_that_is_not_verified() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut rec = sample_record("alice");
    rec.attestation.verified = false;
    write_record_json(&dir.join("alice.json"), &rec);
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn unattested_opt_in_round_trips_and_is_not_verified() {
    let (_d, store) = fresh();
    let mut rec = sample_record("alice");
    rec.attestation.mode = MODE_UNATTESTED_OPT_IN.into();
    rec.attestation.verified = false;
    store.save_atomic(&rec, false).expect("save");
    assert_eq!(store.load("alice").unwrap(), rec);
    // The serialized string keeps the stable `unattested-opt-in` spelling.
    let bytes = fs::read(store.credentials_dir().join("alice.json")).unwrap();
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("\"mode\":\"unattested-opt-in\"")
    );
}

#[test]
fn save_rejects_unknown_attestation_mode() {
    // The writer must refuse to persist a record the reader would reject.
    let (_d, store) = fresh();
    let mut rec = sample_record("alice");
    rec.attestation.mode = "bogus".into();
    assert!(store.save_atomic(&rec, false).is_err());
    assert!(!store.credentials_dir().join("alice.json").exists());
}

#[test]
fn load_record_user_mismatch_is_rejected() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    // File alice.json but linux_user says "bob".
    write_record_json(&dir.join("alice.json"), &sample_record("bob"));
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::RecordUserMismatch { .. })
    ));
}

#[test]
fn load_oversized_record_is_too_large() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&dir.join("alice.json"), &vec![b'x'; 256 * 1024 + 1]);
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::TooLarge { .. })
    ));
}

#[test]
fn load_records_with_malformed_b64url_are_corrupt() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

    let mut bad_cred = sample_record("alice");
    bad_cred.credential_id = "not*valid*b64url".into();
    write_record_json(&dir.join("alice.json"), &bad_cred);
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::Corrupt { .. })
    ));

    let mut bad_key = sample_record("alice");
    bad_key.cose_public_key = "====".into();
    write_record_json(&dir.join("alice.json"), &bad_key);
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn load_rejects_unknown_record_fields() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut value = serde_json::to_value(sample_record("alice")).unwrap();
    value["unexpected_provenance"] = serde_json::json!("x");
    write_private(&dir.join("alice.json"), value.to_string().as_bytes());
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn remove_refuses_directory_record() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(dir.join("alice.json")).unwrap();
    assert!(matches!(
        store.remove("alice"),
        Err(StoreError::NotRegularFile { .. })
    ));
}

#[test]
fn replace_over_symlinked_target_replaces_link_not_target() {
    let (d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let other = d.path().join("other.json");
    write_private(&other, b"sentinel");
    symlink(&other, dir.join("alice.json")).unwrap();

    store.save_atomic(&sample_record("alice"), true).unwrap();

    // rename replaces the symlink itself; the link target is untouched.
    let meta = fs::symlink_metadata(dir.join("alice.json")).unwrap();
    assert!(meta.file_type().is_file(), "must be a regular file now");
    assert_eq!(fs::read(&other).unwrap(), b"sentinel");
    assert_eq!(store.load("alice").unwrap().linux_user, "alice");
}

#[test]
fn load_directory_named_record_is_not_regular_file() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(dir.join("alice.json")).unwrap();
    assert!(matches!(
        store.load("alice"),
        Err(StoreError::NotRegularFile { .. })
    ));
}

// ---------------------------------------------------------------------------
// Atomicity / temp-file hygiene
// ---------------------------------------------------------------------------

#[test]
fn no_temp_files_after_successful_saves() {
    let (_d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    assert!(no_temp_files(&store.credentials_dir()));
    store.save_atomic(&sample_record("alice"), true).unwrap();
    assert!(no_temp_files(&store.credentials_dir()));
}

#[test]
fn no_temp_files_after_failed_install() {
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    // A directory sits where the record should go; `rename` over it fails *after* the
    // temp file has been created and fsynced.
    fs::create_dir(dir.join("alice.json")).unwrap();
    let err = store.save_atomic(&sample_record("alice"), true);
    assert!(err.is_err(), "rename over a directory must fail");
    assert!(
        no_temp_files(&dir),
        "temp file must be cleaned up on failure"
    );
}

#[test]
fn no_temp_files_after_already_exists_link_race() {
    // With replace=false the target appears after the pre-check by using link(2)'s
    // atomic EEXIST; simulate by pre-creating the target as a directory so `link`
    // fails, and confirm no temp survives.
    let (_d, store) = fresh();
    let dir = store.credentials_dir();
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(dir.join("alice.json")).unwrap();
    let err = store.save_atomic(&sample_record("alice"), false);
    assert!(err.is_err());
    assert!(no_temp_files(&dir));
}

#[test]
fn list_missing_dir_is_empty() {
    let (_d, store) = fresh();
    assert_eq!(store.list().unwrap(), Vec::<String>::new());
}

#[test]
fn list_skips_junk_entries() {
    let (_d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    let dir = store.credentials_dir();
    write_private(&dir.join("notjson.txt"), b"x");
    fs::create_dir(dir.join("subdir")).unwrap();
    // A .json whose stem is not a valid username is skipped.
    write_private(&dir.join("9bad.json"), b"{}");
    symlink(dir.join("alice.json"), dir.join("link.json")).unwrap();
    assert_eq!(store.list().unwrap(), vec!["alice".to_string()]);
}

#[test]
fn remove_on_missing_dir_is_false() {
    let (_d, store) = fresh();
    assert!(!store.remove("alice").unwrap());
}

// ---------------------------------------------------------------------------
// TOCTOU (best effort)
//
// A deterministic injection point between `lstat` and `open` is unavailable from a
// single-threaded test; instead we race a replacer against the reader and assert that
// every outcome is well-defined (a valid record or a typed error, never a panic and
// never a partially-read record).
// ---------------------------------------------------------------------------

#[test]
fn concurrent_replace_never_yields_torn_record() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (_d, store) = fresh();
    store.save_atomic(&sample_record("alice"), false).unwrap();
    let dir = store.credentials_dir();
    let target = dir.join("alice.json");

    let stop = Arc::new(AtomicBool::new(false));
    let replacer = {
        let stop = Arc::clone(&stop);
        let dir = dir.clone();
        std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let mut rec = sample_record("alice");
                rec.sign_count = n as u32;
                let tmp = dir.join(format!(".tmp-race-{n}"));
                fs::write(&tmp, serde_json::to_vec(&rec).unwrap()).unwrap();
                fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).unwrap();
                let _ = fs::rename(&tmp, &target);
                n += 1;
            }
        })
    };

    let reader_store = store_for(store.base());
    for _ in 0..2_000 {
        match reader_store.load("alice") {
            Ok(rec) => {
                assert_eq!(rec.linux_user, "alice");
                assert_eq!(rec.schema_version, 1);
            }
            // Any of these are legitimate race outcomes.
            Err(
                StoreError::NotFound { .. }
                | StoreError::PathChanged { .. }
                | StoreError::BadOwnership { .. }
                | StoreError::SymlinkedPath { .. }
                | StoreError::Corrupt { .. }
                | StoreError::Io { .. },
            ) => {}
            Err(other) => panic!("unexpected error under race: {other:?}"),
        }
    }
    stop.store(true, Ordering::Relaxed);
    replacer.join().unwrap();
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const VALID_CONFIG: &str = r#"
bridge_path = "/mnt/c/Users/alice/WSLWebAuthnBridge.exe"
win_mnt = "/mnt/c"
timeout_secs = 60
"#;

#[test]
fn config_round_trip() {
    let (_d, store) = fresh();
    write_private(&store.config_path(), VALID_CONFIG.as_bytes());
    let cfg = store.load_config().unwrap();
    assert_eq!(
        cfg.bridge_path,
        PathBuf::from("/mnt/c/Users/alice/WSLWebAuthnBridge.exe")
    );
    assert_eq!(cfg.win_mnt, PathBuf::from("/mnt/c"));
    assert_eq!(cfg.timeout_secs, Some(60));
}

#[test]
fn config_defaults_win_mnt_and_timeout() {
    let (_d, store) = fresh();
    write_private(
        &store.config_path(),
        b"bridge_path = \"/x/WSLWebAuthnBridge.exe\"\n",
    );
    let cfg = store.load_config().unwrap();
    assert_eq!(cfg.win_mnt, PathBuf::from("/mnt/c"));
    assert_eq!(cfg.timeout_secs, None);
}

#[test]
fn config_missing_is_error() {
    let (_d, store) = fresh();
    assert!(matches!(
        store.load_config(),
        Err(StoreError::ConfigMissing { .. })
    ));
}

#[test]
fn config_malformed_is_config_error() {
    let (_d, store) = fresh();
    write_private(&store.config_path(), b"bridge_path = [");
    assert!(matches!(
        store.load_config(),
        Err(StoreError::Config { .. })
    ));
}

#[test]
fn config_missing_required_field_is_error() {
    let (_d, store) = fresh();
    write_private(&store.config_path(), b"win_mnt = \"/mnt/c\"\n");
    assert!(matches!(
        store.load_config(),
        Err(StoreError::Config { .. })
    ));
}

#[test]
fn config_wrong_mode_is_bad_ownership() {
    let (_d, store) = fresh();
    write_private(&store.config_path(), VALID_CONFIG.as_bytes());
    fs::set_permissions(store.config_path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        store.load_config(),
        Err(StoreError::BadOwnership { .. })
    ));
}

#[test]
fn config_oversized_is_too_large() {
    let (_d, store) = fresh();
    write_private(&store.config_path(), &vec![b'#'; 64 * 1024 + 1]);
    assert!(matches!(
        store.load_config(),
        Err(StoreError::TooLarge { .. })
    ));
}

#[test]
fn config_is_symlink_refused() {
    let (d, store) = fresh();
    let other = d.path().join("real-config");
    write_private(&other, VALID_CONFIG.as_bytes());
    symlink(&other, store.config_path()).unwrap();
    assert!(matches!(
        store.load_config(),
        Err(StoreError::SymlinkedPath { .. })
    ));
}

// ---------------------------------------------------------------------------
// Config serialization / persistence (L7-4)
// ---------------------------------------------------------------------------

fn sample_config() -> Config {
    Config {
        bridge_path: PathBuf::from("/mnt/c/Users/alice/WSLWebAuthnBridge.exe"),
        win_mnt: PathBuf::from("/mnt/c"),
        timeout_secs: Some(60),
    }
}

#[test]
fn to_toml_matches_the_installer_shape() {
    // The historical installer emitted exactly this key order/format; the store-owned
    // serializer must stay byte-compatible for the handoff (L7-4).
    assert_eq!(
        sample_config().to_toml(),
        "bridge_path = \"/mnt/c/Users/alice/WSLWebAuthnBridge.exe\"\nwin_mnt = \"/mnt/c\"\ntimeout_secs = 60\n"
    );
}

#[test]
fn to_toml_omits_timeout_when_none() {
    let mut cfg = sample_config();
    cfg.timeout_secs = None;
    assert_eq!(
        cfg.to_toml(),
        "bridge_path = \"/mnt/c/Users/alice/WSLWebAuthnBridge.exe\"\nwin_mnt = \"/mnt/c\"\n"
    );
}

#[test]
fn to_toml_round_trips_paths_with_special_characters() {
    // `toml` may choose a literal (single-quoted) string for values containing `"`; the
    // parser accepts it, so only round-trip fidelity is required (not a fixed quoting).
    let (_d, store) = fresh();
    let mut cfg = sample_config();
    cfg.bridge_path = PathBuf::from("/mnt/c/a\"b\\c");
    write_private(&store.config_path(), cfg.to_toml().as_bytes());
    assert_eq!(store.load_config().unwrap(), cfg);
}

#[test]
fn to_toml_omits_win_mnt_default_but_round_trips_custom() {
    // `win_mnt` is always emitted (the installer always wrote it); its default value is
    // what the parser falls back to when absent.
    let mut cfg = sample_config();
    cfg.win_mnt = PathBuf::from("/mnt/d");
    let (_d, store) = fresh();
    write_private(&store.config_path(), cfg.to_toml().as_bytes());
    assert_eq!(store.load_config().unwrap(), cfg);

    write_private(
        &store.config_path(),
        b"bridge_path = \"/x/WSLWebAuthnBridge.exe\"\n",
    );
    assert_eq!(
        store.load_config().unwrap().win_mnt,
        PathBuf::from(Config::DEFAULT_WIN_MNT)
    );
}

#[test]
fn save_config_writes_0600_and_loads_back() {
    let (_d, store) = fresh();
    store.save_config(&sample_config()).expect("save_config");
    let meta = fs::metadata(store.config_path()).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, CONFIG_MODE);
    assert_eq!(store.load_config().unwrap(), sample_config());
    assert!(no_temp_files(store.base()));
}

#[test]
fn save_config_creates_missing_base() {
    // Only the final base component is created (the store does not `mkdir -p`); the
    // installer owns creating the parent (`/etc`), matching `ensure_credentials_dir`.
    let d = TempDir::new().unwrap();
    let missing = d.path().join("wsl_webauthn");
    let store = Store::with_owner(&missing, current_euid());
    store.save_config(&sample_config()).expect("save_config");
    let meta = fs::metadata(&missing).unwrap();
    assert_eq!(meta.permissions().mode() & 0o7777, BASE_MODE);
    assert_eq!(store.load_config().unwrap(), sample_config());
}

#[test]
fn save_config_replaces_existing() {
    let (_d, store) = fresh();
    write_private(&store.config_path(), VALID_CONFIG.as_bytes());
    let cfg = Config {
        bridge_path: PathBuf::from("/new/WSLWebAuthnBridge.exe"),
        win_mnt: PathBuf::from("/mnt/e"),
        timeout_secs: None,
    };
    store.save_config(&cfg).unwrap();
    assert_eq!(store.load_config().unwrap(), cfg);
    assert!(no_temp_files(store.base()));
}

#[test]
fn save_config_refuses_insecure_base() {
    // Pre-existing 0770 base: refused by the same check as every other store op, so the
    // config is never written into an attacker-writable directory.
    let (d, store) = fresh();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        store.save_config(&sample_config()),
        Err(StoreError::InsecureBase { .. })
    ));
    assert!(!store.config_path().exists());
}

#[test]
fn default_win_mnt_is_the_canonical_constant() {
    // L7-5 = L16-9: the CLI/installer must re-export this one constant.
    assert_eq!(Config::DEFAULT_WIN_MNT, "/mnt/c");
    let mut cfg = sample_config();
    cfg.win_mnt = PathBuf::from(Config::DEFAULT_WIN_MNT);
    let (_d, store) = fresh();
    write_private(&store.config_path(), cfg.to_toml().as_bytes());
    assert_eq!(
        store.load_config().unwrap().win_mnt,
        PathBuf::from("/mnt/c")
    );
}

// ---------------------------------------------------------------------------
// Paths / owner accessors
// ---------------------------------------------------------------------------

#[test]
fn system_store_uses_production_paths() {
    let store = Store::system();
    assert_eq!(store.base(), Path::new("/etc/wsl_webauthn"));
    assert_eq!(
        store.credentials_dir(),
        PathBuf::from("/etc/wsl_webauthn/credentials")
    );
    assert_eq!(
        store.config_path(),
        PathBuf::from("/etc/wsl_webauthn/config")
    );
    assert_eq!(store.owner_uid(), 0);
}

#[test]
fn kind_str_is_stable_distinct_and_non_identifying() {
    // L8-9: the PAM module logs `kind_str`, never `Display`, so no token may embed the
    // record path (the username leaf) and every variant needs a distinct stable token.
    let path = PathBuf::from("/etc/wsl_webauthn/credentials/alice.json");
    let cases: Vec<(StoreError, &str)> = vec![
        (StoreError::InvalidUsername, "invalid_username"),
        (StoreError::SymlinkedPath { path: path.clone() }, "symlink"),
        (
            StoreError::NotRegularFile { path: path.clone() },
            "not_regular_file",
        ),
        (
            StoreError::BadOwnership {
                path: path.clone(),
                expected_uid: 0,
                actual_uid: 1,
                expected_mode: FILE_MODE,
                actual_mode: 0o644,
            },
            "bad_ownership",
        ),
        (
            StoreError::InsecureBase {
                path: path.clone(),
                expected_uid: 0,
                actual_uid: 1,
                actual_mode: 0o777,
            },
            "insecure_base",
        ),
        (StoreError::NotFound { path: path.clone() }, "not_found"),
        (
            StoreError::AlreadyExists { path: path.clone() },
            "already_exists",
        ),
        (
            StoreError::Corrupt {
                path: path.clone(),
                message: "bad".into(),
            },
            "record_corrupt",
        ),
        (
            StoreError::TooLarge {
                path: path.clone(),
                cap: 1,
            },
            "too_large",
        ),
        (
            StoreError::PathChanged { path: path.clone() },
            "path_changed",
        ),
        (
            StoreError::RecordUserMismatch {
                record_user: "alice".into(),
                argument_user: "bob".into(),
            },
            "record_user_mismatch",
        ),
        (
            StoreError::ConfigMissing { path: path.clone() },
            "config_missing",
        ),
        (
            StoreError::Config {
                path: path.clone(),
                message: "bad".into(),
            },
            "config_invalid",
        ),
        (
            StoreError::Encode {
                message: "bad".into(),
            },
            "encode",
        ),
        (
            StoreError::Io {
                path: path.clone(),
                source: std::io::Error::other("bad"),
            },
            "io",
        ),
    ];
    for (err, expected) in &cases {
        assert_eq!(err.kind_str(), *expected, "{err:?}");
        assert!(!err.kind_str().contains("alice"), "{err:?}");
        assert!(!err.kind_str().contains('/'), "{err:?}");
    }
    let distinct: std::collections::BTreeSet<&str> =
        cases.iter().map(|(e, _)| e.kind_str()).collect();
    assert_eq!(distinct.len(), cases.len(), "tokens must be distinct");
}

#[test]
fn config_file_mode_constant_matches_plan() {
    assert_eq!(CONFIG_MODE, 0o600);
    assert_eq!(DIR_MODE, 0o700);
    assert_eq!(FILE_MODE, 0o600);
}
