//! Shared test machinery for the PAM module integration suite.
//!
//! Nothing here is compiled into the `.so`. It provides:
//!
//! * [`FakeSeam`] — an in-memory [`PamSeam`] that records messages and fail delays.
//! * [`TestDeps`] — a [`Deps`] implementation that can serve a real
//!   [`wsl_webauthn_store::Store`] (tempdir, `Store::with_owner`) or fixed replies,
//!   and drive the real runner against the `pam-test-fake-bridge` double.
//! * [`TestKey`]/[`AssertionBundle`] — a real ES256 keypair and the exact
//!   `clientDataJSON` + `authenticatorData` + signature bytes the verifier expects,
//!   so the success path is a genuine cryptographic assertion (no mocking the
//!   verifier).
//!
//! The fake bridge is scripted by *pre-building* the framed response bytes (including
//! the signature over the test's fixed challenge) and passing them via
//! `response=<b64url>`; the module's random source is pinned to the same challenge.

#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use p256::ecdsa::SigningKey as P256SigningKey;
use p256::ecdsa::signature::Signer as _;
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha256};

use wsl_webauthn_protocol::{ClientDataKind, Response, b64u_encode, build_client_data};
use wsl_webauthn_runner::{AssertParams, Runner, RunnerError, RunnerResponse};
use wsl_webauthn_store::{
    AttestationRecord, Config, CredentialRecord, MODE_STRICT, Store, StoreError, current_euid,
    validate_username,
};

use pam_wsl_webauthn::logic::Deps;
use pam_wsl_webauthn::seam::{PamSeam, SeamError};

// ---------------------------------------------------------------------------
// Minimal PAM ABI surface for the integration tests
// ---------------------------------------------------------------------------
//
// `pam_wsl_webauthn::bindings` is crate-private (L6-7), and these tests live in a
// separate crate, so they declare the handful of `pam_*` constants and types they
// need themselves — exactly as an out-of-tree consumer would. The values are
// pinned by the module's own `bindings.rs` layout tests; keeping the test copies
// here means the test does not depend on a widened production API.

/// `PAM_SUCCESS`.
pub const PAM_SUCCESS: std::ffi::c_int = 0;
/// `PAM_AUTH_ERR`.
pub const PAM_AUTH_ERR: std::ffi::c_int = 7;
/// `PAM_AUTHINFO_UNAVAIL`.
pub const PAM_AUTHINFO_UNAVAIL: std::ffi::c_int = 9;
/// `PAM_USER_UNKNOWN`.
pub const PAM_USER_UNKNOWN: std::ffi::c_int = 10;
/// `PAM_IGNORE`.
pub const PAM_IGNORE: std::ffi::c_int = 25;
/// `PAM_ABORT`.
pub const PAM_ABORT: std::ffi::c_int = 26;
/// `PAM_SILENT`.
pub const PAM_SILENT: std::ffi::c_int = 0x8000;
/// `PAM_TEXT_INFO` message style.
pub const PAM_TEXT_INFO: std::ffi::c_int = 4;

/// Opaque PAM handle (only ever passed through).
#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
}

/// Message passed to the application conversation function.
#[repr(C)]
pub struct pam_message {
    /// One of the `PAM_*_MSG` / prompt styles.
    pub msg_style: std::ffi::c_int,
    /// The message text (NUL-terminated).
    pub msg: *const std::ffi::c_char,
}

/// The application's reply to a [`pam_message`].
#[repr(C)]
pub struct pam_response {
    /// Reply text (NUL-terminated), or null when none is expected.
    pub resp: *mut std::ffi::c_char,
    /// Return code; unused (libpam convention).
    pub resp_retcode: std::ffi::c_int,
}

/// The application conversation function and its opaque application data.
#[repr(C)]
pub struct pam_conv {
    /// The callback libpam invokes to talk to the user.
    pub conv: Option<
        unsafe extern "C" fn(
            num_msg: std::ffi::c_int,
            msg: *mut *const pam_message,
            resp: *mut *mut pam_response,
            appdata_ptr: *mut std::ffi::c_void,
        ) -> std::ffi::c_int,
    >,
    /// Opaque pointer passed back to [`pam_conv::conv`].
    pub appdata_ptr: *mut std::ffi::c_void,
}

/// The `pam-test-fake-bridge` binary built alongside this test crate.
pub const FAKE_BRIDGE: &str = env!("CARGO_BIN_EXE_pam-test-fake-bridge");

// ---------------------------------------------------------------------------
// Fake PAM seam
// ---------------------------------------------------------------------------

/// An in-memory [`PamSeam`].
pub struct FakeSeam {
    /// What `pam_get_user` returns.
    pub user: Result<String, SeamError>,
    /// What `pam_get_item(PAM_SERVICE)` returns.
    pub service: Option<String>,
    /// What `conv_available` reports.
    pub conv_available: bool,
    /// What `conv_text` returns.
    pub conv_result: Result<(), SeamError>,
    /// Recorded `pam_fail_delay` requests, in order.
    pub fail_delays: Vec<u32>,
    /// Recorded conversation messages as `(style, text)`.
    pub messages: Vec<(i32, String)>,
}

impl FakeSeam {
    /// A seam for `user` with no conversation and an empty recorder.
    pub fn for_user(user: &str) -> FakeSeam {
        FakeSeam {
            user: Ok(user.to_string()),
            service: Some("sudo".to_string()),
            conv_available: false,
            conv_result: Ok(()),
            fail_delays: Vec::new(),
            messages: Vec::new(),
        }
    }

    /// Enable a working conversation that records messages.
    pub fn with_conv(mut self) -> FakeSeam {
        self.conv_available = true;
        self
    }
}

impl PamSeam for FakeSeam {
    fn get_user_name(&mut self) -> Result<String, SeamError> {
        self.user.clone()
    }
    fn get_service(&mut self) -> Option<String> {
        self.service.clone()
    }
    fn conv_available(&mut self) -> bool {
        self.conv_available
    }
    fn conv_text(&mut self, style: i32, text: &str) -> Result<(), SeamError> {
        self.messages.push((style, text.to_string()));
        self.conv_result.clone()
    }
    fn fail_delay(&mut self, usec: u32) {
        self.fail_delays.push(usec);
    }
}

// ---------------------------------------------------------------------------
// Scripted dependencies
// ---------------------------------------------------------------------------

/// How [`TestDeps::sha256_file`] behaves.
pub enum Sha256Behavior {
    /// Hash the real file through the production `O_NOFOLLOW` hasher.
    OfFile,
    /// Return this digest regardless of the file (a pin mismatch).
    Fixed([u8; 32]),
    /// Fail as if the file were unreadable.
    Err(String),
}

/// How [`TestDeps::bridge_path_is_trusted`] behaves.
pub enum TrustBehavior {
    /// Delegate to the production ownership/mode/symlink check.
    Real,
    /// Accept every path (the common in-test case: the fake bridge lives outside the
    /// tempdir/win_mnt and is not root-owned, so the production rule would refuse it).
    Trusted,
    /// Refuse every path (drives the untrusted-path mapping).
    Untrusted,
}

/// How the runner is driven.
pub struct RunnerBehavior {
    /// The bridge executable path.
    pub bridge: PathBuf,
    /// The child's `current_dir`.
    pub win_mnt: PathBuf,
    /// Arguments passed to the bridge.
    pub args: Vec<String>,
    /// Which transport behaviour to exercise.
    pub mode: RunnerMode,
}

/// Runner transport modes.
pub enum RunnerMode {
    /// Spawn the real `pam-test-fake-bridge` double.
    Real,
    /// Point at a nonexistent bridge (→ `RunnerError::BridgeMissing`).
    MissingBridge,
    /// Point the interop pre-flight at a nonexistent binfmt file
    /// (→ `RunnerError::InteropUnavailable`).
    InteropUnavailable,
}

/// A [`Deps`] bundle for tests.
pub struct TestDeps {
    /// When set, config and records come from this real store.
    pub store: Option<Store>,
    /// Fixed config reply (used when `store` is `None`).
    pub config: ConfigReply,
    /// Fixed record reply (used when `store` is `None`).
    pub record: RecordReply,
    /// Bridge-pin hashing behaviour.
    pub sha256: Sha256Behavior,
    /// Bridge-path trust behaviour.
    pub trust: TrustBehavior,
    /// Bytes returned by `fill_random` (copied, repeated if needed).
    pub random: [u8; 32],
    /// When set, `fill_random` reports an entropy failure instead of filling bytes
    /// (drives the `PAM_AUTHINFO_UNAVAIL` mapping without a real RNG failure).
    pub random_error: Option<String>,
    /// Runner behaviour.
    pub runner: RunnerBehavior,
    /// When true, `panic_probe` panics (drives the `PAM_ABORT` mapping).
    pub panic: bool,
    /// Cap on the runner deadline (keeps timeout tests fast).
    pub deadline_cap: Option<Duration>,
}

/// A fixed config reply.
pub enum ConfigReply {
    /// Return this config.
    Ok(Config),
    /// Return [`StoreError::ConfigMissing`].
    Missing,
    /// Return a generic [`StoreError::Config`].
    Other(String),
}

/// A fixed record reply.
pub enum RecordReply {
    /// Return this record.
    Ok(Box<CredentialRecord>),
    /// Return [`StoreError::NotFound`].
    NotFound,
    /// Return a generic [`StoreError::Io`].
    Other(String),
}

impl ConfigReply {
    fn resolve(&self) -> Result<Config, StoreError> {
        match self {
            ConfigReply::Ok(c) => Ok(c.clone()),
            ConfigReply::Missing => Err(StoreError::ConfigMissing {
                path: PathBuf::from("/etc/wsl_webauthn/config"),
            }),
            ConfigReply::Other(m) => Err(StoreError::Config {
                path: PathBuf::from("/etc/wsl_webauthn/config"),
                message: m.clone(),
            }),
        }
    }
}

impl RecordReply {
    fn resolve(&self) -> Result<CredentialRecord, StoreError> {
        match self {
            RecordReply::Ok(r) => Ok((**r).clone()),
            RecordReply::NotFound => Err(StoreError::NotFound {
                path: PathBuf::from("/etc/wsl_webauthn/credentials/user.json"),
            }),
            RecordReply::Other(m) => Err(StoreError::Io {
                path: PathBuf::from("/etc/wsl_webauthn/credentials/user.json"),
                source: std::io::Error::other(m.clone()),
            }),
        }
    }
}

impl Deps for TestDeps {
    fn load_config(&self) -> Result<Config, StoreError> {
        match &self.store {
            Some(s) => s.load_config(),
            None => self.config.resolve(),
        }
    }

    fn load_record(&self, username: &str) -> Result<CredentialRecord, StoreError> {
        match &self.store {
            Some(s) => s.load(username),
            None => self.record.resolve(),
        }
    }

    fn sha256_file(&self, path: &Path) -> Result<[u8; 32], String> {
        match &self.sha256 {
            Sha256Behavior::OfFile => hash_file(path),
            Sha256Behavior::Fixed(d) => Ok(*d),
            Sha256Behavior::Err(e) => Err(e.clone()),
        }
    }

    fn bridge_path_is_trusted(&self, path: &Path, win_mnt: &Path) -> Result<(), String> {
        match &self.trust {
            TrustBehavior::Real => pam_wsl_webauthn::logic::bridge_path_is_trusted(path, win_mnt),
            TrustBehavior::Trusted => Ok(()),
            TrustBehavior::Untrusted => Err("test-forced untrusted bridge path".to_string()),
        }
    }

    fn fill_random(&self, dest: &mut [u8]) -> Result<(), String> {
        if let Some(e) = &self.random_error {
            return Err(e.clone());
        }
        for (i, b) in dest.iter_mut().enumerate() {
            *b = self.random[i % self.random.len()];
        }
        Ok(())
    }

    fn authenticate(
        &self,
        bridge: &Path,
        win_mnt: &Path,
        params: AssertParams,
        deadline: Duration,
    ) -> Result<RunnerResponse, RunnerError> {
        let deadline = match self.deadline_cap {
            Some(cap) => cap.min(deadline),
            None => deadline,
        };
        let runner = match self.runner.mode {
            RunnerMode::Real => Runner::without_interop_check(bridge, win_mnt)
                .args(self.runner.args.clone())
                .taskkill_program("/bin/true"),
            RunnerMode::MissingBridge => {
                Runner::without_interop_check(win_mnt.join("no-such-bridge.exe"), win_mnt)
            }
            RunnerMode::InteropUnavailable => {
                Runner::with_interop_path(bridge, win_mnt, win_mnt.join("no-such-WSLInterop"))
            }
        };
        runner.authenticate(params, deadline)
    }

    fn panic_probe(&self) {
        assert!(!self.panic, "injected panic for PAM_ABORT coverage");
    }
}

/// SHA-256 a file, mirroring the hardened O_NOFOLLOW hasher used in production.
pub fn hash_file(path: &Path) -> Result<[u8; 32], String> {
    pam_wsl_webauthn::logic::sha256_file_nofollow(path)
}

// ---------------------------------------------------------------------------
// Real ES256 assertion construction
// ---------------------------------------------------------------------------

/// A P-256 signing key plus its COSE_Key encoding.
pub struct TestKey {
    /// The private key.
    pub signing: P256SigningKey,
    /// COSE_Key CBOR for the public key.
    pub cose: Vec<u8>,
}

/// Generate an ES256 test key.
pub fn es256_key() -> TestKey {
    let signing = P256SigningKey::random(&mut OsRng);
    let cose = cose_es256(&signing);
    TestKey { signing, cose }
}

fn cose_es256(sk: &P256SigningKey) -> Vec<u8> {
    use ciborium::value::Value;
    let point = sk.verifying_key().to_encoded_point(false);
    let map = vec![
        (Value::from(1i64), Value::from(2i64)),
        (Value::from(3i64), Value::from(-7i64)),
        (Value::from(-1i64), Value::from(1i64)),
        (
            Value::from(-2i64),
            Value::Bytes(point.x().expect("x").to_vec()),
        ),
        (
            Value::from(-3i64),
            Value::Bytes(point.y().expect("y").to_vec()),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).expect("cbor");
    out
}

/// The exact byte strings a successful assertion needs.
#[derive(Clone)]
pub struct AssertionBundle {
    /// The challenge (also fed to the module's `fill_random`).
    pub challenge: [u8; 32],
    /// The credential id.
    pub credential_id: Vec<u8>,
    /// The exact `clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// The `authenticatorData`.
    pub auth_data: Vec<u8>,
    /// The DER signature.
    pub signature: Vec<u8>,
}

/// Build a real assertion signed by `key` for `challenge`.
///
/// `rp_id` defaults to the pinned value via [`build_assertion`]; pass `"wrong.rp"`
/// to exercise the `rpIdHash` check.
pub fn build_assertion_with(
    key: &TestKey,
    challenge: [u8; 32],
    credential_id: &[u8],
    counter: u32,
    rp_id: &str,
    flags: u8,
) -> AssertionBundle {
    let client_data_json =
        build_client_data(ClientDataKind::Get, &challenge).expect("challenge length");
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    auth_data.push(flags);
    auth_data.extend_from_slice(&counter.to_be_bytes());

    let mut message = auth_data.clone();
    message.extend_from_slice(&Sha256::digest(&client_data_json));
    let sig: p256::ecdsa::DerSignature = key.signing.sign(&message);

    AssertionBundle {
        challenge,
        credential_id: credential_id.to_vec(),
        client_data_json,
        auth_data,
        signature: sig.as_bytes().to_vec(),
    }
}

/// A valid assertion (correct RP ID, UP+UV=1, counter 0).
pub fn build_assertion(
    key: &TestKey,
    challenge: [u8; 32],
    credential_id: &[u8],
) -> AssertionBundle {
    build_assertion_with(
        key,
        challenge,
        credential_id,
        0,
        wsl_webauthn_protocol::RP_ID,
        0x01 | 0x04,
    )
}

/// A fixed, recognisable 32-byte challenge.
pub fn fixed_challenge() -> [u8; 32] {
    let mut c = [0u8; 32];
    for (i, b) in c.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    c
}

/// Serialise a success response for `bundle`, optionally echoing `clientDataJSON`,
/// and return it as a `response=<b64url>` script argument for the fake bridge.
pub fn script_success(bundle: &AssertionBundle, echo: bool) -> String {
    let echo_value = echo.then(|| b64u_encode(&bundle.client_data_json));
    let response = Response::assertion(
        b64u_encode(&bundle.auth_data),
        b64u_encode(&bundle.signature),
        b64u_encode(&bundle.credential_id),
        echo_value,
    );
    script_response(&response)
}

/// Frame `response` and encode it as a `response=<b64url>` script argument.
pub fn script_response(response: &Response) -> String {
    let frame = response.to_frame().expect("response serializes");
    format!("response={}", b64u_encode(&frame))
}

/// A scripted **probe** response, to exercise an unexpected variant on the assert path.
pub fn script_probe() -> String {
    script_response(&Response::probe(true, 10))
}

/// A scripted **enroll** response, to exercise an unexpected variant on the assert path.
pub fn script_enroll() -> String {
    script_response(&Response::enroll("packed", "", ""))
}

// ---------------------------------------------------------------------------
// Record / config / store helpers
// ---------------------------------------------------------------------------

/// Lowercase hex of a 32-byte digest.
pub fn hex32(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// A bridge file with deterministic content, plus its SHA-256.
pub fn make_bridge_file(dir: &Path) -> (PathBuf, [u8; 32]) {
    let path = dir.join("WSLWebAuthnBridge.exe");
    std::fs::write(&path, b"pam test bridge executable\n").expect("write bridge");
    let digest = hash_file(&path).expect("hash bridge");
    (path, digest)
}

/// Build a credential record for `username` using `bundle` and `key`.
pub fn record_for(
    username: &str,
    bundle: &AssertionBundle,
    cose: &[u8],
    bridge_path: &Path,
    bridge_digest: &[u8; 32],
    sign_count: u32,
) -> CredentialRecord {
    CredentialRecord {
        schema_version: 1,
        rp_id: wsl_webauthn_protocol::RP_ID.to_string(),
        origin: wsl_webauthn_protocol::ORIGIN.to_string(),
        linux_user: username.to_string(),
        linux_uid: 1000,
        credential_id: b64u_encode(&bundle.credential_id),
        cose_public_key: b64u_encode(cose),
        alg: -7,
        aaguid: "08987058-cadc-4b81-b6e1-30de50dcbe96".to_string(),
        attestation: AttestationRecord {
            format: "packed".to_string(),
            mode: MODE_STRICT.to_string(),
            verified: true,
            leaf_sha256: None,
        },
        windows_identity: None,
        enrolled_at: "2026-10-01T00:00:00Z".to_string(),
        sign_count,
        bridge_path: bridge_path.to_string_lossy().into_owned(),
        bridge_sha256: hex32(bridge_digest),
    }
}

/// A config pointing at `bridge_path` in `win_mnt`.
pub fn config_for(bridge_path: &Path, win_mnt: &Path) -> Config {
    Config {
        bridge_path: bridge_path.to_path_buf(),
        win_mnt: win_mnt.to_path_buf(),
        timeout_secs: None,
    }
}

/// Write `config` as a mode-`0600` file in `store`'s base directory.
pub fn write_config(store: &Store, config: &Config) {
    let toml = format!(
        "bridge_path = {:?}\nwin_mnt = {:?}\n",
        config.bridge_path.to_string_lossy(),
        config.win_mnt.to_string_lossy()
    );
    let path = store.config_path();
    std::fs::write(&path, toml).expect("write config");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod config");
}

/// Open a tempdir-backed store owned by the current euid.
pub fn temp_store(dir: &Path) -> Store {
    let store = Store::with_owner(dir, current_euid());
    assert!(validate_username("alice").is_ok());
    store
}

/// Enroll `record` into a fresh tempdir store and write a matching config.
///
/// Returns the store; the caller keeps the [`tempfile::TempDir`] alive.
pub fn enrolled_store(dir: &Path, record: &CredentialRecord, config: &Config) -> Store {
    let store = temp_store(dir);
    store.save_atomic(record, false).expect("save record");
    write_config(&store, config);
    store
}

// ---------------------------------------------------------------------------
// Composed happy-path fixture
// ---------------------------------------------------------------------------

/// A ready-to-use happy-path fixture: a real ES256 key, the pinned challenge, the
/// signed assertion, a tempdir workspace, and the fake-bridge path.
pub struct Fixture {
    /// Tempdir holding the store and the script's working directory.
    pub tmp: tempfile::TempDir,
    /// The credential key.
    pub key: TestKey,
    /// The challenge the module's RNG will produce.
    pub challenge: [u8; 32],
    /// The credential id.
    pub credential_id: Vec<u8>,
    /// The signed assertion.
    pub bundle: AssertionBundle,
}

impl Fixture {
    /// Build a fixture with a random ES256 key and the fixed challenge.
    pub fn new() -> Fixture {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let key = es256_key();
        let challenge = fixed_challenge();
        let credential_id = b"pam-e2e-credential".to_vec();
        let bundle = build_assertion(&key, challenge, &credential_id);
        Fixture {
            tmp,
            key,
            challenge,
            credential_id,
            bundle,
        }
    }

    /// The `response=<b64url>` script argument for a success with/without echo.
    pub fn success_script(&self, echo: bool) -> String {
        script_success(&self.bundle, echo)
    }

    /// A credential record pointing at the fake bridge.
    pub fn record(&self, user: &str, sign_count: u32) -> CredentialRecord {
        let digest = hash_file(Path::new(FAKE_BRIDGE)).expect("hash fake bridge");
        record_for(
            user,
            &self.bundle,
            &self.key.cose,
            Path::new(FAKE_BRIDGE),
            &digest,
            sign_count,
        )
    }

    /// A config pointing at the fake bridge with `tmp` as the Windows mount.
    pub fn config(&self) -> Config {
        config_for(Path::new(FAKE_BRIDGE), self.tmp.path())
    }

    /// Enroll `record` into a tempdir-backed store with the matching config.
    pub fn enrolled_store(&self, record: &CredentialRecord) -> Store {
        enrolled_store(self.tmp.path(), record, &self.config())
    }

    /// Default dependencies that spawn the fake bridge with `args`.
    pub fn deps(&self, store: Store, args: Vec<String>) -> TestDeps {
        TestDeps {
            store: Some(store),
            config: ConfigReply::Missing,
            record: RecordReply::NotFound,
            sha256: Sha256Behavior::OfFile,
            trust: TrustBehavior::Trusted,
            random: self.challenge,
            random_error: None,
            runner: RunnerBehavior {
                bridge: PathBuf::from(FAKE_BRIDGE),
                win_mnt: self.tmp.path().to_path_buf(),
                args,
                mode: RunnerMode::Real,
            },
            panic: false,
            deadline_cap: Some(Duration::from_secs(5)),
        }
    }
}
