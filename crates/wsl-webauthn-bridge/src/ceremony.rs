//! Ceremony orchestration: wire request → platform options → framed response.
//! Platform-independent (no `unsafe`); driven through the
//! [`WebAuthnApi`] trait so it is fully unit-testable on Linux.
//!
//! The only platform coupling is the watchdog thread, which calls
//! [`WebAuthnApi::cancel`] after `timeout_ms` while the calling thread blocks
//! inside a ceremony. `WebAuthNAuthenticatorMakeCredential` /
//! `WebAuthNAuthenticatorGetAssertion` execute on the *calling* Win32 thread;
//! the hidden window created there is what gives Windows Hello a foreground
//! owner. All `unsafe` is confined to `crate::ffi`;
//! this module is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use wsl_webauthn_protocol::{BridgeError, RP_ID, RP_NAME, Request, Response};

use crate::api::{
    AssertionOptions, AttestationConveyance, AuthenticatorAttachment, CancellationId,
    MakeCredentialOptions, UvRequirement, WebAuthnApi,
};

/// Maximum WebAuthn user-handle length (`WEBAUTHN_MAX_USER_ID_LENGTH`).
pub const MAX_USER_ID_BYTES: usize = 64;

/// Options for one ceremony invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyOptions {
    /// Advisory platform timeout handed to `webauthn.dll` *and* used to arm
    /// the user-mode watchdog: the platform timeout is never trusted.
    pub timeout_ms: u32,
}

/// Build the enrollment options from a wire request.
///
/// All security-relevant values are fixed here and asserted by tests: user
/// verification `REQUIRED`, attestation `DIRECT`, attachment `PLATFORM`,
/// non-resident credential, RP = the pinned `protocol` constants, and an empty
/// exclude list (non-resident keys are discovered by the allow-list instead).
pub fn build_make_credential_options(
    req: &Request,
    cancellation_id: CancellationId,
) -> Result<MakeCredentialOptions, BridgeError> {
    let Request::Enroll {
        client_data_json,
        user_id,
        user_name,
        user_display_name,
        algs,
        timeout_ms,
    } = req
    else {
        return Err(BridgeError::InvalidParameter);
    };

    let user_id =
        wsl_webauthn_protocol::b64u_decode(user_id).map_err(|_| BridgeError::InvalidParameter)?;
    if user_id.is_empty() || user_id.len() > MAX_USER_ID_BYTES {
        return Err(BridgeError::InvalidParameter);
    }
    if algs.is_empty() {
        return Err(BridgeError::InvalidParameter);
    }
    let client_data_json = wsl_webauthn_protocol::b64u_decode(client_data_json)
        .map_err(|_| BridgeError::InvalidParameter)?;
    if client_data_json.is_empty() {
        return Err(BridgeError::InvalidParameter);
    }

    Ok(MakeCredentialOptions {
        rp_id: RP_ID.to_string(),
        rp_name: RP_NAME.to_string(),
        user_id,
        user_name: user_name.clone(),
        user_display_name: user_display_name.clone(),
        client_data_json,
        cose_algorithms: algs.clone(),
        timeout_ms: *timeout_ms,
        uv_requirement: UvRequirement::Required,
        attestation: AttestationConveyance::Direct,
        attachment: AuthenticatorAttachment::Platform,
        require_resident_key: false,
        cancellation_id,
    })
}

/// Build the assertion options from a wire request.
///
/// User verification `REQUIRED`, attachment `PLATFORM`, RP = the pinned
/// `protocol` constant, and the allow-list is exactly the request's credential
/// IDs.
pub fn build_assertion_options(
    req: &Request,
    cancellation_id: CancellationId,
) -> Result<AssertionOptions, BridgeError> {
    let Request::Assert {
        client_data_json,
        allow_credentials,
        timeout_ms,
    } = req
    else {
        return Err(BridgeError::InvalidParameter);
    };

    let client_data_json = wsl_webauthn_protocol::b64u_decode(client_data_json)
        .map_err(|_| BridgeError::InvalidParameter)?;
    if client_data_json.is_empty() {
        return Err(BridgeError::InvalidParameter);
    }
    if allow_credentials.is_empty() {
        return Err(BridgeError::InvalidParameter);
    }
    let mut ids = Vec::with_capacity(allow_credentials.len());
    for c in allow_credentials {
        let id =
            wsl_webauthn_protocol::b64u_decode(c).map_err(|_| BridgeError::InvalidParameter)?;
        if id.is_empty() {
            return Err(BridgeError::InvalidParameter);
        }
        ids.push(id);
    }

    Ok(AssertionOptions {
        rp_id: RP_ID.to_string(),
        client_data_json,
        allow_credential_ids: ids,
        timeout_ms: *timeout_ms,
        uv_requirement: UvRequirement::Required,
        attachment: AuthenticatorAttachment::Platform,
        cancellation_id,
    })
}

/// Watchdog that fires [`WebAuthnApi::cancel`] once after a delay.
///
/// The delay can be cut short via [`ArmedCancellation::finish`] so the normal
/// (fast) path does not pay the full timeout in `join()`.
struct ArmedCancellation {
    state: Arc<(Mutex<bool>, Condvar)>,
    /// Set **only** when the watchdog actually times out and fires
    /// [`WebAuthnApi::cancel`]. `finish()` marks `state` without touching this,
    /// so the flag distinguishes "our watchdog cancelled" from "the ceremony
    /// ended on its own". Snapshot with [`Self::fired`] *before* `finish`.
    fired: Arc<Mutex<bool>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ArmedCancellation {
    fn arm(api: &Arc<dyn WebAuthnApi>, id: CancellationId, timeout_ms: u32) -> Self {
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let fired = Arc::new(Mutex::new(false));
        let watchdog_state = Arc::clone(&state);
        let watchdog_fired = Arc::clone(&fired);
        let api = Arc::clone(api);

        let handle = thread::spawn(move || {
            let (lock, cvar) = &*watchdog_state;
            let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
            while !*done {
                let (guard, timeout) = cvar
                    .wait_timeout(done, Duration::from_millis(timeout_ms as u64))
                    .unwrap_or_else(|e| e.into_inner());
                done = guard;
                if timeout.timed_out() && !*done {
                    // Mark done so a concurrent `finish` cannot double-cancel.
                    *done = true;
                    // Publish "our watchdog fired" under the mutex *before*
                    // cancelling, so the ceremony thread observes it after the
                    // cancel-induced error returns (mutex gives the ordering).
                    *watchdog_fired.lock().unwrap_or_else(|e| e.into_inner()) = true;
                    drop(done);
                    api.cancel(&id);
                    return;
                }
            }
        });

        ArmedCancellation {
            state,
            fired,
            handle: Some(handle),
        }
    }

    /// Was the watchdog's timer what fired (i.e. did we call `cancel`)?
    ///
    /// Must be read *before* [`Self::finish`], which otherwise only stops the
    /// thread and does not imply the timer expired.
    fn fired(&self) -> bool {
        *self.fired.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Signal "ceremony over" and join the watchdog. Fast path: the watchdog
    /// wakes immediately instead of sleeping out the full timeout.
    fn finish(mut self) {
        {
            let (lock, cvar) = &*self.state;
            let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
            *done = true;
            cvar.notify_all();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Reclassify a ceremony error when *our* watchdog fired.
///
/// Windows returns `NTE_USER_CANCELLED` (`0x80090036`) to the ceremony when the
/// bridge's own `WebAuthNCancelCurrentOperation` fires, so a watchdog-induced
/// cancel is indistinguishable from a genuine user cancel at the HRESULT
/// level. The bridge reports `timeout` in that case, so:
///
/// * the error was already a [`BridgeError::Timeout`] → stays `Timeout`;
/// * the error mapped to [`BridgeError::UserCancelled`] **and** our watchdog
///   fired → `Timeout`;
/// * any *other* error, and every success, is returned untouched — a ceremony
///   that completes successfully while the watchdog is cancelling must never be
///   turned into an error.
///
/// `fired` is snapshotted after the ceremony returns and before `finish`.
fn remap_watchdog_fire<T>(result: Result<T, BridgeError>, fired: bool) -> Result<T, BridgeError> {
    match result {
        Err(BridgeError::UserCancelled | BridgeError::Timeout) if fired => {
            Err(BridgeError::Timeout)
        }
        other => other,
    }
}

/// Run a ceremony under a timed watchdog.
///
/// * `api.get_cancellation_id()` is fetched first; the exact id it returns is
///   the one the platform accepts for cancellation and the one handed to the
///   ceremony through its options.
/// * `run` executes the blocking platform call on the current thread.
/// * The watchdog's `fired` flag is snapshotted **after** `run` returns and
///   **before** the watchdog is disarmed; if our own cancel produced a
///   user-cancel-shaped error it is reclassified to `timeout`. A
///   successful result is never remapped.
/// * On completion (success *or* error) the watchdog is disarmed and joined,
///   so no thread outlives the ceremony.
fn run_with_watchdog<T, F>(
    api: &Arc<dyn WebAuthnApi>,
    options: &CeremonyOptions,
    run: F,
) -> Result<T, BridgeError>
where
    F: FnOnce(CancellationId) -> Result<T, BridgeError>,
{
    let id = api.get_cancellation_id()?;
    let watchdog = ArmedCancellation::arm(api, id, options.timeout_ms);
    let result = run(id);
    let watchdog_fired = watchdog.fired();
    watchdog.finish();
    remap_watchdog_fire(result, watchdog_fired)
}

/// Run an enrollment ceremony and build the wire response.
pub fn run_enroll(
    api: &Arc<dyn WebAuthnApi>,
    req: &Request,
    options: &CeremonyOptions,
) -> Response {
    match run_with_watchdog(api, options, |id| {
        let opts = build_make_credential_options(req, id)?;
        api.make_credential(&opts)
    }) {
        Ok(att) => Response::enroll(
            att.format,
            wsl_webauthn_protocol::b64u_encode(&att.attestation_object),
            wsl_webauthn_protocol::b64u_encode(&att.credential_id),
        ),
        Err(e) => Response::error(e),
    }
}

/// Run an assertion ceremony and build the wire response.
pub fn run_assert(
    api: &Arc<dyn WebAuthnApi>,
    req: &Request,
    options: &CeremonyOptions,
) -> Response {
    match run_with_watchdog(api, options, |id| {
        let opts = build_assertion_options(req, id)?;
        api.get_assertion(&opts)
    }) {
        Ok(res) => Response::assertion(
            wsl_webauthn_protocol::b64u_encode(&res.authenticator_data),
            wsl_webauthn_protocol::b64u_encode(&res.signature),
            wsl_webauthn_protocol::b64u_encode(&res.credential_id),
            res.client_data_json_echo
                .as_deref()
                .map(wsl_webauthn_protocol::b64u_encode),
        ),
        Err(e) => Response::error(e),
    }
}

/// Probe the platform and build the wire response.
///
/// A missing/old `webauthn.dll` surfaces as [`BridgeError::NotSupported`] from
/// the FFI layer and is reported here as a ceremony error. Probe has no
/// watchdog: `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable` does not
/// raise UI and the Linux side has its own transport deadline.
pub fn run_probe(api: &Arc<dyn WebAuthnApi>, _req: &Request) -> Response {
    match api.probe() {
        Ok(info) => Response::probe(info.uv_platform_available, info.api_version),
        Err(e) => Response::error(e),
    }
}

/// Run one ceremony for `req`.
///
/// The request has already been deserialized (so the operation is known-valid);
/// the returned [`Response`] is always written, even for ceremony failures.
pub fn dispatch(api: &Arc<dyn WebAuthnApi>, req: &Request) -> Response {
    match req {
        Request::Probe { timeout_ms } => {
            let _ = timeout_ms;
            run_probe(api, req)
        }
        Request::Enroll { timeout_ms, .. } => run_enroll(
            api,
            req,
            &CeremonyOptions {
                timeout_ms: *timeout_ms,
            },
        ),
        Request::Assert { timeout_ms, .. } => run_assert(
            api,
            req,
            &CeremonyOptions {
                timeout_ms: *timeout_ms,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        AssertionResult, CredentialAttestation, ERROR_TIMEOUT, Hresult, NTE_USER_CANCELLED,
        ProbeInfo, hresult_from_win32, map_hresult,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // ---- scriptable stub ------------------------------------------------

    struct StubApi {
        probe: Result<ProbeInfo, BridgeError>,
        make: Result<CredentialAttestation, BridgeError>,
        assert: Result<AssertionResult, BridgeError>,
        /// When set, both ceremonies return `Err(map_hresult(hr))` immediately
        /// (models a real platform HRESULT with the watchdog *not* fired).
        immediate_error: Option<Hresult>,
        /// When true, both ceremonies spin until `cancel` flips `saw_cancel`.
        block_until_cancel: bool,
        /// Error the simulated platform returns once it observes our cancel.
        /// `None` models a ceremony that completes successfully despite the
        /// watchdog having cancelled (the race the remap must not corrupt).
        unblocked_error: Option<Hresult>,
        cancel_count: AtomicUsize,
        saw_cancel: AtomicBool,
        last_make: Mutex<Option<MakeCredentialOptions>>,
        last_assert: Mutex<Option<AssertionOptions>>,
    }

    impl StubApi {
        fn new() -> Self {
            StubApi {
                probe: Ok(ProbeInfo {
                    uv_platform_available: true,
                    api_version: 9,
                }),
                make: Ok(CredentialAttestation {
                    format: "packed".into(),
                    attestation_object: vec![1, 2, 3],
                    credential_id: vec![9, 9],
                }),
                assert: Ok(AssertionResult {
                    authenticator_data: vec![4, 5],
                    signature: vec![6, 7],
                    credential_id: vec![9, 9],
                    client_data_json_echo: Some(vec![8]),
                }),
                immediate_error: None,
                block_until_cancel: false,
                unblocked_error: None,
                cancel_count: AtomicUsize::new(0),
                saw_cancel: AtomicBool::new(false),
                last_make: Mutex::new(None),
                last_assert: Mutex::new(None),
            }
        }

        /// A stub whose ceremony blocks until the watchdog cancels, then
        /// reports `ERROR_TIMEOUT` (the platform-timeout shape).
        fn blocking() -> Self {
            StubApi {
                block_until_cancel: true,
                unblocked_error: Some(hresult_from_win32(ERROR_TIMEOUT)),
                ..StubApi::new()
            }
        }

        /// A stub whose ceremony blocks until the watchdog cancels, then
        /// reports `NTE_USER_CANCELLED` — Windows' behavior
        /// when *our* `WebAuthNCancelCurrentOperation` fires.
        fn blocking_user_cancelled() -> Self {
            StubApi {
                block_until_cancel: true,
                unblocked_error: Some(NTE_USER_CANCELLED),
                ..StubApi::new()
            }
        }

        /// A stub whose ceremony blocks until the watchdog cancels, then
        /// nonetheless succeeds (cancel raced a completing ceremony).
        fn succeed_after_cancel() -> Self {
            StubApi {
                block_until_cancel: true,
                unblocked_error: None,
                ..StubApi::new()
            }
        }

        /// Block until the watchdog cancels (bounded), then return the
        /// simulated platform error. Returns `Internal` if the watchdog never
        /// fired, which fails the tests.
        fn ceremony<T: Clone>(&self, scripted: &Result<T, BridgeError>) -> Result<T, BridgeError> {
            if let Some(hr) = self.immediate_error {
                return Err(map_hresult(hr));
            }
            if self.block_until_cancel {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !self.saw_cancel.load(Ordering::SeqCst) {
                    if std::time::Instant::now() > deadline {
                        return Err(BridgeError::Internal);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                return match self.unblocked_error {
                    Some(hr) => Err(map_hresult(hr)),
                    // Cancel raced a successful completion: report success.
                    None => scripted.clone(),
                };
            }
            scripted.clone()
        }
    }

    impl WebAuthnApi for StubApi {
        fn probe(&self) -> Result<ProbeInfo, BridgeError> {
            self.probe
        }
        fn get_cancellation_id(&self) -> Result<CancellationId, BridgeError> {
            Ok(CancellationId([0x11; 16]))
        }
        fn make_credential(
            &self,
            options: &MakeCredentialOptions,
        ) -> Result<CredentialAttestation, BridgeError> {
            *self.last_make.lock().unwrap_or_else(|e| e.into_inner()) = Some(options.clone());
            self.ceremony(&self.make)
        }
        fn get_assertion(
            &self,
            options: &AssertionOptions,
        ) -> Result<AssertionResult, BridgeError> {
            *self.last_assert.lock().unwrap_or_else(|e| e.into_inner()) = Some(options.clone());
            self.ceremony(&self.assert)
        }
        fn cancel(&self, _id: &CancellationId) {
            self.cancel_count.fetch_add(1, Ordering::SeqCst);
            self.saw_cancel.store(true, Ordering::SeqCst);
        }
    }

    fn enroll_request(timeout_ms: u32) -> Request {
        Request::Enroll {
            client_data_json: wsl_webauthn_protocol::b64u_encode(b"{\"x\":1}"),
            user_id: wsl_webauthn_protocol::b64u_encode(b"alice-id"),
            user_name: "alice".into(),
            user_display_name: "alice (Linux sudo)".into(),
            algs: vec![-7, -257],
            timeout_ms,
        }
    }

    fn assert_request(timeout_ms: u32) -> Request {
        Request::Assert {
            client_data_json: wsl_webauthn_protocol::b64u_encode(b"{\"x\":2}"),
            allow_credentials: vec![
                wsl_webauthn_protocol::b64u_encode(b"cred-1"),
                wsl_webauthn_protocol::b64u_encode(b"cred-2"),
            ],
            timeout_ms,
        }
    }

    // ---- option construction -------------------------------------------

    #[test]
    fn enroll_options_are_pinned_per_plan() {
        let req = enroll_request(55_000);
        let opts = build_make_credential_options(&req, CancellationId([0xaa; 16])).unwrap();
        assert_eq!(opts.rp_id, RP_ID);
        assert_eq!(opts.rp_name, RP_NAME);
        assert_eq!(opts.user_id, b"alice-id");
        assert_eq!(opts.user_name, "alice");
        assert_eq!(opts.user_display_name, "alice (Linux sudo)");
        assert_eq!(opts.client_data_json, b"{\"x\":1}");
        assert_eq!(opts.cose_algorithms, vec![-7, -257]);
        assert_eq!(opts.timeout_ms, 55_000);
        assert_eq!(opts.uv_requirement, UvRequirement::Required);
        assert_eq!(opts.attestation, AttestationConveyance::Direct);
        assert_eq!(opts.attachment, AuthenticatorAttachment::Platform);
        assert!(!opts.require_resident_key);
        assert_eq!(opts.cancellation_id, CancellationId([0xaa; 16]));
    }

    #[test]
    fn assert_options_are_pinned_per_plan() {
        let req = assert_request(55_000);
        let opts = build_assertion_options(&req, CancellationId([0xbb; 16])).unwrap();
        assert_eq!(opts.rp_id, RP_ID);
        assert_eq!(opts.client_data_json, b"{\"x\":2}");
        assert_eq!(
            opts.allow_credential_ids,
            vec![b"cred-1".to_vec(), b"cred-2".to_vec()]
        );
        assert_eq!(opts.timeout_ms, 55_000);
        assert_eq!(opts.uv_requirement, UvRequirement::Required);
        assert_eq!(opts.attachment, AuthenticatorAttachment::Platform);
        assert_eq!(opts.cancellation_id, CancellationId([0xbb; 16]));
    }

    #[test]
    fn option_builders_reject_wrong_op_and_bad_input() {
        assert_eq!(
            build_make_credential_options(&assert_request(1), CancellationId([0; 16])),
            Err(BridgeError::InvalidParameter)
        );
        assert_eq!(
            build_assertion_options(&enroll_request(1), CancellationId([0; 16])),
            Err(BridgeError::InvalidParameter)
        );

        let mut bad = enroll_request(1);
        if let Request::Enroll { user_id, .. } = &mut bad {
            *user_id = "!!!notb64!!!".into();
        }
        assert_eq!(
            build_make_credential_options(&bad, CancellationId([0; 16])),
            Err(BridgeError::InvalidParameter)
        );

        let mut bad = enroll_request(1);
        if let Request::Enroll { algs, .. } = &mut bad {
            algs.clear();
        }
        assert_eq!(
            build_make_credential_options(&bad, CancellationId([0; 16])),
            Err(BridgeError::InvalidParameter)
        );

        let mut bad = enroll_request(1);
        if let Request::Enroll { user_id, .. } = &mut bad {
            *user_id = wsl_webauthn_protocol::b64u_encode(&[0u8; MAX_USER_ID_BYTES + 1]);
        }
        assert_eq!(
            build_make_credential_options(&bad, CancellationId([0; 16])),
            Err(BridgeError::InvalidParameter)
        );

        let mut bad = assert_request(1);
        if let Request::Assert {
            allow_credentials, ..
        } = &mut bad
        {
            allow_credentials.clear();
        }
        assert_eq!(
            build_assertion_options(&bad, CancellationId([0; 16])),
            Err(BridgeError::InvalidParameter)
        );

        let mut bad = assert_request(1);
        if let Request::Assert {
            allow_credentials, ..
        } = &mut bad
        {
            allow_credentials[0] = "!!!!".into();
        }
        assert_eq!(
            build_assertion_options(&bad, CancellationId([0; 16])),
            Err(BridgeError::InvalidParameter)
        );
    }

    // ---- ceremony paths -------------------------------------------------

    #[test]
    fn enroll_happy_path_builds_response_and_passes_options() {
        let stub = Arc::new(StubApi::new());
        let api: Arc<dyn WebAuthnApi> = stub.clone();
        let resp = dispatch(&api, &enroll_request(55_000));
        match resp {
            Response::Enroll {
                format,
                attestation_object,
                credential_id,
                ..
            } => {
                assert_eq!(format, "packed");
                assert_eq!(
                    attestation_object,
                    wsl_webauthn_protocol::b64u_encode(&[1, 2, 3])
                );
                assert_eq!(credential_id, wsl_webauthn_protocol::b64u_encode(&[9, 9]));
            }
            other => panic!("unexpected response {other:?}"),
        }
        let seen = stub.last_make.lock().unwrap().clone().unwrap();
        assert_eq!(seen.uv_requirement, UvRequirement::Required);
        assert_eq!(seen.attestation, AttestationConveyance::Direct);
        assert_eq!(seen.attachment, AuthenticatorAttachment::Platform);
    }

    #[test]
    fn assert_happy_path_builds_response_with_echo() {
        let api: Arc<dyn WebAuthnApi> = Arc::new(StubApi::new());
        let resp = dispatch(&api, &assert_request(55_000));
        match resp {
            Response::Assert {
                authenticator_data,
                signature,
                credential_id,
                client_data_json_echo,
                ..
            } => {
                assert_eq!(
                    authenticator_data,
                    wsl_webauthn_protocol::b64u_encode(&[4, 5])
                );
                assert_eq!(signature, wsl_webauthn_protocol::b64u_encode(&[6, 7]));
                assert_eq!(credential_id, wsl_webauthn_protocol::b64u_encode(&[9, 9]));
                assert_eq!(
                    client_data_json_echo,
                    Some(wsl_webauthn_protocol::b64u_encode(&[8]))
                );
            }
            other => panic!("unexpected response {other:?}"),
        }
    }

    #[test]
    fn probe_ok_and_not_supported() {
        let api: Arc<dyn WebAuthnApi> = Arc::new(StubApi::new());
        assert_eq!(
            dispatch(&api, &Request::Probe { timeout_ms: 3000 }),
            Response::probe(true, 9)
        );

        struct Missing;
        impl WebAuthnApi for Missing {
            fn probe(&self) -> Result<ProbeInfo, BridgeError> {
                Err(BridgeError::NotSupported)
            }
            fn get_cancellation_id(&self) -> Result<CancellationId, BridgeError> {
                Err(BridgeError::NotSupported)
            }
            fn make_credential(
                &self,
                _o: &MakeCredentialOptions,
            ) -> Result<CredentialAttestation, BridgeError> {
                Err(BridgeError::NotSupported)
            }
            fn get_assertion(&self, _o: &AssertionOptions) -> Result<AssertionResult, BridgeError> {
                Err(BridgeError::NotSupported)
            }
            fn cancel(&self, _id: &CancellationId) {}
        }
        let api: Arc<dyn WebAuthnApi> = Arc::new(Missing);
        assert_eq!(
            dispatch(&api, &Request::Probe { timeout_ms: 3000 }),
            Response::error(BridgeError::NotSupported)
        );
    }

    #[test]
    fn ceremony_error_is_mapped_to_error_response() {
        let mut stub = StubApi::new();
        stub.make = Err(BridgeError::UserCancelled);
        let api: Arc<dyn WebAuthnApi> = Arc::new(stub);
        assert_eq!(
            dispatch(&api, &enroll_request(1)),
            Response::error(BridgeError::UserCancelled)
        );
    }

    #[test]
    fn assert_without_echo_serializes_null() {
        let mut stub = StubApi::new();
        stub.assert = Ok(AssertionResult {
            authenticator_data: vec![1],
            signature: vec![2],
            credential_id: vec![3],
            client_data_json_echo: None,
        });
        let api: Arc<dyn WebAuthnApi> = Arc::new(stub);
        let resp = dispatch(&api, &assert_request(1));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""client_data_json_echo":null"#), "{json}");
    }

    // ---- watchdog -------------------------------------------------------

    #[test]
    fn watchdog_cancels_blocked_ceremony() {
        let api: Arc<dyn WebAuthnApi> = Arc::new(StubApi::blocking());
        let start = std::time::Instant::now();
        let resp = dispatch(&api, &assert_request(50));
        let elapsed = start.elapsed();

        assert_eq!(resp, Response::error(BridgeError::Timeout));
        assert!(
            elapsed >= Duration::from_millis(50),
            "watchdog fired too early: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "watchdog did not fire: {elapsed:?}"
        );
    }

    #[test]
    fn watchdog_is_disarmed_on_fast_success() {
        // A long timeout but an instant call must not sleep for the timeout.
        let api: Arc<dyn WebAuthnApi> = Arc::new(StubApi::new());
        let start = std::time::Instant::now();
        let _ = dispatch(&api, &assert_request(60_000));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    // ---- watchdog self-cancel reclassification -------------------------

    /// (a) Genuine user cancel with the watchdog never fired must stay
    /// `user_cancelled` — on both the enroll and assert paths.
    #[test]
    fn genuine_user_cancel_without_watchdog_stays_user_cancelled() {
        let stub = StubApi {
            immediate_error: Some(NTE_USER_CANCELLED),
            ..StubApi::new()
        };
        let api: Arc<dyn WebAuthnApi> = Arc::new(stub);
        assert_eq!(
            dispatch(&api, &enroll_request(55_000)),
            Response::error(BridgeError::UserCancelled)
        );
        assert_eq!(
            dispatch(&api, &assert_request(55_000)),
            Response::error(BridgeError::UserCancelled)
        );
    }

    /// (b) Watchdog fires, Windows reports `NTE_USER_CANCELLED` to the blocked
    /// ceremony → the bridge MUST report `timeout`.
    #[test]
    fn watchdog_self_cancel_of_user_cancelled_error_reports_timeout() {
        let stub = Arc::new(StubApi::blocking_user_cancelled());
        let api: Arc<dyn WebAuthnApi> = Arc::clone(&stub) as Arc<dyn WebAuthnApi>;
        assert_eq!(
            dispatch(&api, &enroll_request(50)),
            Response::error(BridgeError::Timeout)
        );
        assert_eq!(stub.cancel_count.load(Ordering::SeqCst), 1);

        let stub = Arc::new(StubApi::blocking_user_cancelled());
        let api: Arc<dyn WebAuthnApi> = Arc::clone(&stub) as Arc<dyn WebAuthnApi>;
        assert_eq!(
            dispatch(&api, &assert_request(50)),
            Response::error(BridgeError::Timeout)
        );
        assert_eq!(stub.cancel_count.load(Ordering::SeqCst), 1);
    }

    /// (c) Platform `ERROR_TIMEOUT` without a watchdog fire stays `timeout`.
    #[test]
    fn platform_timeout_without_watchdog_stays_timeout() {
        let stub = StubApi {
            immediate_error: Some(hresult_from_win32(ERROR_TIMEOUT)),
            ..StubApi::new()
        };
        let api: Arc<dyn WebAuthnApi> = Arc::new(stub);
        assert_eq!(
            dispatch(&api, &enroll_request(55_000)),
            Response::error(BridgeError::Timeout)
        );
        assert_eq!(
            dispatch(&api, &assert_request(55_000)),
            Response::error(BridgeError::Timeout)
        );
    }

    /// Race guard: a ceremony that *succeeds* while the watchdog cancels must
    /// not be remapped into an error.
    #[test]
    fn success_racing_watchdog_is_not_turned_into_error() {
        let api: Arc<dyn WebAuthnApi> = Arc::new(StubApi::succeed_after_cancel());
        match dispatch(&api, &assert_request(50)) {
            Response::Assert { .. } => {}
            other => panic!("success was corrupted into an error: {other:?}"),
        }
    }

    /// Non-cancel errors are never remapped, even when the watchdog fired.
    #[test]
    fn other_errors_are_not_remapped_by_watchdog() {
        // A non-cancel, non-timeout error is left alone by the pure remap.
        assert_eq!(
            remap_watchdog_fire::<()>(Err(BridgeError::NotAvailable), true),
            Err(BridgeError::NotAvailable)
        );
        assert_eq!(
            remap_watchdog_fire::<()>(Err(BridgeError::InvalidParameter), true),
            Err(BridgeError::InvalidParameter)
        );
        // ...and the remap is a no-op when the watchdog did not fire.
        assert_eq!(
            remap_watchdog_fire::<()>(Err(BridgeError::UserCancelled), false),
            Err(BridgeError::UserCancelled)
        );
        assert_eq!(remap_watchdog_fire(Ok(7), true), Ok(7));
    }
}
