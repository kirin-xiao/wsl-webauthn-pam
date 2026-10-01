//! Stable-runnable equivalents of the four `cargo-fuzz` targets (plan §4 test
//! item 4). Each mirrors a `fuzz/fuzz_targets/*.rs` entry, so CI smoke covers the
//! same logic on stable without nightly/libFuzzer.

mod common;

use proptest::prelude::*;
use std::time::SystemTime;
use wsl_webauthn_protocol::{ClientDataKind, build_client_data};
use wsl_webauthn_verifier::{AssertionCheck, testing, verify_assertion};

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, ..ProptestConfig::default() })]

    /// Mirror of `fuzz_targets/attestation_object.rs`.
    #[test]
    fn attestation_object_target(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = testing::parse_attestation_object(&data);
        let _ = testing::parse_tpm_cert_info(&data);
        let _ = testing::parse_tpm_pub_area(&data);
    }

    /// Mirror of `fuzz_targets/authenticator_data.rs`.
    #[test]
    fn authenticator_data_target(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = testing::parse_authenticator_data(&data);
    }

    /// Mirror of `fuzz_targets/cose_key.rs`.
    #[test]
    fn cose_key_target(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = testing::parse_cose_key(&data);
    }

    /// Mirror of `fuzz_targets/assertion.rs`.
    #[test]
    fn assertion_target(
        auth_data in proptest::collection::vec(any::<u8>(), 0..2048),
        signature in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let cose = common::es256().cose;
        let challenge = [0x11u8; 32];
        let client_data_json = build_client_data(ClientDataKind::Get, &challenge).unwrap();
        let check = AssertionCheck {
            expected_challenge: &challenge,
            credential_id: b"fuzz-credential",
            cose_public_key: &cose,
            client_data_json: &client_data_json,
            authenticator_data: &auth_data,
            signature: &signature,
            expected_sign_count: None,
            now: SystemTime::now(),
        };
        let _ = verify_assertion(&check);
    }
}
