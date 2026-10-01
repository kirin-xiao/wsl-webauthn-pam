//! Stable-runnable equivalents of the four `cargo-fuzz` targets (plan §4 test
//! item 4). Each mirrors a `fuzz/fuzz_targets/*.rs` entry, so CI smoke covers the
//! same logic on stable without nightly/libFuzzer.

mod common;

use proptest::prelude::*;
use std::time::SystemTime;
use wsl_webauthn_protocol::{ClientDataKind, RP_ID, build_client_data};
use wsl_webauthn_verifier::{
    AssertionCheck, AttestationPolicy, EnrollCheck, testing, verify_assertion,
    verify_attestation_with_anchor,
};

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

    /// Mirror of `fuzz_targets/attestation.rs` (raw shape): arbitrary bytes as the
    /// whole `attestationObject`, run through the full verifier under both policies.
    #[test]
    fn attestation_full_target(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let challenge = [0x11u8; 32];
        let client_data_json = common::client_data(ClientDataKind::Create, &challenge);
        let check = EnrollCheck::new(&challenge, &data, &client_data_json, b"fuzz-credential");
        let anchor = [0u8; 32];
        let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &anchor);
        let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::AllowUnattested, &anchor);
    }

    /// Mirror of `fuzz_targets/attestation.rs` (stitched shape): arbitrary bytes as
    /// the `attStmt` `x5c`/`certInfo`/`pubArea`/`sig` behind a valid authData, so the
    /// chain walker parses arbitrary DER.
    #[test]
    fn attestation_stitched_target(
        cert_blob in proptest::collection::vec(any::<u8>(), 0..2048),
        tail in proptest::collection::vec(any::<u8>(), 0..512),
        alg in any::<i64>(),
        tpm_style in any::<bool>(),
    ) {
        let challenge = [0x22u8; 32];
        let client_data_json = common::client_data(ClientDataKind::Create, &challenge);
        let credential_id = b"fuzz-credential".to_vec();
        let key = common::es256();
        let attested = common::AttestedData {
            aaguid: common::AAGUID_ALLOWED,
            credential_id: credential_id.clone(),
            cose_public_key: key.cose.clone(),
        };
        let auth_data = common::build_auth_data(RP_ID, 0x01 | 0x04, 0, Some(&attested));
        let x5c = vec![cert_blob];
        let att_stmt = if tpm_style {
            common::tpm_att_stmt("2.0", alg, &tail, &tail, &tail, &x5c)
        } else {
            common::packed_att_stmt(alg, &tail, Some(&x5c))
        };
        let fmt = if tpm_style { "tpm" } else { "packed" };
        let obj = common::attestation_object(fmt, &auth_data, att_stmt);
        let check = EnrollCheck::new(&challenge, &obj, &client_data_json, &credential_id);
        let anchor = [0u8; 32];
        let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &anchor);
        let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::AllowUnattested, &anchor);
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

/// Stable counterpart of the no-spurious-`Ok` oracle added to
/// `fuzz_targets/assertion.rs` (L14-10): a genuinely signed assertion verifies, and a
/// single flipped bit in the signature or the authenticator data is rejected.
#[test]
fn assertion_flipped_bit_is_rejected() {
    let challenge = [0x11u8; 32];
    let credential_id = b"fuzz-credential";
    let key = common::es256();
    let client_data_json = common::client_data(ClientDataKind::Get, &challenge);

    let attested = common::AttestedData {
        aaguid: common::AAGUID_ALLOWED,
        credential_id: credential_id.to_vec(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = common::build_auth_data(RP_ID, 0x01 | 0x04, 0, Some(&attested));
    let signed = common::signed_message(&auth_data, &client_data_json);
    let signature = key.signer.sign(&signed);

    let good = AssertionCheck::new(
        &challenge,
        credential_id,
        &key.cose,
        &client_data_json,
        &auth_data,
        &signature,
    );
    assert!(verify_assertion(&good).is_ok(), "valid assertion verifies");

    let mut bad_sig = signature.clone();
    bad_sig[0] ^= 0x01;
    let tampered_sig = AssertionCheck::new(
        &challenge,
        credential_id,
        &key.cose,
        &client_data_json,
        &auth_data,
        &bad_sig,
    );
    assert!(
        verify_assertion(&tampered_sig).is_err(),
        "tampered signature rejected"
    );

    let mut bad_ad = auth_data.clone();
    bad_ad[32] ^= 0x01;
    let tampered_ad = AssertionCheck::new(
        &challenge,
        credential_id,
        &key.cose,
        &client_data_json,
        &bad_ad,
        &signature,
    );
    assert!(
        verify_assertion(&tampered_ad).is_err(),
        "tampered authenticator data rejected"
    );
}
