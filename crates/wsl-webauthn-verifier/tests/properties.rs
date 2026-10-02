//! `proptest` round-trip and robustness properties (plan §4 test item 3).
//!
//! These run under the normal `cargo test` on stable and keep runtimes short.

mod common;

use std::sync::LazyLock;

use ciborium::value::Value;
use proptest::prelude::*;
use wsl_webauthn_verifier::{
    AssertionCheck, AttestationPolicy, EnrollCheck, testing, verify_assertion,
    verify_attestation_with_anchor,
};

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Random bytes must never panic any parser entry point.
    #[test]
    fn random_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = testing::parse_authenticator_data(&data);
        let _ = testing::parse_cose_key(&data);
        let _ = testing::parse_attestation_object(&data);
        let _ = testing::parse_tpm_cert_info(&data);
        let _ = testing::parse_tpm_pub_area(&data);
    }

    /// A parsed `authData` prefix re-parses identically (structural stability).
    #[test]
    fn authenticator_data_prefix_roundtrip(
        rp_hash in proptest::array::uniform32(any::<u8>()),
        flags in any::<u8>(),
        count in any::<u32>(),
    ) {
        let mut data = Vec::new();
        data.extend_from_slice(&rp_hash);
        data.push(flags);
        data.extend_from_slice(&count.to_be_bytes());
        prop_assert!(testing::parse_authenticator_data(&data));
        // Any truncation shorter than 37 bytes must be rejected, not panic.
        for cut in 0..37usize {
            prop_assert!(!testing::parse_authenticator_data(&data[..cut]));
        }
    }

    /// Canonical-CBOR / trailing-byte rejection for COSE keys (replaces the former
    /// `ciborium`-only round-trip property, L14-9). A key the parser accepts is an
    /// exact single CBOR item; appending any byte must therefore be rejected.
    #[test]
    fn cose_trailing_byte_rejected(
        extra in proptest::collection::vec(any::<u8>(), 1..8),
    ) {
        let good = common::es256().cose;
        prop_assert!(testing::parse_cose_key(&good));
        let mut with_trailing = good.clone();
        with_trailing.extend_from_slice(&extra);
        prop_assert!(
            !testing::parse_cose_key(&with_trailing),
            "a COSE key with appended bytes must be rejected"
        );
    }

    /// The WebAuthn §7.2 counter policy is monotone: with a persisted count, the
    /// assertion is rejected exactly when `stored != 0 || observed != 0` and
    /// `observed <= stored`. A genuinely signed assertion is used each iteration so
    /// the only variable is the counter policy.
    #[test]
    fn counter_policy_monotone(stored in 0u32..16, observed in 0u32..16) {
        let key = common::es256();
        let challenge = [0x5au8; 32];
        let credential_id = b"counter-prop".to_vec();
        let client_data_json =
            common::client_data(wsl_webauthn_protocol::ClientDataKind::Get, &challenge);
        let auth_data = common::build_auth_data(
            wsl_webauthn_protocol::RP_ID,
            0x01 | 0x04,
            observed,
            None,
        );
        let signature = key
            .signer
            .sign(&common::signed_message(&auth_data, &client_data_json));
        let check = AssertionCheck {
            expected_challenge: &challenge,
            credential_id: &credential_id,
            cose_public_key: &key.cose,
            client_data_json: &client_data_json,
            authenticator_data: &auth_data,
            signature: &signature,
            expected_sign_count: Some(stored),
        };
        let outcome = verify_assertion(&check);
        let should_reject = (stored != 0 || observed != 0) && observed <= stored;
        if should_reject {
            prop_assert_eq!(
                outcome,
                Err(wsl_webauthn_verifier::VerifyError::CounterRegression {
                    stored,
                    observed
                })
            );
        } else {
            prop_assert!(outcome.is_ok(), "counter pair {stored}/{observed} must pass");
        }
    }

    /// Assertion verification is deterministic: the same inputs yield the same
    /// result (and never panic) across repeated calls.
    #[test]
    fn assertion_verify_is_deterministic(
        auth_data in proptest::collection::vec(any::<u8>(), 0..256),
        signature in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let cose = common::es256().cose;
        let challenge = [0x11u8; 32];
        let client_data_json =
            common::client_data(wsl_webauthn_protocol::ClientDataKind::Get, &challenge);
        let check = AssertionCheck {
            expected_challenge: &challenge,
            credential_id: b"determinism",
            cose_public_key: &cose,
            client_data_json: &client_data_json,
            authenticator_data: &auth_data,
            signature: &signature,
            expected_sign_count: None,
        };
        prop_assert_eq!(verify_assertion(&check), verify_assertion(&check));
    }

    /// Random COSE maps never panic and never accept a non-allow-listed algorithm.
    #[test]
    fn random_cose_never_panics(
        kty in any::<i64>(),
        alg in any::<i64>(),
        blob in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let map = Value::Map(vec![
            (Value::from(1i64), Value::from(kty)),
            (Value::from(3i64), Value::from(alg)),
            (Value::from(-2i64), Value::Bytes(blob)),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&map, &mut encoded).unwrap();
        let parsed = testing::parse_cose_key(&encoded);
        if parsed {
            prop_assert!(matches!(alg, -7 | -257 | -8));
        }
    }

    /// A well-formed TPM `certInfo`/`pubArea` parses, and every strict truncation is
    /// rejected without panicking.
    #[test]
    fn tpm_structures_truncation_safe(
        extra in proptest::collection::vec(any::<u8>(), 0..64),
        name in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let ci = common::tpm_cert_info(&extra, &name);
        prop_assert!(testing::parse_tpm_cert_info(&ci));
        for cut in 0..ci.len() {
            prop_assert!(!testing::parse_tpm_cert_info(&ci[..cut]));
        }

        let pa = common::tpm_pub_area_ec(&[1u8; 32], &[2u8; 32], common::tpm_alg::SHA256);
        prop_assert!(testing::parse_tpm_pub_area(&pa));
        for cut in 0..pa.len() {
            prop_assert!(!testing::parse_tpm_pub_area(&pa[..cut]));
        }
    }

    /// Arbitrary bytes fed as the whole `attestationObject` must never panic the
    /// **full** enrollment verifier under either policy — the property the
    /// parser-only coverage lacked (L14-1). `Ok` is still only reachable when all
    /// checks genuinely pass.
    #[test]
    fn random_attestation_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let challenge = [0x42u8; 32];
        let client_data_json =
            common::client_data(wsl_webauthn_protocol::ClientDataKind::Create, &challenge);
        let check = EnrollCheck::new(&challenge, &data, &client_data_json, b"prop-credential");
        let anchor = [0u8; 32];
        let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &anchor);
        let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::AllowUnattested, &anchor);
    }

    /// Arbitrary bytes framed as an `attStmt` behind a structurally valid
    /// `authenticatorData`/`clientDataJSON`, so the chain walker actually parses
    /// the arbitrary DER (`x509_cert::Certificate::from_der`) instead of the input
    /// being rejected at the `authData` step. Both the `packed`/x5c and `tpm`
    /// statement shapes are exercised, under both policies.
    #[test]
    fn random_att_stmt_never_panics(
        cert_blob in proptest::collection::vec(any::<u8>(), 0..2048),
        tail in proptest::collection::vec(any::<u8>(), 0..512),
        alg in any::<i64>(),
        tpm_style in any::<bool>(),
    ) {
        let challenge = [0x33u8; 32];
        let client_data_json =
            common::client_data(wsl_webauthn_protocol::ClientDataKind::Create, &challenge);
        let credential_id = b"prop-credible".to_vec();
        let key = common::es256();
        let attested = common::AttestedData {
            aaguid: common::AAGUID_ALLOWED,
            credential_id: credential_id.clone(),
            cose_public_key: key.cose.clone(),
        };
        let auth_data = common::build_auth_data(
            wsl_webauthn_protocol::RP_ID,
            0x01 | 0x04,
            0,
            Some(&attested),
        );
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

    /// Randomly replace the leaf or intermediate certificate of an otherwise valid,
    /// anchored `packed` chain. The anchor still matches, so the chain walker runs
    /// the leaf-shape state machine (OU, AAGUID extension, BasicConstraints,
    /// validity, link signatures) over arbitrary DER.
    #[test]
    fn mutated_packed_chain_never_panics(
        replacement in proptest::collection::vec(any::<u8>(), 0..2048),
        slot in any::<bool>(),
    ) {
        let base = &*PACKED_BASE;
        let obj = rebuild_x5c_entry(&base.attestation_object, slot as usize, &replacement);
        let check =
            EnrollCheck::new(&base.challenge, &obj, &base.client_data_json, &base.credential_id);
        let _ = verify_attestation_with_anchor(
            &check,
            &AttestationPolicy::Strict,
            &base.root_fingerprint,
        );
        let _ = verify_attestation_with_anchor(
            &check,
            &AttestationPolicy::AllowUnattested,
            &base.root_fingerprint,
        );
    }

    /// Arbitrary `certInfo`/`pubArea` bytes against a valid, anchored TPM chain.
    /// Each `certInfo` is re-signed with the fixture's AIK so the AIK signature step
    /// passes and the TPM `certInfo`/`pubArea` semantic checks are actually reached
    /// with randomized input (the coverage L14-1 calls out).
    #[test]
    fn random_tpm_cert_info_never_panics(
        cert_info in proptest::collection::vec(any::<u8>(), 0..512),
        pub_area in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let base = &*TPM_BASE;
        let sig = base.sig_scheme.sign(&base.aik, &cert_info);
        let obj = rebuild_tpm_fields(&base.enr.attestation_object, &pub_area, &cert_info, &sig);
        let check = EnrollCheck::new(
            &base.enr.challenge,
            &obj,
            &base.enr.client_data_json,
            &base.enr.credential_id,
        );
        let _ = verify_attestation_with_anchor(
            &check,
            &AttestationPolicy::Strict,
            &base.enr.root_fingerprint,
        );
        let _ = verify_attestation_with_anchor(
            &check,
            &AttestationPolicy::AllowUnattested,
            &base.enr.root_fingerprint,
        );
    }
}

/// A valid, anchored `packed` enrollment built once and reused (mutations are
/// applied to clones of its bytes).
static PACKED_BASE: LazyLock<common::EnrolledPacked> =
    LazyLock::new(|| common::packed_enrollment(&common::es256()));

/// A valid, anchored `tpm` enrollment plus the AIK needed to re-sign mutated
/// `certInfo` values.
struct TpmBase {
    enr: common::TpmEnrollment,
    aik: rsa::RsaPrivateKey,
    sig_scheme: common::TpmSig,
}

static TPM_BASE: LazyLock<TpmBase> = LazyLock::new(|| {
    let credential = common::es256();
    let aik = common::rsa_aik();
    let aik_test_key = common::TestKey {
        cose: Vec::new(),
        alg: -257,
        signer: common::Signer::Rs256(Box::new(rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
            aik.clone(),
        ))),
    };
    let chain = common::build_tpm_chain(&aik_test_key, &common::ChainOptions::default());
    let enr = common::tpm_enrollment(
        &credential,
        &aik,
        &chain,
        common::TpmSig::Rs1,
        common::tpm_alg::SHA1,
    );
    TpmBase {
        enr,
        aik,
        sig_scheme: common::TpmSig::Rs1,
    }
});

/// Replace the certificate at `slot` in a `packed` attestation object's `x5c`
/// array, preserving everything else (authData, signature, anchor).
fn rebuild_x5c_entry(obj: &[u8], slot: usize, replacement: &[u8]) -> Vec<u8> {
    let value: Value = ciborium::from_reader(obj).expect("base object decodes");
    let mut map = value.as_map().expect("base object is a map").clone();
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            let mut stmt = v.as_map().expect("attStmt is a map").clone();
            for (sk, sv) in stmt.iter_mut() {
                if sk.as_text() == Some("x5c")
                    && let Some(arr) = sv.as_array_mut()
                    && let Some(entry) = arr.get_mut(slot)
                {
                    *entry = Value::Bytes(replacement.to_vec());
                }
            }
            *v = Value::Map(stmt);
        }
    }
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).expect("re-encode");
    out
}

/// Replace a `tpm` attestation object's `pubArea`/`certInfo`/`sig` fields.
fn rebuild_tpm_fields(obj: &[u8], pub_area: &[u8], cert_info: &[u8], sig: &[u8]) -> Vec<u8> {
    let value: Value = ciborium::from_reader(obj).expect("base object decodes");
    let mut map = value.as_map().expect("base object is a map").clone();
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            let mut stmt = v.as_map().expect("attStmt is a map").clone();
            for (sk, sv) in stmt.iter_mut() {
                match sk.as_text() {
                    Some("pubArea") => *sv = Value::Bytes(pub_area.to_vec()),
                    Some("certInfo") => *sv = Value::Bytes(cert_info.to_vec()),
                    Some("sig") => *sv = Value::Bytes(sig.to_vec()),
                    _ => {}
                }
            }
            *v = Value::Map(stmt);
        }
    }
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).expect("re-encode");
    out
}
