//! Synthesized enrollment / attestation verification suite — one negative test per
//! invariant (plan §4, §12.2).
//!
//! Chain tests use the `#[doc(hidden)]` anchor-injection seam
//! [`verify_attestation_with_anchor`] with a synthetic root; the production default
//! ([`verify_attestation`]) pins the real Microsoft root fingerprint and is checked
//! separately.

mod common;

use ciborium::value::Value;
use common::*;
use std::time::{Duration, SystemTime};
use wsl_webauthn_protocol::{ClientDataKind, RP_ID};
use wsl_webauthn_verifier::{
    AttestationMode, AttestationPolicy, EnrollCheck, EnrollOutcome, VerifyError,
    verify_attestation, verify_attestation_with_anchor,
};

/// A positive packed/x5c enrollment, parameterized by chain shape.
struct Fixture {
    challenge: Vec<u8>,
    credential_id: Vec<u8>,
    client_data_json: Vec<u8>,
    attestation_object: Vec<u8>,
    root_fingerprint: [u8; 32],
    aaguid: [u8; 16],
    auth_data: Vec<u8>,
}

/// Build a fixture from explicit chain options and an attStmt algorithm.
fn fixture_with(
    key: TestKey,
    chain_opts: ChainOptions,
    att_stmt_alg: i64,
    att_stmt_signer_override: Option<&Signer>,
) -> Fixture {
    let challenge = vec![0x77u8; 32];
    let credential_id = b"enroll-cred-id".to_vec();
    let client_data_json = client_data(ClientDataKind::Create, &challenge);
    let attested = AttestedData {
        aaguid: chain_opts.aaguid,
        credential_id: credential_id.clone(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = build_auth_data(RP_ID, 0x01 | 0x04, 0, Some(&attested));

    let chain = build_chain(&chain_opts);
    let signature = match att_stmt_signer_override {
        Some(signer) => signer.sign(&signed_message(&auth_data, &client_data_json)),
        None => chain
            .leaf_signer
            .sign(&signed_message(&auth_data, &client_data_json)),
    };
    let att_stmt = packed_att_stmt(att_stmt_alg, &signature, Some(&chain.x5c));
    let attestation_object = attestation_object("packed", &auth_data, att_stmt);

    Fixture {
        challenge,
        credential_id,
        client_data_json,
        attestation_object,
        root_fingerprint: chain.root_fingerprint,
        aaguid: chain_opts.aaguid,
        auth_data,
    }
}

/// The default positive fixture.
fn positive() -> Fixture {
    fixture_with(es256(), ChainOptions::default(), -7, None)
}

fn check<'a>(f: &'a Fixture, _policy: &'a AttestationPolicy) -> EnrollCheck<'a> {
    EnrollCheck {
        expected_challenge: &f.challenge,
        attestation_object: &f.attestation_object,
        client_data_json: &f.client_data_json,
        reported_credential_id: &f.credential_id,
        now: SystemTime::now(),
    }
}

fn verify(
    f: &Fixture,
    policy: AttestationPolicy,
) -> Result<wsl_webauthn_verifier::EnrollOutcome, VerifyError> {
    verify_attestation_with_anchor(&check(f, &policy), &policy, &f.root_fingerprint)
}

// ---------------------------------------------------------------------------
// Positive
// ---------------------------------------------------------------------------

#[test]
fn positive_packed_x5c_strict() {
    let f = positive();
    let outcome = verify(&f, AttestationPolicy::Strict).expect("strict packed");
    assert_eq!(outcome.credential_id, f.credential_id);
    assert_eq!(outcome.aaguid, f.aaguid);
    assert_eq!(outcome.attestation.format, "packed");
    assert_eq!(outcome.attestation.mode, AttestationMode::StrictVerified);
    assert!(outcome.attestation.leaf_sha256.is_some());
}

#[test]
fn positive_packed_x5c_with_each_credential_alg() {
    for key in [es256(), rs256(), ed25519()] {
        let f = fixture_with(key, ChainOptions::default(), -7, None);
        verify(&f, AttestationPolicy::Strict).expect("packed valid for all credential algs");
    }
}

#[test]
fn positive_aaguid_second_allowlisted_value() {
    let second = wsl_webauthn_verifier::STRICT_AAGUIDS[1];
    let f = fixture_with(
        es256(),
        ChainOptions {
            aaguid: second,
            ..Default::default()
        },
        -7,
        None,
    );
    let outcome = verify(&f, AttestationPolicy::Strict).expect("second AAGUID allowed");
    assert_eq!(outcome.aaguid, second);
}

// ---------------------------------------------------------------------------
// clientData invariants
// ---------------------------------------------------------------------------

#[test]
fn negative_wrong_challenge() {
    let f = positive();
    let other = [0x11u8; 32];
    let policy = AttestationPolicy::Strict;
    let c = EnrollCheck {
        expected_challenge: &other,
        ..check(&f, &policy)
    };
    assert_eq!(
        verify_attestation_with_anchor(&c, &policy, &f.root_fingerprint),
        Err(VerifyError::ChallengeMismatch)
    );
}

#[test]
fn negative_wrong_type_at_enrollment() {
    // A `webauthn.get` clientData cannot be used for registration.
    let key = es256();
    let challenge = vec![0x77u8; 32];
    let credential_id = b"cid".to_vec();
    let client_data_json = client_data(ClientDataKind::Get, &challenge);
    let attested = AttestedData {
        aaguid: AAGUID_ALLOWED,
        credential_id: credential_id.clone(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = build_auth_data(RP_ID, 0x05, 0, Some(&attested));
    let chain = build_chain(&ChainOptions::default());
    let sig = chain
        .leaf_signer
        .sign(&signed_message(&auth_data, &client_data_json));
    let att_stmt = packed_att_stmt(-7, &sig, Some(&chain.x5c));
    let attestation_object = attestation_object("packed", &auth_data, att_stmt);
    let f = Fixture {
        challenge,
        credential_id,
        client_data_json,
        attestation_object,
        root_fingerprint: chain.root_fingerprint,
        aaguid: AAGUID_ALLOWED,
        auth_data,
    };
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::ClientDataTypeMismatch)
    );
}

// ---------------------------------------------------------------------------
// authenticatorData invariants
// ---------------------------------------------------------------------------

#[test]
fn negative_bad_rpid_hash() {
    let f = rebuild_with_auth_data(|_| build_auth_data("wrong.rp", 0x05, 0, None));
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::RpIdHashMismatch)
    );
}

#[test]
fn negative_user_presence_zero() {
    let f = rebuild_with_auth_data(|attested| build_auth_data(RP_ID, 0x04, 0, Some(&attested)));
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::UserPresenceRequired)
    );
}

#[test]
fn negative_user_verification_zero() {
    let f = rebuild_with_auth_data(|attested| build_auth_data(RP_ID, 0x01, 0, Some(&attested)));
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::UserVerificationRequired)
    );
}

#[test]
fn negative_missing_attested_credential_data() {
    let f = rebuild_with_auth_data(|_| build_auth_data(RP_ID, 0x05, 0, None));
    assert!(matches!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::MalformedAuthenticatorData { .. })
    ));
}

// ---------------------------------------------------------------------------
// credential id / reported id
// ---------------------------------------------------------------------------

#[test]
fn negative_reported_credential_id_mismatch() {
    let f = positive();
    let policy = AttestationPolicy::Strict;
    let c = EnrollCheck {
        reported_credential_id: b"a-different-id",
        ..check(&f, &policy)
    };
    assert_eq!(
        verify_attestation_with_anchor(&c, &policy, &f.root_fingerprint),
        Err(VerifyError::CredentialIdMismatch)
    );
}

// ---------------------------------------------------------------------------
// attestation object structure
// ---------------------------------------------------------------------------

#[test]
fn negative_malformed_cbor() {
    let f = positive();
    let policy = AttestationPolicy::Strict;
    let c = EnrollCheck {
        attestation_object: &[0xff, 0x00, 0x01],
        ..check(&f, &policy)
    };
    assert!(matches!(
        verify_attestation_with_anchor(&c, &policy, &f.root_fingerprint),
        Err(VerifyError::MalformedAttestationObject { .. })
    ));
}

#[test]
fn negative_attestation_object_trailing_bytes() {
    // The attestation object must be exactly one CBOR item; trailing bytes appended
    // to a valid object must be rejected, not silently ignored.
    let f = positive();
    let mut obj = f.attestation_object.clone();
    obj.extend_from_slice(&[0xde, 0xad]);
    let policy = AttestationPolicy::Strict;
    let c = EnrollCheck {
        attestation_object: &obj,
        ..check(&f, &policy)
    };
    assert!(matches!(
        verify_attestation_with_anchor(&c, &policy, &f.root_fingerprint),
        Err(VerifyError::MalformedAttestationObject { .. })
    ));
}

#[test]
fn negative_unsupported_format() {
    let f = positive();
    let policy = AttestationPolicy::Strict;
    // Re-encode the object with an unimplemented format.
    let obj = rewrite_fmt(&f.attestation_object, "android-key");
    let c = EnrollCheck {
        attestation_object: &obj,
        ..check(&f, &policy)
    };
    assert_eq!(
        verify_attestation_with_anchor(&c, &policy, &f.root_fingerprint),
        Err(VerifyError::UnsupportedAttestationFormat {
            format: "android-key".into()
        })
    );
}

#[test]
fn negative_tpm_format_without_tpm_fields() {
    // A genuine `tpm` chain whose attStmt is missing `certInfo` must be rejected as an
    // invalid statement rather than silently accepted.
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let obj = remove_field(&f.attestation_object, "certInfo");
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::InvalidAttestationStatement)
    );
}

// ---------------------------------------------------------------------------
// packed self-attestation
// ---------------------------------------------------------------------------

fn self_attestation(key: &TestKey) -> Fixture {
    let challenge = vec![0x78u8; 32];
    let credential_id = b"self-cred".to_vec();
    let client_data_json = client_data(ClientDataKind::Create, &challenge);
    let attested = AttestedData {
        aaguid: AAGUID_ALLOWED,
        credential_id: credential_id.clone(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = build_auth_data(RP_ID, 0x05, 0, Some(&attested));
    let sig = key
        .signer
        .sign(&signed_message(&auth_data, &client_data_json));
    let att_stmt = packed_att_stmt(key.alg, &sig, None);
    let attestation_object = attestation_object("packed", &auth_data, att_stmt);
    Fixture {
        challenge,
        credential_id,
        client_data_json,
        attestation_object,
        root_fingerprint: [0u8; 32],
        aaguid: AAGUID_ALLOWED,
        auth_data,
    }
}

#[test]
fn negative_self_attestation_under_strict() {
    let f = self_attestation(&es256());
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::AttestationNotAllowed)
    );
}

#[test]
fn positive_self_attestation_under_allow_unattested() {
    let key = es256();
    let f = self_attestation(&key);
    let outcome = verify(&f, AttestationPolicy::AllowUnattested).expect("self allowed");
    assert_eq!(outcome.attestation.mode, AttestationMode::SelfAttested);
    assert_eq!(outcome.attestation.format, "packed");
    assert!(outcome.attestation.leaf_sha256.is_none());
}

#[test]
fn negative_self_attestation_alg_mismatch() {
    // attStmt.alg says RS256 but the credential key is ES256.
    let key = es256();
    let challenge = vec![0x79u8; 32];
    let credential_id = b"self-cred".to_vec();
    let client_data_json = client_data(ClientDataKind::Create, &challenge);
    let attested = AttestedData {
        aaguid: AAGUID_ALLOWED,
        credential_id: credential_id.clone(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = build_auth_data(RP_ID, 0x05, 0, Some(&attested));
    let sig = key
        .signer
        .sign(&signed_message(&auth_data, &client_data_json));
    let att_stmt = packed_att_stmt(-257, &sig, None);
    let attestation_object = attestation_object("packed", &auth_data, att_stmt);
    let f = Fixture {
        challenge,
        credential_id,
        client_data_json,
        attestation_object,
        root_fingerprint: [0u8; 32],
        aaguid: AAGUID_ALLOWED,
        auth_data,
    };
    assert_eq!(
        verify(&f, AttestationPolicy::AllowUnattested),
        Err(VerifyError::AlgorithmMismatch)
    );
}

#[test]
fn negative_self_attestation_bad_signature() {
    let key = es256();
    let f = self_attestation(&key);
    // Corrupt the signature inside attStmt by rebuilding the object.
    let obj = rewrite_att_stmt_sig(&f.attestation_object);
    let policy = AttestationPolicy::AllowUnattested;
    let c = EnrollCheck {
        attestation_object: &obj,
        ..check(&f, &policy)
    };
    let outcome = verify_attestation_with_anchor(&c, &policy, &f.root_fingerprint);
    assert!(matches!(
        outcome,
        Err(VerifyError::MalformedSignature { .. }) | Err(VerifyError::SignatureInvalid)
    ));
}

// ---------------------------------------------------------------------------
// none attestation
// ---------------------------------------------------------------------------

fn none_attestation(stmt: Vec<(ciborium::value::Value, ciborium::value::Value)>) -> Fixture {
    let key = es256();
    let challenge = vec![0x7au8; 32];
    let credential_id = b"none-cred".to_vec();
    let client_data_json = client_data(ClientDataKind::Create, &challenge);
    let attested = AttestedData {
        aaguid: AAGUID_ALLOWED,
        credential_id: credential_id.clone(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = build_auth_data(RP_ID, 0x05, 0, Some(&attested));
    let attestation_object = attestation_object("none", &auth_data, stmt);
    Fixture {
        challenge,
        credential_id,
        client_data_json,
        attestation_object,
        root_fingerprint: [0u8; 32],
        aaguid: AAGUID_ALLOWED,
        auth_data,
    }
}

#[test]
fn negative_none_under_strict() {
    let f = none_attestation(vec![]);
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::AttestationNotAllowed)
    );
}

#[test]
fn positive_none_under_allow_unattested() {
    let f = none_attestation(vec![]);
    let outcome = verify(&f, AttestationPolicy::AllowUnattested).expect("none allowed");
    assert_eq!(outcome.attestation.mode, AttestationMode::None);
}

#[test]
fn negative_none_with_nonempty_attstmt() {
    let f = none_attestation(vec![(
        ciborium::value::Value::from("alg"),
        ciborium::value::Value::from(-7i64),
    )]);
    assert_eq!(
        verify(&f, AttestationPolicy::AllowUnattested),
        Err(VerifyError::InvalidAttestationStatement)
    );
}

// ---------------------------------------------------------------------------
// x5c chain invariants
// ---------------------------------------------------------------------------

fn chain_fixture(opts: ChainOptions, alg: i64) -> Fixture {
    fixture_with(es256(), opts, alg, None)
}

#[test]
fn negative_broken_chain_leaf_signature() {
    let f = chain_fixture(
        ChainOptions {
            break_leaf_signature: true,
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::CertificateChainSignatureInvalid)
    );
}

#[test]
fn negative_missing_anchor() {
    let f = chain_fixture(
        ChainOptions {
            omit_root: true,
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::CertificateChainAnchorNotFound)
    );
}

#[test]
fn negative_expired_leaf() {
    let now = SystemTime::now();
    let f = chain_fixture(
        ChainOptions {
            leaf_validity: validity_from(
                now - Duration::from_secs(7200),
                now - Duration::from_secs(3600),
            ),
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::CertificateExpired)
    );
}

#[test]
fn negative_not_yet_valid_leaf() {
    let now = SystemTime::now();
    let f = chain_fixture(
        ChainOptions {
            leaf_validity: validity_from(
                now + Duration::from_secs(3600),
                now + Duration::from_secs(7200),
            ),
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::CertificateNotYetValid)
    );
}

#[test]
fn negative_leaf_is_ca() {
    let f = chain_fixture(
        ChainOptions {
            leaf_is_ca: true,
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::CertificateLeafIsCa)
    );
}

#[test]
fn negative_intermediate_not_ca() {
    let f = chain_fixture(
        ChainOptions {
            intermediate_is_ca: false,
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::CertificateIntermediateNotCa)
    );
}

#[test]
fn negative_wrong_ou() {
    let f = chain_fixture(
        ChainOptions {
            leaf_ou: "Something Else".to_string(),
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::CertificateSubjectOuMismatch)
    );
}

#[test]
fn negative_missing_aaguid_extension() {
    let f = chain_fixture(
        ChainOptions {
            include_aaguid_ext: false,
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::CertificateAaguidExtensionMissing)
    );
}

#[test]
fn negative_cert_aaguid_mismatch() {
    // authData says AAGUID_ALLOWED; the leaf extension says a different (allowed but
    // unequal) AAGUID.
    let mut other = AAGUID_ALLOWED;
    other[15] ^= 0x01;
    let f = chain_fixture(
        ChainOptions {
            aaguid: AAGUID_ALLOWED,
            cert_aaguid: Some(other),
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::CertificateAaguidMismatch)
    );
}

#[test]
fn negative_aaguid_not_in_allowlist() {
    let f = chain_fixture(
        ChainOptions {
            aaguid: AAGUID_DISALLOWED,
            ..Default::default()
        },
        -7,
    );
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::AaguidNotAllowed)
    );
}

#[test]
fn negative_x5c_not_der() {
    let f = positive();
    let policy = AttestationPolicy::Strict;
    // Replace x5c[0] with garbage bytes.
    let obj = rewrite_x5c_first(&f.attestation_object, vec![0xde, 0xad, 0xbe, 0xef]);
    let c = EnrollCheck {
        attestation_object: &obj,
        ..check(&f, &policy)
    };
    assert_eq!(
        verify_attestation_with_anchor(&c, &policy, &f.root_fingerprint),
        Err(VerifyError::MalformedCertificate {
            reason: "certificate is not valid DER"
        })
    );
}

#[test]
fn negative_attstmt_alg_mismatch_x5c() {
    // The x5c leaf is ES256 but attStmt.alg claims RS256.
    let f = chain_fixture(ChainOptions::default(), -257);
    assert_eq!(
        verify(&f, AttestationPolicy::Strict),
        Err(VerifyError::AlgorithmMismatch)
    );
}

#[test]
fn negative_attstmt_signature_invalid_x5c() {
    let key = es256();
    let f = chain_fixture(ChainOptions::default(), -7);
    let _ = key;
    // Re-sign the attStmt with a random key instead of the leaf key.
    let wrong = es256();
    let obj = rewrite_att_stmt_sig_with(
        &f.attestation_object,
        &wrong.signer,
        &signed_message(&f.auth_data, &f.client_data_json),
    );
    let policy = AttestationPolicy::Strict;
    let c = EnrollCheck {
        attestation_object: &obj,
        ..check(&f, &policy)
    };
    assert_eq!(
        verify_attestation_with_anchor(&c, &policy, &f.root_fingerprint),
        Err(VerifyError::SignatureInvalid)
    );
}

#[test]
fn negative_empty_x5c() {
    let f = positive();
    let obj = rewrite_x5c(&f.attestation_object, vec![]);
    let policy = AttestationPolicy::Strict;
    let c = EnrollCheck {
        attestation_object: &obj,
        ..check(&f, &policy)
    };
    assert_eq!(
        verify_attestation_with_anchor(&c, &policy, &f.root_fingerprint),
        Err(VerifyError::CertificateChainEmpty)
    );
}

// ---------------------------------------------------------------------------
// Production anchor
// ---------------------------------------------------------------------------

#[test]
fn negative_real_policy_rejects_synthetic_root() {
    // `verify_attestation` pins the real Microsoft root; a synthetic chain must fail.
    let f = positive();
    assert_eq!(
        verify_attestation(
            &check(&f, &AttestationPolicy::Strict),
            &AttestationPolicy::Strict
        ),
        Err(VerifyError::CertificateChainAnchorNotFound)
    );
}

// ---------------------------------------------------------------------------
// TPM attestation (§8.3)
// ---------------------------------------------------------------------------

/// A synthesized `tpm` fixture: RS1 (Windows Hello) by default.
struct TpmFixture {
    challenge: Vec<u8>,
    credential_id: Vec<u8>,
    client_data_json: Vec<u8>,
    attestation_object: Vec<u8>,
    auth_data: Vec<u8>,
    root_fingerprint: [u8; 32],
    credential: TestKey,
    /// The AIK private key, retained so negative tests can re-sign a mutated certInfo.
    aik: rsa::RsaPrivateKey,
    /// The signature/hash scheme the fixture signed with.
    sig_scheme: TpmSig,
    /// The `nameAlg` the fixture's pubArea declares.
    name_alg: u16,
}

fn tpm_fixture(sig_scheme: TpmSig, name_alg: u16) -> TpmFixture {
    let credential = es256();
    let aik = rsa_aik();
    let aik_test_key = rsa_test_key(&aik);
    let chain = build_tpm_chain(&aik_test_key, &ChainOptions::default());
    let e = tpm_enrollment(&credential, &aik, &chain, sig_scheme, name_alg);
    TpmFixture {
        challenge: e.challenge,
        credential_id: e.credential_id,
        client_data_json: e.client_data_json,
        attestation_object: e.attestation_object,
        auth_data: e.auth_data,
        root_fingerprint: e.root_fingerprint,
        credential,
        aik,
        sig_scheme,
        name_alg,
    }
}

/// Wrap an RSA private key as a `TestKey` for certificate generation.
fn rsa_test_key(key: &rsa::RsaPrivateKey) -> TestKey {
    TestKey {
        cose: Vec::new(),
        alg: -257,
        signer: Signer::Rs256(Box::new(rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
            key.clone(),
        ))),
    }
}

impl TpmFixture {
    /// Rebuild the attestation object with a mutated `(pubArea, certInfo)`, re-signing
    /// `certInfo` with the fixture's AIK under its scheme — so only the mutated
    /// property can cause a failure.
    fn rebuild(&self, pub_area: &[u8], cert_info: &[u8]) -> Vec<u8> {
        let sig = self.sig_scheme.sign(&self.aik, cert_info);
        set_tpm_fields(
            &self.attestation_object,
            pub_area,
            cert_info,
            Some(&sig),
            None,
        )
    }
}

fn verify_tpm(f: &TpmFixture, policy: AttestationPolicy) -> Result<EnrollOutcome, VerifyError> {
    let check = EnrollCheck {
        expected_challenge: &f.challenge,
        attestation_object: &f.attestation_object,
        client_data_json: &f.client_data_json,
        reported_credential_id: &f.credential_id,
        now: SystemTime::now(),
    };
    verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint)
}

#[test]
fn positive_tpm_rs1_windows_hello_shape_strict() {
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let outcome = verify_tpm(&f, AttestationPolicy::Strict).expect("strict tpm");
    assert_eq!(outcome.attestation.format, "tpm");
    assert_eq!(outcome.attestation.mode, AttestationMode::StrictVerified);
    assert!(outcome.attestation.leaf_sha256.is_some());
    assert_eq!(outcome.aaguid, AAGUID_ALLOWED);
    assert_eq!(outcome.credential_id, f.credential_id);
}

#[test]
fn positive_tpm_rs256_strict() {
    let f = tpm_fixture(TpmSig::Rs256, tpm_alg::SHA256);
    verify_tpm(&f, AttestationPolicy::Strict).expect("rs256 tpm");
}

#[test]
fn positive_tpm_rs256_credential_key_strict() {
    // Regression: an RSA credential key makes `pubArea.unique`/`parameters` describe
    // an RSA key. `TPMS_RSA_PARMS.exponent` is a fixed-width `u32` (`00 01 00 01` for
    // 65537) while `BigUint::to_bytes_be` is minimal (`01 00 01`); a byte-length
    // comparison would reject every RSA credential.
    let credential = rs256();
    let aik = rsa_aik();
    let aik_test_key = rsa_test_key(&aik);
    let chain = build_tpm_chain(&aik_test_key, &ChainOptions::default());
    let e = tpm_enrollment(&credential, &aik, &chain, TpmSig::Rs1, tpm_alg::SHA1);
    let check = EnrollCheck {
        expected_challenge: &e.challenge,
        attestation_object: &e.attestation_object,
        client_data_json: &e.client_data_json,
        reported_credential_id: &e.credential_id,
        now: SystemTime::now(),
    };
    let outcome =
        verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &e.root_fingerprint)
            .expect("tpm attestation of an RSA credential key");
    assert_eq!(outcome.attestation.format, "tpm");
}

#[test]
fn positive_tpm_under_allow_unattested_too() {
    // A fully verified tpm attestation is acceptable under either policy.
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    verify_tpm(&f, AttestationPolicy::AllowUnattested).expect("tpm under allow-unattested");
}

#[test]
fn negative_tpm_bad_version() {
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let obj = rewrite_att_stmt_text(&f.attestation_object, "ver", "2.1");
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::TpmVersionUnsupported { ver: "2.1".into() })
    );
}

#[test]
fn negative_tpm_tampered_cert_info_signature() {
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    // Flip a byte in the certInfo; the signature no longer covers it.
    let obj = rewrite_att_stmt_bytes_flip(&f.attestation_object, "certInfo");
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::SignatureInvalid)
    );
}

#[test]
fn negative_tpm_wrong_extra_data() {
    // Re-sign a certInfo whose extraData is a hash of the wrong message, keeping the
    // correct attested Name so only the extraData check can fail.
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let pub_area = tpm_pub_area_bytes(&f.attestation_object);
    let name = tpm_name(&pub_area, f.name_alg);
    let wrong_extra = sha1_of(b"a different attToBeSigned");
    let cert_info = tpm_cert_info(&wrong_extra, &name);
    let obj = f.rebuild(&pub_area, &cert_info);
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::TpmCertInfoExtraDataMismatch)
    );
}

#[test]
fn negative_tpm_wrong_name() {
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let pub_area = tpm_pub_area_bytes(&f.attestation_object);
    let correct_extra = sha1_of(&att_to_be_signed(&f));
    let cert_info = tpm_cert_info(&correct_extra, &[0u8; 22]);
    let obj = f.rebuild(&pub_area, &cert_info);
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::TpmCertInfoNameMismatch)
    );
}

#[test]
fn negative_tpm_pub_area_key_mismatch() {
    // Replace pubArea's unique point with a different valid P-256 point and attest the
    // matching Name, so only the credential-key equality check can fail.
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let other = es256();
    let (x, y) = p256_xy_from_cose(&other.cose);
    let new_pub_area = tpm_pub_area_ec(&x, &y, f.name_alg);
    let name = tpm_name(&new_pub_area, f.name_alg);
    let extra = sha1_of(&att_to_be_signed(&f));
    let cert_info = tpm_cert_info(&extra, &name);
    let obj = f.rebuild(&new_pub_area, &cert_info);
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::TpmPubAreaKeyMismatch)
    );
}

#[test]
fn negative_tpm_magic() {
    // Corrupt magic (bytes 0..4) and re-sign: expect TpmCertInfoMagic.
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let pub_area = tpm_pub_area_bytes(&f.attestation_object);
    let mut cert_info = tpm_cert_info(
        &sha1_of(&att_to_be_signed(&f)),
        &tpm_name(&pub_area, f.name_alg),
    );
    cert_info[0] = 0x00;
    let obj = f.rebuild(&pub_area, &cert_info);
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::TpmCertInfoMagic)
    );
}

#[test]
fn negative_tpm_type() {
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let pub_area = tpm_pub_area_bytes(&f.attestation_object);
    let mut cert_info = tpm_cert_info(
        &sha1_of(&att_to_be_signed(&f)),
        &tpm_name(&pub_area, f.name_alg),
    );
    // type at offset 4..6 -> TPM_ST_ATTEST_QUOTE (0x8018), not CERTIFY.
    cert_info[4] = 0x80;
    cert_info[5] = 0x18;
    let obj = f.rebuild(&pub_area, &cert_info);
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::TpmCertInfoType)
    );
}

#[test]
fn negative_tpm_unsupported_name_alg() {
    // pubArea declares SHA3-256 (unsupported) as nameAlg; re-sign so only the nameAlg
    // check can fail.
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let (x, y) = p256_xy_from_cose(&f.credential.cose);
    let new_pub_area = tpm_pub_area_ec(&x, &y, 0x0028); // TPM_ALG_SHA3_256
    let cert_info = tpm_cert_info(&sha1_of(&att_to_be_signed(&f)), &Vec::new());
    let obj = f.rebuild(&new_pub_area, &cert_info);
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::TpmNameAlgUnsupported { name_alg: 0x0028 })
    );
}

#[test]
fn negative_tpm_eddsa_alg_rejected() {
    // A COSE EdDSA alg with an RSA AIK cannot verify and is not trialable.
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let obj = set_tpm_fields(
        &f.attestation_object,
        &tpm_pub_area_bytes(&f.attestation_object),
        &[],
        None,
        Some(("alg", -8)),
    );
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::TpmAlgorithmUnsupported { alg: -8 })
    );
}

#[test]
fn positive_tpm_unknown_alg_trial_verifies() {
    // An unrecognised alg that still verifies under the AIK key (RS1 here) is accepted.
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let obj = set_tpm_fields(
        &f.attestation_object,
        &tpm_pub_area_bytes(&f.attestation_object),
        &[],
        None,
        Some(("alg", 12345)),
    );
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint)
        .expect("unknown alg that verifies is accepted");
}

#[test]
fn negative_tpm_aik_subject_not_empty() {
    // A chain whose leaf has a non-empty Subject must fail under the tpm profile.
    let credential = es256();
    let aik = rsa_aik();
    // A normal packed-style chain: the leaf Subject carries the OU.
    let chain = build_chain(&ChainOptions::default());
    let e = tpm_enrollment(&credential, &aik, &chain, TpmSig::Rs1, tpm_alg::SHA1);
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        expected_challenge: &e.challenge,
        attestation_object: &e.attestation_object,
        client_data_json: &e.client_data_json,
        reported_credential_id: &e.credential_id,
        now: SystemTime::now(),
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &e.root_fingerprint),
        Err(VerifyError::TpmAikSubjectNotEmpty)
    );
}

#[test]
fn negative_tpm_missing_x5c() {
    let f = tpm_fixture(TpmSig::Rs1, tpm_alg::SHA1);
    let obj = remove_field(&f.attestation_object, "x5c");
    let policy = AttestationPolicy::Strict;
    let check = EnrollCheck {
        attestation_object: &obj,
        ..tpm_check(&f)
    };
    assert_eq!(
        verify_attestation_with_anchor(&check, &policy, &f.root_fingerprint),
        Err(VerifyError::InvalidAttestationStatement)
    );
}

// ---- TPM test helpers ----

fn tpm_check<'a>(f: &'a TpmFixture) -> EnrollCheck<'a> {
    EnrollCheck {
        expected_challenge: &f.challenge,
        attestation_object: &f.attestation_object,
        client_data_json: &f.client_data_json,
        reported_credential_id: &f.credential_id,
        now: SystemTime::now(),
    }
}

fn sha1_of(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest as _;
    sha1::Sha1::digest(bytes).to_vec()
}

/// `authData || SHA-256(clientDataJSON)` for a tpm fixture.
fn att_to_be_signed(f: &TpmFixture) -> Vec<u8> {
    signed_message(&f.auth_data, &f.client_data_json)
}

/// The pubArea bytes from a tpm attestation object.
fn tpm_pub_area_bytes(obj: &[u8]) -> Vec<u8> {
    let map = parse_object(obj);
    let stmt = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("attStmt"))
        .and_then(|(_, v)| v.as_map())
        .expect("attStmt");
    stmt.iter()
        .find(|(k, _)| k.as_text() == Some("pubArea"))
        .and_then(|(_, v)| v.as_bytes())
        .expect("pubArea")
        .clone()
}

/// Replace fields in the `attStmt` of a `tpm` attestation object.
///
/// `pub_area`/`cert_info` are replaced when non-empty; `sig` when `Some`; and `text`
/// sets one text/int field (used for `alg`). Re-encoding preserves all other fields.
fn set_tpm_fields(
    obj: &[u8],
    pub_area: &[u8],
    cert_info: &[u8],
    sig: Option<&[u8]>,
    text: Option<(&str, i64)>,
) -> Vec<u8> {
    let mut map = parse_object(obj);
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            if let Some(stmt) = v.as_map_mut() {
                for (sk, sv) in stmt.iter_mut() {
                    match sk.as_text() {
                        Some("pubArea") if !pub_area.is_empty() => {
                            *sv = Value::Bytes(pub_area.to_vec());
                        }
                        Some("certInfo") if !cert_info.is_empty() => {
                            *sv = Value::Bytes(cert_info.to_vec());
                        }
                        Some("sig") => {
                            if let Some(sig) = sig {
                                *sv = Value::Bytes(sig.to_vec());
                            }
                        }
                        Some(name) if text.map(|(n, _)| n) == Some(name) => {
                            *sv = Value::from(text.expect("checked").1);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    encode_object(map)
}

/// Remove a top-level `attStmt` field from an attestation object.
fn remove_field(obj: &[u8], name: &str) -> Vec<u8> {
    let mut map = parse_object(obj);
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            if let Some(stmt) = v.as_map_mut() {
                stmt.retain(|(sk, _)| sk.as_text() != Some(name));
            }
        }
    }
    encode_object(map)
}

/// Replace one `attStmt` text field.
fn rewrite_att_stmt_text(obj: &[u8], name: &str, value: &str) -> Vec<u8> {
    let mut map = parse_object(obj);
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            if let Some(stmt) = v.as_map_mut() {
                for (sk, sv) in stmt.iter_mut() {
                    if sk.as_text() == Some(name) {
                        *sv = Value::from(value);
                    }
                }
            }
        }
    }
    encode_object(map)
}

/// Flip the first byte of an `attStmt` byte-string field.
fn rewrite_att_stmt_bytes_flip(obj: &[u8], name: &str) -> Vec<u8> {
    let mut map = parse_object(obj);
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            if let Some(stmt) = v.as_map_mut() {
                for (sk, sv) in stmt.iter_mut() {
                    if sk.as_text() == Some(name) {
                        if let Some(bytes) = sv.as_bytes_mut() {
                            if !bytes.is_empty() {
                                bytes[0] ^= 0xff;
                            }
                        }
                    }
                }
            }
        }
    }
    encode_object(map)
}

// ---------------------------------------------------------------------------
// TPM attestation (§8.3) — real-machine vector (git-ignored, env-gated)
// ---------------------------------------------------------------------------

/// Env var pointing at a spike-captured vector JSON (never committed).
const LOCAL_VECTOR_ENV: &str = "WSL_WEBAUTHN_LOCAL_VECTOR";

/// The shape of the spike harness vector we consume.
#[derive(serde::Deserialize)]
struct SpikeVector {
    #[serde(default)]
    rp_id: String,
    enroll_request: SpikeEnrollRequest,
    enroll_response: SpikeEnrollResponse,
    assert_request: SpikeAssertRequest,
    assert_response: SpikeAssertResponse,
}

#[derive(serde::Deserialize)]
struct SpikeEnrollRequest {
    client_data_json: String,
}

#[derive(serde::Deserialize)]
struct SpikeEnrollResponse {
    attestation_object: String,
    credential_id: String,
}

#[derive(serde::Deserialize)]
struct SpikeAssertRequest {
    client_data_json: String,
}

#[derive(serde::Deserialize)]
struct SpikeAssertResponse {
    authenticator_data: String,
    signature: String,
}

/// `#[ignore]`d real-machine test. Run with:
///
/// ```text
/// WSL_WEBAUTHN_LOCAL_VECTOR=/path/to/spike-enroll-assert.json \
///   cargo test -p wsl-webauthn-verifier --test attestation -- --ignored local_vector
/// ```
#[test]
#[ignore = "requires a git-ignored real-machine vector via WSL_WEBAUTHN_LOCAL_VECTOR"]
fn local_vector_tpm_strict_round_trip() {
    let path = std::env::var(LOCAL_VECTOR_ENV).expect("set WSL_WEBAUTHN_LOCAL_VECTOR");
    let bytes = std::fs::read(&path).expect("read vector");
    let v: SpikeVector = serde_json::from_slice(&bytes).expect("parse vector");
    assert_eq!(v.rp_id, RP_ID, "vector must be for this RP ID");

    let decode = |s: &str| -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .expect("b64url")
    };

    let enroll_cdj = decode(&v.enroll_request.client_data_json);
    let attestation_object = decode(&v.enroll_response.attestation_object);
    let credential_id = decode(&v.enroll_response.credential_id);

    // Derive the challenge from the clientData (the vector does not repeat it).
    let challenge = challenge_from_client_data(&enroll_cdj);
    let check = EnrollCheck {
        expected_challenge: &challenge,
        attestation_object: &attestation_object,
        client_data_json: &enroll_cdj,
        reported_credential_id: &credential_id,
        now: SystemTime::now(),
    };
    // The real chain pins the genuine Microsoft root, so use the production entry.
    let outcome = wsl_webauthn_verifier::verify_attestation(&check, &AttestationPolicy::Strict)
        .expect("strict tpm verification of the real vector");
    assert_eq!(outcome.attestation.mode, AttestationMode::StrictVerified);
    assert_eq!(outcome.attestation.format, "tpm");
    assert_eq!(outcome.credential_id, credential_id);

    // Assertion leg.
    let assert_cdj = decode(&v.assert_request.client_data_json);
    let auth_data = decode(&v.assert_response.authenticator_data);
    let signature = decode(&v.assert_response.signature);
    let assert_challenge = challenge_from_client_data(&assert_cdj);
    let assert_check = wsl_webauthn_verifier::AssertionCheck {
        expected_challenge: &assert_challenge,
        credential_id: &outcome.credential_id,
        cose_public_key: &outcome.cose_public_key,
        client_data_json: &assert_cdj,
        authenticator_data: &auth_data,
        signature: &signature,
        expected_sign_count: None,
        now: SystemTime::now(),
    };
    wsl_webauthn_verifier::verify_assertion(&assert_check).expect("real assertion verification");
}

/// Extract the raw challenge bytes from a `clientDataJSON`.
fn challenge_from_client_data(cdj: &[u8]) -> Vec<u8> {
    #[derive(serde::Deserialize)]
    struct Cd {
        challenge: String,
    }
    use base64::Engine as _;
    let cd: Cd = serde_json::from_slice(cdj).expect("clientData");
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cd.challenge.as_bytes())
        .expect("challenge b64url")
}

fn parse_object(der: &[u8]) -> Vec<(ciborium::value::Value, ciborium::value::Value)> {
    use ciborium::value::Value;
    let value: Value = ciborium::from_reader(der).expect("object");
    value.into_map().expect("map")
}

fn encode_object(map: Vec<(ciborium::value::Value, ciborium::value::Value)>) -> Vec<u8> {
    use ciborium::value::Value;
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).expect("cbor");
    out
}

fn rewrite_fmt(obj: &[u8], fmt: &str) -> Vec<u8> {
    use ciborium::value::Value;
    let mut map = parse_object(obj);
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("fmt") {
            *v = Value::from(fmt);
        }
    }
    encode_object(map)
}

fn rewrite_x5c_first(obj: &[u8], replacement: Vec<u8>) -> Vec<u8> {
    rewrite_x5c_entry(obj, 0, replacement)
}

fn rewrite_x5c_entry(obj: &[u8], index: usize, replacement: Vec<u8>) -> Vec<u8> {
    use ciborium::value::Value;
    let mut map = parse_object(obj);
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            if let Some(stmt) = v.as_map_mut() {
                for (sk, sv) in stmt.iter_mut() {
                    if sk.as_text() == Some("x5c") {
                        if let Some(arr) = sv.as_array_mut() {
                            if index < arr.len() {
                                arr[index] = Value::Bytes(replacement.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    encode_object(map)
}

fn rewrite_x5c(obj: &[u8], certs: Vec<Vec<u8>>) -> Vec<u8> {
    use ciborium::value::Value;
    let mut map = parse_object(obj);
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            if let Some(stmt) = v.as_map_mut() {
                for (sk, sv) in stmt.iter_mut() {
                    if sk.as_text() == Some("x5c") {
                        *sv = Value::Array(certs.iter().cloned().map(Value::Bytes).collect());
                    }
                }
            }
        }
    }
    encode_object(map)
}

fn rewrite_att_stmt_sig(obj: &[u8]) -> Vec<u8> {
    // Corrupt the existing signature bytes.
    let mut map = parse_object(obj);
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            if let Some(stmt) = v.as_map_mut() {
                for (sk, sv) in stmt.iter_mut() {
                    if sk.as_text() == Some("sig") {
                        if let Some(bytes) = sv.as_bytes_mut() {
                            bytes[0] ^= 0xff;
                        }
                    }
                }
            }
        }
    }
    encode_object(map)
}

fn rewrite_att_stmt_sig_with(obj: &[u8], signer: &Signer, message: &[u8]) -> Vec<u8> {
    use ciborium::value::Value;
    let mut map = parse_object(obj);
    for (k, v) in map.iter_mut() {
        if k.as_text() == Some("attStmt") {
            if let Some(stmt) = v.as_map_mut() {
                for (sk, sv) in stmt.iter_mut() {
                    if sk.as_text() == Some("sig") {
                        *sv = Value::Bytes(signer.sign(message));
                    }
                }
            }
        }
    }
    encode_object(map)
}

/// Rebuild a positive fixture with a custom `authData`, re-signing the attStmt.
fn rebuild_with_auth_data<F>(build: F) -> Fixture
where
    F: FnOnce(AttestedData) -> Vec<u8>,
{
    let key = es256();
    let challenge = vec![0x7bu8; 32];
    let credential_id = b"rebuild-cred".to_vec();
    let client_data_json = client_data(ClientDataKind::Create, &challenge);
    let attested = AttestedData {
        aaguid: AAGUID_ALLOWED,
        credential_id: credential_id.clone(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = build(attested);
    let chain = build_chain(&ChainOptions::default());
    let sig = chain
        .leaf_signer
        .sign(&signed_message(&auth_data, &client_data_json));
    let att_stmt = packed_att_stmt(-7, &sig, Some(&chain.x5c));
    let attestation_object = attestation_object("packed", &auth_data, att_stmt);
    Fixture {
        challenge,
        credential_id,
        client_data_json,
        attestation_object,
        root_fingerprint: chain.root_fingerprint,
        aaguid: AAGUID_ALLOWED,
        auth_data,
    }
}
