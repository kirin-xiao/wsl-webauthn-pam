//! Synthesized assertion (login) verification suite — one negative test per
//! invariant (plan §4/§12.1/§12.2).
//!
//! Positive cases cover all three allow-listed algorithms; negative cases cover
//! `rpIdHash`, UP, UV, challenge, origin, type, credential id, signature, malformed
//! COSE, and the allow-list boundary.

mod common;

use common::*;
use std::time::SystemTime;
use wsl_webauthn_protocol::{ClientDataKind, RP_ID};
use wsl_webauthn_verifier::{AssertionCheck, VerifyError, verify_assertion};

/// Build a positive assertion bundle for `key` (credential = the key's COSE key).
struct Assertion {
    challenge: Vec<u8>,
    credential_id: Vec<u8>,
    client_data_json: Vec<u8>,
    auth_data: Vec<u8>,
    signature: Vec<u8>,
    cose: Vec<u8>,
}

fn build_assertion(key: &TestKey) -> Assertion {
    let challenge = vec![0x24u8; 32];
    let credential_id = b"assertion-cred-id".to_vec();
    let client_data_json = client_data(ClientDataKind::Get, &challenge);
    // Platform assertions omit attested credential data (AT=0).
    let auth_data = build_auth_data(RP_ID, 0x01 | 0x04, 5, None);
    let message = signed_message(&auth_data, &client_data_json);
    let signature = key.signer.sign(&message);
    Assertion {
        challenge,
        credential_id,
        client_data_json,
        auth_data,
        signature,
        cose: key.cose.clone(),
    }
}

fn check<'a>(a: &'a Assertion) -> AssertionCheck<'a> {
    AssertionCheck {
        expected_challenge: &a.challenge,
        credential_id: &a.credential_id,
        cose_public_key: &a.cose,
        client_data_json: &a.client_data_json,
        authenticator_data: &a.auth_data,
        signature: &a.signature,
        now: SystemTime::now(),
    }
}

/// Clone an assertion so a single field can be perturbed.
#[allow(dead_code)]
fn clone(a: &Assertion) -> Assertion {
    Assertion {
        challenge: a.challenge.clone(),
        credential_id: a.credential_id.clone(),
        client_data_json: a.client_data_json.clone(),
        auth_data: a.auth_data.clone(),
        signature: a.signature.clone(),
        cose: a.cose.clone(),
    }
}

// ---------------------------------------------------------------------------
// Positive
// ---------------------------------------------------------------------------

#[test]
fn positive_es256() {
    let a = build_assertion(&es256());
    let outcome = verify_assertion(&check(&a)).expect("es256 assertion");
    assert_eq!(outcome.sign_count, 5);
}

#[test]
fn positive_rs256() {
    let a = build_assertion(&rs256());
    verify_assertion(&check(&a)).expect("rs256 assertion");
}

#[test]
fn positive_eddsa() {
    let a = build_assertion(&ed25519());
    verify_assertion(&check(&a)).expect("eddsa assertion");
}

#[test]
fn positive_with_attested_credential_data_matching_id() {
    // An assertion that does carry AT must have its embedded id match.
    let key = es256();
    let challenge = vec![0x33u8; 32];
    let credential_id = b"embedded-cred".to_vec();
    let client_data_json = client_data(ClientDataKind::Get, &challenge);
    let attested = AttestedData {
        aaguid: AAGUID_ALLOWED,
        credential_id: credential_id.clone(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = build_auth_data(RP_ID, 0x01 | 0x04, 1, Some(&attested));
    let signature = key
        .signer
        .sign(&signed_message(&auth_data, &client_data_json));
    let a = Assertion {
        challenge,
        credential_id,
        client_data_json,
        auth_data,
        signature,
        cose: key.cose.clone(),
    };
    verify_assertion(&check(&a)).expect("assertion with matching attested id");
}

// ---------------------------------------------------------------------------
// clientData invariants
// ---------------------------------------------------------------------------

#[test]
fn negative_wrong_challenge() {
    let a = build_assertion(&es256());
    let mut c = check(&a);
    c.expected_challenge = &[0x99u8; 32];
    assert_eq!(verify_assertion(&c), Err(VerifyError::ChallengeMismatch));
}

#[test]
fn negative_wrong_origin() {
    let key = es256();
    let mut a = build_assertion(&key);
    a.client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://evil.example"}}"#,
        challenge_b64(&a.challenge)
    )
    .into_bytes();
    // Re-sign so only the origin check can fail.
    a.signature = key
        .signer
        .sign(&signed_message(&a.auth_data, &a.client_data_json));
    assert_eq!(
        verify_assertion(&check(&a)),
        Err(VerifyError::OriginMismatch)
    );
}

#[test]
fn negative_wrong_type() {
    let key = es256();
    let mut a = build_assertion(&key);
    // A webauthn.create clientData cannot satisfy a get assertion.
    a.client_data_json = client_data(ClientDataKind::Create, &a.challenge);
    a.signature = key
        .signer
        .sign(&signed_message(&a.auth_data, &a.client_data_json));
    assert_eq!(
        verify_assertion(&check(&a)),
        Err(VerifyError::ClientDataTypeMismatch)
    );
}

#[test]
fn negative_invalid_utf8_client_data() {
    let key = es256();
    let mut a = build_assertion(&key);
    a.client_data_json = vec![0xff, 0xfe, 0xfd];
    a.signature = key
        .signer
        .sign(&signed_message(&a.auth_data, &a.client_data_json));
    assert!(matches!(
        verify_assertion(&check(&a)),
        Err(VerifyError::MalformedClientData { .. })
    ));
}

// ---------------------------------------------------------------------------
// authenticatorData invariants
// ---------------------------------------------------------------------------

#[test]
fn negative_bad_rpid_hash() {
    let key = es256();
    let mut a = build_assertion(&key);
    let mut auth = build_auth_data("wrong.rp.id", 0x01 | 0x04, 5, None);
    // Re-sign so only rpIdHash can fail.
    a.auth_data = std::mem::take(&mut auth);
    a.signature = key
        .signer
        .sign(&signed_message(&a.auth_data, &a.client_data_json));
    assert_eq!(
        verify_assertion(&check(&a)),
        Err(VerifyError::RpIdHashMismatch)
    );
}

#[test]
fn negative_user_presence_zero() {
    let key = es256();
    let mut a = build_assertion(&key);
    a.auth_data = build_auth_data(RP_ID, 0x04, 5, None); // UP=0
    a.signature = key
        .signer
        .sign(&signed_message(&a.auth_data, &a.client_data_json));
    assert_eq!(
        verify_assertion(&check(&a)),
        Err(VerifyError::UserPresenceRequired)
    );
}

#[test]
fn negative_user_verification_zero() {
    let key = es256();
    let mut a = build_assertion(&key);
    a.auth_data = build_auth_data(RP_ID, 0x01, 5, None); // UV=0
    a.signature = key
        .signer
        .sign(&signed_message(&a.auth_data, &a.client_data_json));
    assert_eq!(
        verify_assertion(&check(&a)),
        Err(VerifyError::UserVerificationRequired)
    );
}

#[test]
fn negative_truncated_auth_data() {
    let key = es256();
    let mut a = build_assertion(&key);
    a.auth_data.truncate(20);
    assert!(matches!(
        verify_assertion(&check(&a)),
        Err(VerifyError::MalformedAuthenticatorData { .. })
    ));
}

// ---------------------------------------------------------------------------
// credential id / signature
// ---------------------------------------------------------------------------

#[test]
fn negative_empty_credential_id() {
    let a = build_assertion(&es256());
    let mut c = check(&a);
    c.credential_id = &[];
    assert_eq!(verify_assertion(&c), Err(VerifyError::EmptyCredentialId));
}

#[test]
fn negative_embedded_credential_id_mismatch() {
    let key = es256();
    let challenge = vec![0x44u8; 32];
    let client_data_json = client_data(ClientDataKind::Get, &challenge);
    let attested = AttestedData {
        aaguid: AAGUID_ALLOWED,
        credential_id: b"embedded".to_vec(),
        cose_public_key: key.cose.clone(),
    };
    let auth_data = build_auth_data(RP_ID, 0x01 | 0x04, 1, Some(&attested));
    let signature = key
        .signer
        .sign(&signed_message(&auth_data, &client_data_json));
    let a = Assertion {
        challenge,
        credential_id: b"different".to_vec(),
        client_data_json,
        auth_data,
        signature,
        cose: key.cose.clone(),
    };
    assert_eq!(
        verify_assertion(&check(&a)),
        Err(VerifyError::CredentialIdMismatch)
    );
}

#[test]
fn negative_bad_signature() {
    let key = es256();
    let a = build_assertion(&key);
    let mut c = check(&a);
    // Flip a byte in the signature.
    let mut sig = a.signature.clone();
    sig[0] ^= 0xff;
    c.signature = &sig;
    assert!(matches!(
        verify_assertion(&c),
        Err(VerifyError::SignatureInvalid) | Err(VerifyError::MalformedSignature { .. })
    ));
}

#[test]
fn negative_signature_over_wrong_message() {
    let key = es256();
    let mut a = build_assertion(&key);
    a.signature = key.signer.sign(b"a completely different message");
    assert_eq!(
        verify_assertion(&check(&a)),
        Err(VerifyError::SignatureInvalid)
    );
}

#[test]
fn negative_rs256_signature_wrong_encoding() {
    // An ES256 DER signature replayed against an RS256 key must not panic.
    let es = build_assertion(&es256());
    let rs = build_assertion(&rs256());
    let a = Assertion {
        cose: rs.cose.clone(),
        signature: es.signature.clone(),
        ..es
    };
    assert!(matches!(
        verify_assertion(&check(&a)),
        Err(VerifyError::MalformedSignature { .. }) | Err(VerifyError::SignatureInvalid)
    ));
}

// ---------------------------------------------------------------------------
// COSE allow-list
// ---------------------------------------------------------------------------

#[test]
fn negative_credential_key_disallowed_alg() {
    let a = build_assertion(&es256());
    // A COSE key carrying alg = -47 (ES256K) must be rejected by the allow-list.
    let bad = cbor_map(&[(1, int(2)), (3, int(-47)), (-1, int(1))]);
    let mut c = check(&a);
    c.cose_public_key = &bad;
    assert_eq!(
        verify_assertion(&c),
        Err(VerifyError::UnsupportedAlgorithm { alg: -47 })
    );
}

#[test]
fn negative_credential_key_unknown_alg() {
    let a = build_assertion(&es256());
    let bad = cbor_map(&[(1, int(2)), (3, int(12345))]);
    let mut c = check(&a);
    c.cose_public_key = &bad;
    assert_eq!(
        verify_assertion(&c),
        Err(VerifyError::UnsupportedAlgorithm { alg: 12345 })
    );
}

#[test]
fn negative_credential_key_different_valid_key() {
    // A valid but *different* ES256 key must not verify the signature.
    let a = build_assertion(&es256());
    let other = es256();
    let mut c = check(&a);
    c.cose_public_key = &other.cose;
    assert_eq!(verify_assertion(&c), Err(VerifyError::SignatureInvalid));
}

#[test]
fn negative_credential_key_malformed_cbor() {
    let a = build_assertion(&es256());
    let mut c = check(&a);
    c.cose_public_key = &[0xff, 0x00, 0x00];
    assert!(matches!(
        verify_assertion(&c),
        Err(VerifyError::MalformedCoseKey { .. })
    ));
}

#[test]
fn negative_credential_key_compressed_point() {
    let a = build_assertion(&es256());
    let compressed = cbor_map(&[
        (1, int(2)),
        (3, int(-7)),
        (-1, int(1)),
        (-2, bytes(vec![0x02u8; 32])),
        (-3, bytes(vec![0x00u8; 32])),
    ]);
    let mut c = check(&a);
    c.cose_public_key = &compressed;
    assert_eq!(verify_assertion(&c), Err(VerifyError::CosePointNotOnCurve));
}

#[test]
fn negative_credential_key_bad_x_length() {
    let a = build_assertion(&es256());
    let bad = cbor_map(&[
        (1, int(2)),
        (3, int(-7)),
        (-1, int(1)),
        (-2, bytes(vec![0u8; 31])),
        (-3, bytes(vec![0u8; 32])),
    ]);
    let mut c = check(&a);
    c.cose_public_key = &bad;
    assert!(matches!(
        verify_assertion(&c),
        Err(VerifyError::MalformedCoseKey { .. })
    ));
}

#[test]
fn negative_client_data_challenge_not_base64url() {
    let key = es256();
    let mut a = build_assertion(&key);
    a.client_data_json = br#"{"type":"webauthn.get","challenge":"!!!not-base64!!!","origin":"io.github.kirin-xiao.wsl-webauthn-pam"}"#.to_vec();
    a.signature = key
        .signer
        .sign(&signed_message(&a.auth_data, &a.client_data_json));
    assert!(matches!(
        verify_assertion(&check(&a)),
        Err(VerifyError::MalformedClientData { .. })
    ));
}

// ---------------------------------------------------------------------------
// Counter policy
// ---------------------------------------------------------------------------

#[test]
fn zero_counter_is_accepted() {
    let key = es256();
    let challenge = vec![0x55u8; 32];
    let credential_id = b"zero-counter".to_vec();
    let client_data_json = client_data(ClientDataKind::Get, &challenge);
    let auth_data = build_auth_data(RP_ID, 0x01 | 0x04, 0, None);
    let signature = key
        .signer
        .sign(&signed_message(&auth_data, &client_data_json));
    let a = Assertion {
        challenge,
        credential_id,
        client_data_json,
        auth_data,
        signature,
        cose: key.cose.clone(),
    };
    let outcome = verify_assertion(&check(&a)).expect("zero counter must pass");
    assert_eq!(outcome.sign_count, 0);
}

/// Small helper to build a raw COSE map from `(i64 label, value)` pairs.
fn cbor_map(pairs: &[(i64, CoseValue)]) -> Vec<u8> {
    use ciborium::value::Value;
    let map: Vec<(Value, Value)> = pairs
        .iter()
        .map(|(k, v)| (Value::from(*k), v.to_value()))
        .collect();
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

/// Build an integer COSE value.
fn int(v: i64) -> CoseValue {
    CoseValue::Int(v)
}

/// Build a byte-string COSE value.
fn bytes(v: Vec<u8>) -> CoseValue {
    CoseValue::Bytes(v)
}

/// Either an integer or a byte-string COSE value.
#[derive(Clone)]
enum CoseValue {
    Int(i64),
    Bytes(Vec<u8>),
}

impl CoseValue {
    fn to_value(&self) -> ciborium::value::Value {
        use ciborium::value::Value;
        match self {
            CoseValue::Int(i) => Value::from(*i),
            CoseValue::Bytes(b) => Value::Bytes(b.clone()),
        }
    }
}
