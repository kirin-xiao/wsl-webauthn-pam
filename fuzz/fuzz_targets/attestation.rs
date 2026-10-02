#![no_main]

//! Fuzz the **full** attestation (enrollment) verification path under both
//! policies — the X.509 chain walker, the packed/tpm leaf-shape state machine, and
//! the TPM `certInfo`/`pubArea` semantic checks were previously reachable only
//! through hand-built fixtures (L14-1).
//!
//! Two shapes are exercised per input:
//!
//! 1. **Raw:** the whole input is the CBOR `attestationObject`. This is the pure
//!    panic/robustness oracle: arbitrary bytes must only ever yield `Ok`/`Err`.
//! 2. **Stitched:** a valid `clientDataJSON` and a valid `authenticatorData`
//!    (correct `rpIdHash`, UP|UV|AT, a synthetic ES256 credential key) frame
//!    arbitrary input bytes as the `attStmt` `x5c`/`certInfo`/`pubArea`/`sig`. This
//!    drives the arbitrary DER into `chain::verify_chain`, where
//!    `x509_cert::Certificate::from_der` and the link/leaf checks run.
//!
//! The chain entry (`chain::verify_chain`) is `pub(crate)` and takes a
//! `&[Vec<u8>]`, so it is not directly reachable from the public/test API; the
//! stitched shape below is the chain-oriented coverage the task asks for. `Ok`
//! results are only reachable through a genuine verification (the verifier is
//! unchanged), so no `Ok` is asserted here.

use ciborium::value::Value;
use libfuzzer_sys::fuzz_target;
use wsl_webauthn_verifier::{AttestationPolicy, EnrollCheck, verify_attestation_with_anchor};

#[path = "common.rs"]
mod common;

/// `SHA-256("io.github.kirin-xiao.wsl-webauthn-pam")`, i.e. the pinned `rpIdHash`.
const RP_ID_HASH: [u8; 32] = [
    0x7c, 0x76, 0x94, 0x27, 0x98, 0x25, 0x3f, 0x3d, 0xac, 0xc9, 0x92, 0x03, 0x09, 0xf0, 0xb8, 0x77,
    0x35, 0xaa, 0x5d, 0xe2, 0x1d, 0xda, 0xe6, 0x15, 0xce, 0xf2, 0x62, 0x55, 0xa7, 0xb0, 0xe4, 0xfc,
];

/// Feed arbitrary bytes as the entire `attestationObject` through both policies.
fn raw_attestation(data: &[u8]) {
    let challenge = [0x11u8; 32];
    let client_data_json = wsl_webauthn_protocol::build_client_data(
        wsl_webauthn_protocol::ClientDataKind::Create,
        &challenge,
    )
    .expect("challenge is long enough");
    let check = EnrollCheck::new(&challenge, data, &client_data_json, b"fuzz-credential");
    let anchor = [0u8; 32];
    let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &anchor);
    let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::AllowUnattested, &anchor);
}

/// A valid `authenticatorData` (fixed `rpIdHash`, `UP|UV|AT`, synthetic ES256 key,
/// fixed credential id) so the input can drive the attestation statement rather
/// than being rejected at the `authData` step.
fn valid_auth_data() -> Option<Vec<u8>> {
    let cose = common::synthetic_cose_key();
    if cose.is_empty() {
        return None;
    }
    let credential_id = b"fuzz-credential";
    let mut auth_data = Vec::with_capacity(37 + 16 + 2 + credential_id.len() + cose.len());
    auth_data.extend_from_slice(&RP_ID_HASH);
    auth_data.push(0x45); // UP | UV | AT
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&[0u8; 16]); // AAGUID (allow-list fails later; fine)
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(&cose);
    Some(auth_data)
}

/// Frame arbitrary bytes as an `attStmt` inside a structurally valid attestation
/// object, then run the full verifier under both policies.
fn stitched_attestation(data: &[u8]) {
    let Some(auth_data) = valid_auth_data() else {
        return;
    };
    let selector = data.first().copied().unwrap_or(0);
    let body = data.get(1..).unwrap_or(&[]);
    let mid = body.len() / 2;
    let (cert_blob, tail) = body.split_at(mid);
    let alg = tail
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map(i64::from_le_bytes)
        .unwrap_or(0i64);
    let x5c = Value::Array(vec![Value::Bytes(cert_blob.to_vec())]);

    let att_stmt = if selector & 1 == 0 {
        // packed / x5c
        Value::Map(vec![
            (Value::from("alg"), Value::from(alg)),
            (Value::from("sig"), Value::Bytes(tail.to_vec())),
            (Value::from("x5c"), x5c),
        ])
    } else {
        // tpm
        Value::Map(vec![
            (Value::from("ver"), Value::from("2.0")),
            (Value::from("alg"), Value::from(alg)),
            (Value::from("sig"), Value::Bytes(tail.to_vec())),
            (Value::from("certInfo"), Value::Bytes(cert_blob.to_vec())),
            (Value::from("pubArea"), Value::Bytes(tail.to_vec())),
            (Value::from("x5c"), x5c),
        ])
    };

    let obj = Value::Map(vec![
        (Value::from("fmt"), Value::from(if selector & 1 == 0 { "packed" } else { "tpm" })),
        (Value::from("attStmt"), att_stmt),
        (Value::from("authData"), Value::Bytes(auth_data)),
    ]);
    let mut attestation_object = Vec::new();
    if ciborium::into_writer(&obj, &mut attestation_object).is_err() {
        return;
    }

    let challenge = [0x22u8; 32];
    let client_data_json = wsl_webauthn_protocol::build_client_data(
        wsl_webauthn_protocol::ClientDataKind::Create,
        &challenge,
    )
    .expect("challenge is long enough");
    let check = EnrollCheck::new(
        &challenge,
        &attestation_object,
        &client_data_json,
        b"fuzz-credential",
    );
    let anchor = [0u8; 32];
    let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &anchor);
    let _ = verify_attestation_with_anchor(&check, &AttestationPolicy::AllowUnattested, &anchor);
}

/// Fail-open oracle over an **independent** (non-Rust) golden vector: a known-good
/// `packed`/x5c object must verify, one bit of its signature must not, and a
/// single-byte mutation anywhere in the object must be rejected. This catches a
/// verifier that returns `Ok` without genuinely binding the signed message (L14-5,
/// L14-10) and does not use the synthesized-vector helpers.
fn independent_oracle() {
    let challenge = common::unhex(common::INDEPENDENT_CHALLENGE_HEX);
    let good = common::unhex(common::INDEPENDENT_ATTESTATION_OBJECT_HEX);
    let client_data_json = common::INDEPENDENT_CLIENT_DATA_CREATE;
    let credential_id = common::INDEPENDENT_CREDENTIAL_ID;
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&common::unhex(common::INDEPENDENT_ROOT_FINGERPRINT_HEX));
    let now = common::independent_now();

    let check = EnrollCheck {
        expected_challenge: &challenge,
        attestation_object: &good,
        client_data_json,
        reported_credential_id: credential_id,
        now,
    };
    assert!(
        verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &fingerprint).is_ok(),
        "the independent golden vector must verify"
    );

    // Mutate bytes from structurally significant regions: the CBOR header, the
    // `sig`/`x5c` interior, and the tail. All must be rejected.
    for i in [0usize, good.len() / 3, good.len() / 2, good.len() - 1] {
        let mut mutated = good.clone();
        mutated[i] ^= 0x01;
        let check = EnrollCheck {
            expected_challenge: &challenge,
            attestation_object: &mutated,
            client_data_json,
            reported_credential_id: credential_id,
            now,
        };
        assert!(
            verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &fingerprint).is_err(),
            "independent vector mutation at offset {i} must be rejected"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    raw_attestation(data);
    stitched_attestation(data);
    // Rare seeded branch: run the independent fail-open oracle once per corpus
    // exploration of this marker, not on every iteration.
    if data.first() == Some(&0xAB) {
        independent_oracle();
    }
});
