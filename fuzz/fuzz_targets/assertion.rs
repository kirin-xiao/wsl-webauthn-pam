#![no_main]

//! Fuzz the full assertion verification path with a synthetic pinned key and a
//! fixed clientData. Arbitrary `authenticatorData`/`signature` bytes must only ever
//! produce `Ok`/`Err`, never a panic.
//!
//! A seeded branch builds a valid signature over a fixed message, asserts it
//! verifies, then flips one byte and asserts the result is `Err`, so a verifier
//! that spuriously accepts (`Ok`) without a genuine signature is caught. The
//! branch is gated on a rare marker so it does not slow the main libFuzzer
//! throughput materially.

use libfuzzer_sys::fuzz_target;
use wsl_webauthn_verifier::{AssertionCheck, verify_assertion};

#[path = "common.rs"]
mod common;

/// `SHA-256("wsl-webauthn-pam")`, the pinned `rpIdHash`.
const RP_ID_HASH: [u8; 32] = [
    0xfe, 0xc5, 0x64, 0x7d, 0x06, 0xbb, 0x3e, 0xa1, 0x22, 0x9a, 0x88, 0x8a, 0x15, 0x38, 0x59, 0x05,
    0x25, 0x40, 0xd7, 0x0f, 0xcb, 0xad, 0x8c, 0x93, 0x21, 0x6b, 0x80, 0x5e, 0x4f, 0x68, 0xf4, 0x51,
];

/// A valid assertion must verify; a single flipped byte must be rejected.
fn assert_no_spurious_ok(challenge: &[u8], client_data_json: &[u8], cose: &[u8]) {
    use p256::ecdsa::signature::Signer as _;
    use sha2::{Digest as _, Sha256};

    let sk = common::synthetic_signing_key();
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&RP_ID_HASH);
    auth_data.push(0x05); // UP | UV
    auth_data.extend_from_slice(&0u32.to_be_bytes());

    let mut message = auth_data.clone();
    message.extend_from_slice(&Sha256::digest(client_data_json));

    let good_sig: p256::ecdsa::DerSignature = sk.sign(&message);
    let good = good_sig.as_bytes().to_vec();
    let check = AssertionCheck::new(
        challenge,
        b"fuzz-credential",
        cose,
        client_data_json,
        &auth_data,
        &good,
    );
    assert!(
        verify_assertion(&check).is_ok(),
        "a genuinely signed assertion must verify"
    );

    // Flip one bit of the signature: verification must fail.
    let mut bad = good.clone();
    bad[0] ^= 0x01;
    let check = AssertionCheck::new(
        challenge,
        b"fuzz-credential",
        cose,
        client_data_json,
        &auth_data,
        &bad,
    );
    assert!(
        verify_assertion(&check).is_err(),
        "a tampered signature must not verify"
    );

    // Flip one bit of the authenticator data: verification must fail.
    let mut bad_ad = auth_data.clone();
    bad_ad[32] ^= 0x01;
    let check = AssertionCheck::new(
        challenge,
        b"fuzz-credential",
        cose,
        client_data_json,
        &bad_ad,
        &good,
    );
    assert!(
        verify_assertion(&check).is_err(),
        "tampered authenticator data must not verify"
    );
}

fuzz_target!(|data: &[u8]| {
    let (auth_data, signature) = common::split(data);
    let cose = common::synthetic_cose_key();
    let challenge = [0x11u8; 32];
    let client_data_json = wsl_webauthn_protocol::build_client_data(
        wsl_webauthn_protocol::ClientDataKind::Get,
        &challenge,
    )
    .unwrap();
    let check = AssertionCheck::new(
        &challenge,
        b"fuzz-credential",
        &cose,
        &client_data_json,
        auth_data,
        signature,
    );
    let _ = verify_assertion(&check);

    // Rare seeded branch: run the no-spurious-`Ok` oracle exactly once per corpus
    // exploration of this marker, without signing on every iteration.
    if data.first() == Some(&0xAB) {
        assert_no_spurious_ok(&challenge, &client_data_json, &cose);
    }
});
