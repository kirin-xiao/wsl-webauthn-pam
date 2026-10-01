#![no_main]

//! Fuzz the full assertion verification path with a synthetic pinned key and a
//! fixed clientData. Arbitrary `authenticatorData`/`signature` bytes must only ever
//! produce `Ok`/`Err`, never a panic.

use libfuzzer_sys::fuzz_target;
use wsl_webauthn_verifier::{AssertionCheck, verify_assertion};

#[path = "common.rs"]
mod common;

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
});
