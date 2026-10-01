#![no_main]

//! Fuzz the attestation-object parser: arbitrary bytes must only ever produce
//! `Ok`/`Err`, never a panic.

use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let _ = wsl_webauthn_verifier::testing::parse_attestation_object(data);
});
