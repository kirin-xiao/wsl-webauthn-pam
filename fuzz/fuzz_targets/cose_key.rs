#![no_main]

//! Fuzz the COSE_Key parser: arbitrary bytes must never panic.

use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let _ = wsl_webauthn_verifier::testing::parse_cose_key(data);
});
