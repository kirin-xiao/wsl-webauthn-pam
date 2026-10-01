#![no_main]

//! Fuzz the `authenticatorData` prefix parser: arbitrary bytes must never panic.

use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let _ = wsl_webauthn_verifier::testing::parse_authenticator_data(data);
});
