#![no_main]

//! Fuzz the COSE_Key parser: arbitrary bytes must never panic.
//!
//! A spurious `Ok` — accepting a structure the parser should reject — is a fail-open
//! class the bare panic oracle cannot see. A rare marker branch runs a
//! seeded oracle (a genuine key parses; appended or single-byte-corrupted keys are
//! rejected); the marker is committed as `fuzz/corpus/cose_key/seed_oracle`.

use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let _ = wsl_webauthn_verifier::testing::parse_cose_key(data);
    if data.first() == Some(&common::ORACLE_MARKER) {
        common::cose_key_oracle();
    }
});
