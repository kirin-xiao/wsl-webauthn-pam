#![no_main]

//! Fuzz the `authenticatorData` prefix parser: arbitrary bytes must never panic.
//!
//! A rare marker branch runs a seeded oracle asserting that a valid 37-byte prefix
//! parses and every strict truncation below 37 bytes is rejected, so a parser that
//! spuriously returns `Ok` for a too-short prefix is caught (L14-10). The marker is
//! committed as `fuzz/corpus/authenticator_data/seed_oracle`.

use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let _ = wsl_webauthn_verifier::testing::parse_authenticator_data(data);
    if data.first() == Some(&common::ORACLE_MARKER) {
        common::authenticator_data_oracle();
    }
});
