#![no_main]

//! Fuzz the attestation-object parser: arbitrary bytes must only ever produce
//! `Ok`/`Err`, never a panic.
//!
//! A rare marker branch runs a seeded oracle asserting that a structurally complete
//! object parses and an object missing any required member (or a non-map) is rejected,
//! so a parser that spuriously returns `Ok` for an incomplete object is caught
//! (L14-10). The marker is committed as
//! `fuzz/corpus/attestation_object/seed_oracle`.

use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let _ = wsl_webauthn_verifier::testing::parse_attestation_object(data);
    if data.first() == Some(&common::ORACLE_MARKER) {
        common::attestation_object_oracle();
    }
});
