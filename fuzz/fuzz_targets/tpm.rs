#![no_main]

//! Fuzz the TPM `certInfo` (`TPMS_ATTEST`) and `pubArea` (`TPMT_PUBLIC`) parsers:
//! arbitrary bytes must never panic (WebAuthn §8.3).
//!
//! A rare marker branch runs a seeded oracle asserting that valid structures parse,
//! every strict truncation is rejected, and (since both parsers consume the whole
//! buffer) an appended byte is rejected too — so a parser that spuriously returns
//! `Ok` for a short or over-long buffer is caught (L14-10). The declared-`keyBits`
//! semantic invariant lives in `tpm::verify`, not this parse seam; see the oracle.
//! The marker is committed as `fuzz/corpus/tpm/seed_oracle`.

use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    // The two TPM parsers consume the whole buffer, so an input accepted by either
    // is self-delimiting; the trailing-byte rejection is therefore implied by the
    // truncation assertions in the oracle.
    let _ = wsl_webauthn_verifier::testing::parse_tpm_cert_info(data);
    let _ = wsl_webauthn_verifier::testing::parse_tpm_pub_area(data);
    if data.first() == Some(&common::ORACLE_MARKER) {
        common::tpm_oracle();
    }
});
