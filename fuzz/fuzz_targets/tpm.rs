#![no_main]

//! Fuzz the TPM `certInfo` (`TPMS_ATTEST`) and `pubArea` (`TPMT_PUBLIC`) parsers:
//! arbitrary bytes must never panic (WebAuthn §8.3).

use libfuzzer_sys::fuzz_target;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    let _ = wsl_webauthn_verifier::testing::parse_tpm_cert_info(data);
    let _ = wsl_webauthn_verifier::testing::parse_tpm_pub_area(data);
});
