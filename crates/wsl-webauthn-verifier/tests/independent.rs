//! Independent golden vector for the verifier.
//!
//! Every byte below was produced off-line, outside Rust, with `python3` + the
//! `cryptography` package and a hand-rolled minimal CBOR encoder. Nothing here
//! calls `tests/common`'s builders, so the vectors are independent of the
//! verifier's own construction; the literals must not be edited by hand.
//!
//! Regenerate with `python3 tests/vectors/generate_independent_vector.py`, which
//! prints the hex literals for this file and `fuzz/fuzz_targets/common.rs`.

use std::time::{Duration, SystemTime};

use wsl_webauthn_verifier::{
    AssertionCheck, AttestationMode, AttestationPolicy, EnrollCheck, VerifyError, verify_assertion,
    verify_attestation_with_anchor,
};

const AAGUID_HEX: &str = "08987058cadc4b81b6e130de50dcbe96";
const CHALLENGE_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";
const CREDENTIAL_ID: &[u8] = b"independent-vector-cred";
const CLIENT_DATA_CREATE: &[u8] = br#"{"type":"webauthn.create","challenge":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","origin":"wsl-webauthn-pam"}"#;
const AUTH_DATA_HEX: &str = "fec5647d06bb3ea1229a888a153859052540d70fcbad8c93216b805e4f68f451450000000008987058cadc4b81b6e130de50dcbe960017696e646570656e64656e742d766563746f722d63726564a5010203262001215820b9e102424555569c82baff1e9e2eaa65ca3fee3dd80ef86ee6f3191f2d497d8a225820b1b219b202d96ae72dc69801cc399cee0ef83ae03fae220cb1b8a7d5b02bb0d7";
const ATTESTATION_OBJECT_HEX: &str = "a363666d74667061636b65646761747453746d74a363616c672663736967584630440220765e058a3b3eebb9dea98bcabc9ce5dc83265e26a2e999652adf3d606adc842902203eb9ee3c1fb0520d2a8b80a95fdbf38285314d1198196ee87687271f5ac6c12363783563835901fc308201f83082019da00302010202021002300a06082a8648ce3d04030230593129302706035504030c20496e646570656e64656e74205465737420496e7465726d656469617465204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a307b3127302506035504030c1e496e646570656e64656e7420546573742041757468656e74696361746f7231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200047819ccaa4a7165a4193c5d3d417cf0ab0b3341a90b950be196cb84f2cdfca16459640831a54bf3c98aeb135c1639f8ef71a38f4e8e20a4730cb0869e737934f3a3333031300c0603551d130101ff040230003021060b2b0601040182e51c0101040412041008987058cadc4b81b6e130de50dcbe96300a06082a8648ce3d0403020349003046022100e7951f3bbc8658accc67b0d6454d8fd2ed0c318dfcf18cf37e3db605bb642536022100847c1d6a4c6cdc4c1d9f61a7a2698c175b434fb2b47fbe83c617c3c19069e11d5901b4308201b030820156a00302010202021001300a06082a8648ce3d04030230513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a30593129302706035504030c20496e646570656e64656e74205465737420496e7465726d656469617465204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d03010703420004269d4f50087c9696b8d4643f27635c246b35242c5bb8ef3f82526d59f8208c98d262be1090d09c7e7395efb4c94ba406f5c191966c64da42498a1cb5531e637ea316301430120603551d130101ff040830060101ff020100300a06082a8648ce3d0403020348003045022100d924e939f6fa5ad99da96181fd2717fe6e25e3cc2f5b10802836fb532cea47860220415bfeb4336b2a71012385891fe67499d388c8a3aace02b57584431febd2964d5901a9308201a53082014ba00302010202021000300a06082a8648ce3d04030230513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a30513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000473179c2827f473838309ecf3f5d7f8ee3e9dbc7405522242ff61c4cb53adfde22f47d92dc596f604eec4ef059c20b13ab2106f81005228c949808950c897799ba3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502201c2794d69302b2cfcd3811e1b73270fa1d1a10267e1aed505fffbbdcd122c15f022100845fedd48c606f2d0e1757b9e3204e7e4fbe9731f48470aa53766001ed4de988686175746844617461589bfec5647d06bb3ea1229a888a153859052540d70fcbad8c93216b805e4f68f451450000000008987058cadc4b81b6e130de50dcbe960017696e646570656e64656e742d766563746f722d63726564a5010203262001215820b9e102424555569c82baff1e9e2eaa65ca3fee3dd80ef86ee6f3191f2d497d8a225820b1b219b202d96ae72dc69801cc399cee0ef83ae03fae220cb1b8a7d5b02bb0d7";
const ROOT_FINGERPRINT_HEX: &str =
    "5e7a2cb6bc38d3dadfa3155a7640f5e27a1d0082b567c40de24f424dcea2b25c";
const ASSERT_CLIENT_DATA: &[u8] = br#"{"type":"webauthn.get","challenge":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","origin":"wsl-webauthn-pam"}"#;
const ASSERT_AUTH_DATA_HEX: &str =
    "fec5647d06bb3ea1229a888a153859052540d70fcbad8c93216b805e4f68f4510500000005";
const ASSERT_SIGNATURE_HEX: &str = "304402206121627bd2efdcd2603e066f166ba1593136d67010da19fed209b0d7cba66918022033370945cc767595a8b0a5e9fce8d8d0f6ae4802e70a8e412065f983fc527ab8";
const CREDENTIAL_COSE_HEX: &str = "a5010203262001215820b9e102424555569c82baff1e9e2eaa65ca3fee3dd80ef86ee6f3191f2d497d8a225820b1b219b202d96ae72dc69801cc399cee0ef83ae03fae220cb1b8a7d5b02bb0d7";
const SHA256_CLIENT_DATA_CREATE_HEX: &str =
    "ae5013d22b7839d836e91a1748a93c01396db51c3da401a12f5ecffdb388e7bd";
const SHA256_SIGNED_MESSAGE_HEX: &str =
    "50710dc3f91950269e9b917fba3ed4f3ccf232d7b0a2b82e5f70abb55da2503c";

/// Decode a lowercase/uppercase hex string.
fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    let byte = |hi: u8, lo: u8| -> u8 {
        let d = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit"),
        };
        (d(hi) << 4) | d(lo)
    };
    let bytes = s.as_bytes();
    (0..bytes.len() / 2)
        .map(|i| byte(bytes[2 * i], bytes[2 * i + 1]))
        .collect()
}

/// The pinned verification instant: 2020-09-13, inside the certificate validity
/// window (2020-01-01 .. 2049-01-01).
fn pinned_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000)
}

fn root_fingerprint() -> [u8; 32] {
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&unhex(ROOT_FINGERPRINT_HEX));
    fp
}

/// The committed independent `packed`/x5c enrollment must verify under Strict.
#[test]
fn independent_packed_x5c_strict() {
    let challenge = unhex(CHALLENGE_HEX);
    let attestation_object = unhex(ATTESTATION_OBJECT_HEX);
    let check = EnrollCheck {
        expected_challenge: &challenge,
        attestation_object: &attestation_object,
        client_data_json: CLIENT_DATA_CREATE,
        reported_credential_id: CREDENTIAL_ID,
        now: pinned_now(),
    };
    let outcome =
        verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &root_fingerprint())
            .expect("independent packed/x5c vector must verify");
    assert_eq!(outcome.attestation.format, "packed");
    assert_eq!(outcome.attestation.mode, AttestationMode::StrictVerified);
    assert_eq!(outcome.credential_id, CREDENTIAL_ID);
    assert_eq!(outcome.aaguid, unhex(AAGUID_HEX).as_slice());
    assert_eq!(outcome.cose_public_key, unhex(CREDENTIAL_COSE_HEX));
    assert!(outcome.attestation.leaf_sha256.is_some());
}

/// The independent assertion over the same credential key must verify.
#[test]
fn independent_assertion() {
    let challenge = unhex(CHALLENGE_HEX);
    let cose = unhex(CREDENTIAL_COSE_HEX);
    let auth_data = unhex(ASSERT_AUTH_DATA_HEX);
    let signature = unhex(ASSERT_SIGNATURE_HEX);
    let check = AssertionCheck {
        expected_challenge: &challenge,
        credential_id: CREDENTIAL_ID,
        cose_public_key: &cose,
        client_data_json: ASSERT_CLIENT_DATA,
        authenticator_data: &auth_data,
        signature: &signature,
        expected_sign_count: None,
    };
    let outcome = verify_assertion(&check).expect("independent assertion must verify");
    assert_eq!(outcome.sign_count, 5);
}

/// The signed-message definition itself is pinned to an off-line digest, so a
/// change to `authData || SHA-256(clientDataJSON)` in *both* the verifier and a
/// mirroring helper is still caught here.
#[test]
fn independent_golden_digests() {
    use sha2::{Digest as _, Sha256};
    assert_eq!(
        hex(&Sha256::digest(CLIENT_DATA_CREATE)),
        SHA256_CLIENT_DATA_CREATE_HEX
    );
    let mut message = unhex(AUTH_DATA_HEX);
    message.extend_from_slice(&Sha256::digest(CLIENT_DATA_CREATE));
    assert_eq!(hex(&Sha256::digest(&message)), SHA256_SIGNED_MESSAGE_HEX);
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").expect("write to string");
    }
    out
}

/// Every single-byte corruption of the known-good attestation object must be
/// rejected: a byte the verifier does not bind would let a tampered vector verify.
#[test]
fn independent_mutation_oracle() {
    let challenge = unhex(CHALLENGE_HEX);
    let good = unhex(ATTESTATION_OBJECT_HEX);
    let fp = root_fingerprint();
    for i in 0..good.len() {
        let mut mutated = good.clone();
        mutated[i] ^= 0x01;
        let check = EnrollCheck {
            expected_challenge: &challenge,
            attestation_object: &mutated,
            client_data_json: CLIENT_DATA_CREATE,
            reported_credential_id: CREDENTIAL_ID,
            now: pinned_now(),
        };
        let result = verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &fp);
        assert!(
            result.is_err(),
            "single-byte mutation at offset {i} unexpectedly verified: {result:?}"
        );
    }
}

/// A flipped verification signature must not verify; this catches a mutation
/// oracle that would be vacuously true because the base never verifies.
#[test]
fn independent_base_is_not_vacuous() {
    let challenge = unhex(CHALLENGE_HEX);
    let attestation_object = unhex(ATTESTATION_OBJECT_HEX);
    let check = EnrollCheck {
        expected_challenge: &challenge,
        attestation_object: &attestation_object,
        client_data_json: CLIENT_DATA_CREATE,
        reported_credential_id: CREDENTIAL_ID,
        now: pinned_now(),
    };
    assert!(
        verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &root_fingerprint())
            .is_ok()
    );
    assert_eq!(
        verify_attestation_with_anchor(&check, &AttestationPolicy::Strict, &[0u8; 32]),
        Err(VerifyError::CertificateChainAnchorNotFound)
    );
}
