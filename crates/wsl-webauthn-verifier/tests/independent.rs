//! Independent golden vector for the verifier.
//!
//! Every byte below was produced **off-line, outside Rust**, by
//! `python3` + the `cryptography` package and a hand-rolled minimal CBOR
//! encoder: the ECDSA P-256 certificate chain, the `packed` attestation
//! object, the credential COSE key, the `clientDataJSON`, and both signatures.
//! Nothing here calls `tests/common`'s builders, so the suite no longer relies
//! solely on helpers that mirror the verifier's own construction (L14-5).
//!
//! The synthetic CA/leaf names are obviously fake ("Independent Test …"); no
//! real machine identifier, serial, key, or user is present. The trust anchor
//! is the test root, injected through the `test-anchor` seam exactly as the
//! other synthesized chains are.
//!
//! Regeneration recipe (recorded for provenance; do not edit the literals by
//! hand): build a P-256 root → P-256 intermediate → P-256 leaf whose Subject OU
//! is `Authenticator Attestation` and whose
//! `1.3.6.1.4.1.45724.1.1.4` extension carries the AAGUID; sign
//! `authData || SHA-256(clientDataJSON)` with the leaf key; sign a `webauthn.get`
//! over the same message shape with the credential key.

use std::time::{Duration, SystemTime};

use wsl_webauthn_verifier::{
    AssertionCheck, AttestationMode, AttestationPolicy, EnrollCheck, VerifyError, verify_assertion,
    verify_attestation_with_anchor,
};

const AAGUID_HEX: &str = "08987058cadc4b81b6e130de50dcbe96";
const CHALLENGE_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";
const CREDENTIAL_ID: &[u8] = b"independent-vector-cred";
const CLIENT_DATA_CREATE: &[u8] = br#"{"type":"webauthn.create","challenge":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","origin":"io.github.kirin-xiao.wsl-webauthn-pam"}"#;
const AUTH_DATA_HEX: &str = "7c76942798253f3dacc9920309f0b87735aa5de21ddae615cef26255a7b0e4fc450000000008987058cadc4b81b6e130de50dcbe960017696e646570656e64656e742d766563746f722d63726564a5010203262001215820df67a461578cbb4205d8dd682de06a7dfa90c91b4967c1190d12f6e423ff118722582026dca882bc2d5b2d6f2ea860e8bb7832b5b4be4d05a16152a00a62eb45c2921b";
const ATTESTATION_OBJECT_HEX: &str = "a363666d74667061636b65646761747453746d74a363616c672663736967584730450221009cdec46bdc6fb2a18c80dc2fbd6bc8d8c7562e40848a13a7caa310c84b8abb4e02200e0a1f198414b5269d39b28c4a4dd1ad619f5fbef30dbe07135270945e85337563783563835901fb308201f73082019da00302010202021002300a06082a8648ce3d04030230593129302706035504030c20496e646570656e64656e74205465737420496e7465726d656469617465204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a307b3127302506035504030c1e496e646570656e64656e7420546573742041757468656e74696361746f7231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200048a739ac71b231020ed10b98be3fb20c4dc9397892408960b9d3f8234a7f78b2f7c9e4bc67544ff10c212241a7ffe41baa33bf517ce3c8b191011812959ec5448a3333031300c0603551d130101ff040230003021060b2b0601040182e51c0101040412041008987058cadc4b81b6e130de50dcbe96300a06082a8648ce3d04030203480030450220796d078496324b1c763b741a55721490f6bf274d0f8e17630c88428205804c65022100a2e06aaa44a37c5af8507154575dc641aacf7bb60970de6c77bffcd52a7d57ce5901b5308201b130820156a00302010202021001300a06082a8648ce3d04030230513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a30593129302706035504030c20496e646570656e64656e74205465737420496e7465726d656469617465204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200042d862609bebf2b224e1400dc9b12c09b6fd849b01d9e7eb851093b717789a9ec87592ef4c0fd578bc804a3563af1580dc6ad3360e7c45a02cf6b73a2b0597c1ea316301430120603551d130101ff040830060101ff020100300a06082a8648ce3d040302034900304602210080f9f0a331743ca24f112f9bb19d82398076369ce64ec7ba9c75b86334f03b0e022100d209a300e49a679e07517caea92596a40ffd66c40ff712975b4bbc32510a1e945901a9308201a53082014ba00302010202021000300a06082a8648ce3d04030230513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a30513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000442bd9b9ef257cf254f533ab4d69e03923237556e3ff71dddd331a7efdc2cb4e50f0ebd418dc951724532e3d0ad8a9183c394a783008956abeb0998966ef537b7a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100fc8ca919350909be1058cc422344e99e0e3679ac447a4dfa3a9462ce8af65eb3022048d3e7b2c163aa5df0936608c29bdc282e4044c45c21be155d2e4da0453a14f9686175746844617461589b7c76942798253f3dacc9920309f0b87735aa5de21ddae615cef26255a7b0e4fc450000000008987058cadc4b81b6e130de50dcbe960017696e646570656e64656e742d766563746f722d63726564a5010203262001215820df67a461578cbb4205d8dd682de06a7dfa90c91b4967c1190d12f6e423ff118722582026dca882bc2d5b2d6f2ea860e8bb7832b5b4be4d05a16152a00a62eb45c2921b";
const ROOT_FINGERPRINT_HEX: &str =
    "85cdbb005ca4cd02354d73677455c9366f69d1f669f78b244ad4041b1b6628bc";
const ASSERT_CLIENT_DATA: &[u8] = br#"{"type":"webauthn.get","challenge":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","origin":"io.github.kirin-xiao.wsl-webauthn-pam"}"#;
const ASSERT_AUTH_DATA_HEX: &str =
    "7c76942798253f3dacc9920309f0b87735aa5de21ddae615cef26255a7b0e4fc0500000005";
const ASSERT_SIGNATURE_HEX: &str = "3045022100c28a9dd2e47523bcd6177908a7da3f387b37008fdcc62a7b06647624bf682eb102202cb58705ff930bbf1d07ecd98c0c02ae2f69141c668d8f558e1a65148cb354f1";
const CREDENTIAL_COSE_HEX: &str = "a5010203262001215820df67a461578cbb4205d8dd682de06a7dfa90c91b4967c1190d12f6e423ff118722582026dca882bc2d5b2d6f2ea860e8bb7832b5b4be4d05a16152a00a62eb45c2921b";
const SHA256_CLIENT_DATA_CREATE_HEX: &str =
    "00aa847cadd1c47f4710f814f57f16e480e345d522032712703ef7930a2300f0";
const SHA256_SIGNED_MESSAGE_HEX: &str =
    "03e13ca9849de18c713fa277edd4c04f5ae060e37176e2e9f83766c7ca4998bf";

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

/// The pinned verification instant: 2020-09-13, comfortably inside the
/// certificate validity window (2020-01-01 .. 2049-01-01).
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

/// Mutation oracle (L14-5b): every single-byte corruption of the known-good
/// attestation object must be rejected. A byte that the verifier does not bind
/// would let a tampered vector verify, so a single `Ok` fails this test.
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

/// Sanity: a flipped verification signature must not verify (guards against a
/// mutation oracle that is vacuously true because the base never verifies).
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
