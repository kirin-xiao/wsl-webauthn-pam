//! Shared helpers and fail-open oracles for the fuzz targets.
//!
//! Arbitrary inputs may still legitimately return either `Ok` or `Err` — the primary
//! contract is "never panic". The parser targets additionally run seeded oracles that
//! assert a spurious `Ok` (accepting malformed or semantically-wrong input) is caught
//! rather than discarded (L14-10). See the per-oracle comments below.

#![allow(dead_code)]

use ciborium::value::Value;
use sha2::{Digest as _, Sha256};
use wsl_webauthn_verifier::testing;

/// First input byte that triggers the seeded fail-open oracle branch. A committed
/// seed beginning with this byte keeps the branch on the warm corpus.
pub const ORACLE_MARKER: u8 = 0xAB;

/// The deterministic synthetic ES256 signing key backing [`synthetic_cose_key`].
///
/// A fixed 32-byte scalar is a valid P-256 secret key with overwhelming
/// probability; retry deterministically if it is not.
pub fn synthetic_signing_key() -> p256::ecdsa::SigningKey {
    for seed in 1u8..=255 {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        if let Ok(sk) = p256::ecdsa::SigningKey::from_slice(&bytes) {
            return sk;
        }
    }
    unreachable!("deterministic P-256 seed space always yields a valid key")
}

/// A deterministic synthetic ES256 COSE key used as the "pinned" credential key.
pub fn synthetic_cose_key() -> Vec<u8> {
    let sk = synthetic_signing_key();
    let point = sk.verifying_key().to_encoded_point(false);
    let map = vec![
        (Value::from(1i64), Value::from(2i64)),
        (Value::from(3i64), Value::from(-7i64)),
        (Value::from(-1i64), Value::from(1i64)),
        (Value::from(-2i64), Value::Bytes(point.x().unwrap().to_vec())),
        (Value::from(-3i64), Value::Bytes(point.y().unwrap().to_vec())),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
    out
}

// Independent (non-Rust) golden vector: generated off-line with python3 +
// cryptography + a hand-rolled minimal CBOR encoder (tests/vectors/README.md).
// No Rust helper here builds it, so it is a genuine second implementation.
pub const INDEPENDENT_CHALLENGE_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";
pub const INDEPENDENT_CREDENTIAL_ID: &[u8] = b"independent-vector-cred";
pub const INDEPENDENT_CLIENT_DATA_CREATE: &[u8] = br#"{"type":"webauthn.create","challenge":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","origin":"io.github.kirin-xiao.wsl-webauthn-pam"}"#;
pub const INDEPENDENT_ATTESTATION_OBJECT_HEX: &str = "a363666d74667061636b65646761747453746d74a363616c672663736967584730450221009cdec46bdc6fb2a18c80dc2fbd6bc8d8c7562e40848a13a7caa310c84b8abb4e02200e0a1f198414b5269d39b28c4a4dd1ad619f5fbef30dbe07135270945e85337563783563835901fb308201f73082019da00302010202021002300a06082a8648ce3d04030230593129302706035504030c20496e646570656e64656e74205465737420496e7465726d656469617465204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a307b3127302506035504030c1e496e646570656e64656e7420546573742041757468656e74696361746f7231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200048a739ac71b231020ed10b98be3fb20c4dc9397892408960b9d3f8234a7f78b2f7c9e4bc67544ff10c212241a7ffe41baa33bf517ce3c8b191011812959ec5448a3333031300c0603551d130101ff040230003021060b2b0601040182e51c0101040412041008987058cadc4b81b6e130de50dcbe96300a06082a8648ce3d04030203480030450220796d078496324b1c763b741a55721490f6bf274d0f8e17630c88428205804c65022100a2e06aaa44a37c5af8507154575dc641aacf7bb60970de6c77bffcd52a7d57ce5901b5308201b130820156a00302010202021001300a06082a8648ce3d04030230513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a30593129302706035504030c20496e646570656e64656e74205465737420496e7465726d656469617465204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200042d862609bebf2b224e1400dc9b12c09b6fd849b01d9e7eb851093b717789a9ec87592ef4c0fd578bc804a3563af1580dc6ad3360e7c45a02cf6b73a2b0597c1ea316301430120603551d130101ff040830060101ff020100300a06082a8648ce3d040302034900304602210080f9f0a331743ca24f112f9bb19d82398076369ce64ec7ba9c75b86334f03b0e022100d209a300e49a679e07517caea92596a40ffd66c40ff712975b4bbc32510a1e945901a9308201a53082014ba00302010202021000300a06082a8648ce3d04030230513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a30513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000442bd9b9ef257cf254f533ab4d69e03923237556e3ff71dddd331a7efdc2cb4e50f0ebd418dc951724532e3d0ad8a9183c394a783008956abeb0998966ef537b7a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100fc8ca919350909be1058cc422344e99e0e3679ac447a4dfa3a9462ce8af65eb3022048d3e7b2c163aa5df0936608c29bdc282e4044c45c21be155d2e4da0453a14f9686175746844617461589b7c76942798253f3dacc9920309f0b87735aa5de21ddae615cef26255a7b0e4fc450000000008987058cadc4b81b6e130de50dcbe960017696e646570656e64656e742d766563746f722d63726564a5010203262001215820df67a461578cbb4205d8dd682de06a7dfa90c91b4967c1190d12f6e423ff118722582026dca882bc2d5b2d6f2ea860e8bb7832b5b4be4d05a16152a00a62eb45c2921b";
pub const INDEPENDENT_ROOT_FINGERPRINT_HEX: &str = "85cdbb005ca4cd02354d73677455c9366f69d1f669f78b244ad4041b1b6628bc";
pub const INDEPENDENT_ASSERT_CLIENT_DATA: &[u8] = br#"{"type":"webauthn.get","challenge":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","origin":"io.github.kirin-xiao.wsl-webauthn-pam"}"#;
pub const INDEPENDENT_ASSERT_AUTH_DATA_HEX: &str = "7c76942798253f3dacc9920309f0b87735aa5de21ddae615cef26255a7b0e4fc0500000005";
pub const INDEPENDENT_ASSERT_SIGNATURE_HEX: &str = "3045022100c28a9dd2e47523bcd6177908a7da3f387b37008fdcc62a7b06647624bf682eb102202cb58705ff930bbf1d07ecd98c0c02ae2f69141c668d8f558e1a65148cb354f1";
pub const INDEPENDENT_CREDENTIAL_COSE_HEX: &str = "a5010203262001215820df67a461578cbb4205d8dd682de06a7dfa90c91b4967c1190d12f6e423ff118722582026dca882bc2d5b2d6f2ea860e8bb7832b5b4be4d05a16152a00a62eb45c2921b";
pub const INDEPENDENT_SIGNED_MESSAGE_SHA256_HEX: &str = "03e13ca9849de18c713fa277edd4c04f5ae060e37176e2e9f83766c7ca4998bf";

/// Decode a hex string into bytes.
pub fn unhex(s: &str) -> Vec<u8> {
    let d = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("bad hex digit"),
    };
    let bytes = s.as_bytes();
    assert!(bytes.len().is_multiple_of(2), "odd-length hex");
    (0..bytes.len() / 2).map(|i| (d(bytes[2 * i]) << 4) | d(bytes[2 * i + 1])).collect()
}

/// Lowercase hex encoding, for comparing against golden digests.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").expect("write to string");
    }
    out
}

/// The pinned instant for the independent vector (inside its 2020..2049 window).
pub fn independent_now() -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000)
}

/// Split `data` into two halves at the midpoint.
pub fn split(data: &[u8]) -> (&[u8], &[u8]) {
    let mid = data.len() / 2;
    data.split_at(mid)
}

// ---------------------------------------------------------------------------
// Fail-open oracles (L14-10)
//
// Each oracle seeds a known-good structure, asserts it is accepted, then applies a
// corruption that *must* be rejected. They are run from a rare marker branch in the
// corresponding fuzz target and from a committed seed (`*.oracle` files in
// `fuzz/corpus/<target>/`) so the branch is reached at least once in CI and locally.
// ---------------------------------------------------------------------------

/// `SHA-256(RP_ID)`, the `rpIdHash` a structurally valid `authenticatorData` needs.
pub fn rp_id_hash() -> [u8; 32] {
    Sha256::digest(wsl_webauthn_protocol::RP_ID.as_bytes()).into()
}

/// Encode a CBOR map with the given members in order.
fn cbor_map(items: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(items), &mut out).expect("CBOR encode");
    out
}

/// Encode a TPM `TPM2B_*`: a big-endian u16 length followed by the bytes.
fn tpm2b(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Build a structurally valid bare `TPMT_PUBLIC` for an RSA key with a declared
/// `keyBits` (which `verify` requires to equal the modulus bit length).
fn rsa_pub_area(modulus: &[u8], key_bits: u16) -> Vec<u8> {
    const TPM_ALG_RSA: u16 = 0x0001;
    const TPM_ALG_SHA256: u16 = 0x000b;
    let mut out = Vec::new();
    out.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    out.extend_from_slice(&0x0004_0432u32.to_be_bytes()); // objectAttributes
    out.extend_from_slice(&tpm2b(&[0u8; 32])); // authPolicy
    out.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric NULL
    out.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    out.extend_from_slice(&key_bits.to_be_bytes());
    out.extend_from_slice(&65537u32.to_be_bytes()); // exponent
    out.extend_from_slice(&tpm2b(modulus));
    out
}

/// Fail-open oracle for the COSE_Key target.
///
/// An ES256 key must parse (the oracle is not vacuous); one appended byte must be
/// rejected (`decode_exact` requires exactly one CBOR item), and every single-byte
/// corruption must be rejected (a byte the parser does not bind would let a spurious
/// `Ok` escape).
///
/// Note: `cose::parse` does *not* enforce CBOR canonicality (an indefinite-length map
/// is accepted by `decode_exact`); canonicality is enforced where the key is sliced
/// out of `authenticatorData` instead, so it is deliberately not asserted here.
pub fn cose_key_oracle() {
    let good = synthetic_cose_key();
    assert!(
        testing::parse_cose_key(&good),
        "a valid ES256 COSE key must parse"
    );

    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(
        !testing::parse_cose_key(&trailing),
        "a COSE key with one appended byte must be rejected"
    );

    for i in 0..good.len() {
        let mut mutated = good.clone();
        mutated[i] ^= 0x01;
        assert!(
            !testing::parse_cose_key(&mutated),
            "COSE key byte {i} corruption must be rejected"
        );
    }
}

/// Fail-open oracle for the `authenticatorData` prefix target.
///
/// A valid 37-byte prefix must parse; every strict truncation below 37 bytes must be
/// rejected; one appended byte must still parse as a prefix (the parser reports a
/// valid prefix even with a trailing payload, which is the documented contract).
pub fn authenticator_data_oracle() {
    let mut good = Vec::with_capacity(37);
    good.extend_from_slice(&rp_id_hash());
    good.push(0x05); // UP | UV
    good.extend_from_slice(&0u32.to_be_bytes());
    assert!(
        testing::parse_authenticator_data(&good),
        "a valid authenticatorData prefix must parse"
    );

    for cut in 0..37usize {
        assert!(
            !testing::parse_authenticator_data(&good[..cut]),
            "authenticatorData truncated to {cut} bytes must be rejected"
        );
    }

    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(
        testing::parse_authenticator_data(&trailing),
        "the prefix parser reports a valid prefix regardless of trailing payload"
    );
}

/// Fail-open oracle for the attestation-object target.
///
/// The `testing` seam is a prefix/membership parser (it does not enforce a single
/// CBOR item), so the realistic invariant is: a structurally complete object parses,
/// and dropping any required member (`fmt`/`authData`/`attStmt`) or using a non-map
/// must be rejected. The full exact-decode behaviour is covered by the `attestation`
/// target's independent oracle.
pub fn attestation_object_oracle() {
    let good = cbor_map(vec![
        (Value::from("fmt"), Value::from("none")),
        (Value::from("attStmt"), Value::Map(vec![])),
        (Value::from("authData"), Value::Bytes(vec![0u8; 37])),
    ]);
    assert!(
        testing::parse_attestation_object(&good),
        "a structurally complete attestation object must parse"
    );

    let without_fmt = cbor_map(vec![
        (Value::from("attStmt"), Value::Map(vec![])),
        (Value::from("authData"), Value::Bytes(vec![0u8; 37])),
    ]);
    let without_auth_data = cbor_map(vec![
        (Value::from("fmt"), Value::from("none")),
        (Value::from("attStmt"), Value::Map(vec![])),
    ]);
    let without_att_stmt = cbor_map(vec![
        (Value::from("fmt"), Value::from("none")),
        (Value::from("authData"), Value::Bytes(vec![0u8; 37])),
    ]);
    for (name, missing) in [
        ("fmt", without_fmt),
        ("authData", without_auth_data),
        ("attStmt", without_att_stmt),
    ] {
        assert!(
            !testing::parse_attestation_object(&missing),
            "an attestation object missing {name} must be rejected"
        );
    }

    let mut encoded_array = Vec::new();
    ciborium::into_writer(&Value::Array(vec![Value::from(1i64)]), &mut encoded_array).unwrap();
    assert!(
        !testing::parse_attestation_object(&encoded_array),
        "a CBOR array is not an attestation object"
    );
    assert!(
        !testing::parse_attestation_object(&[]),
        "empty input is not an attestation object"
    );
}

/// Fail-open oracle for the TPM target.
///
/// A valid `certInfo` must parse and every strict truncation must be rejected; a
/// valid `pubArea` must parse and every strict truncation must be rejected. Because
/// both parsers require the whole buffer to be consumed, any accepted input is
/// exactly one structure — so an appended byte is rejected too. This is the strongest
/// fail-open signal reachable from the structural parse seam.
///
/// The declared-`keyBits`-vs-modulus semantic invariant (L1-4) lives in `tpm::verify`,
/// which is *not* reachable from `testing::parse_tpm_pub_area`; `parse_pub_area`
/// correctly accepts a well-formed `pubArea` regardless of whether its fields agree.
/// Asserting the invariant here would fail, so it is left to the full-verifier
/// `attestation` target and the `negative_tpm_pub_area_key_bits_mismatch` unit test
/// rather than faked.
pub fn tpm_oracle() {
    // certInfo: magic || type || qualifiedSigner || extraData || clockInfo ||
    //           firmwareVersion || name || qualifiedName.
    let name = tpm2b(&[0x22u8; 48]);
    let mut cert_info = Vec::new();
    cert_info.extend_from_slice(&0xff54_4347u32.to_be_bytes()); // TPM_GENERATED
    cert_info.extend_from_slice(&0x8017u16.to_be_bytes()); // TPM_ST_ATTEST_CERTIFY
    cert_info.extend_from_slice(&tpm2b(&[])); // qualifiedSigner
    cert_info.extend_from_slice(&tpm2b(&[0x33u8; 32])); // extraData
    cert_info.extend_from_slice(&0u64.to_be_bytes()); // clock
    cert_info.extend_from_slice(&0u32.to_be_bytes()); // resetCount
    cert_info.extend_from_slice(&0u32.to_be_bytes()); // restartCount
    cert_info.push(0); // safe
    cert_info.extend_from_slice(&0u64.to_be_bytes()); // firmwareVersion
    cert_info.extend_from_slice(&name); // TPMS_CERTIFY_INFO.name
    cert_info.extend_from_slice(&name); // qualifiedName
    assert!(
        testing::parse_tpm_cert_info(&cert_info),
        "a valid TPM certInfo must parse"
    );
    for cut in 0..cert_info.len() {
        assert!(
            !testing::parse_tpm_cert_info(&cert_info[..cut]),
            "certInfo truncated to {cut} bytes must be rejected"
        );
    }

    // pubArea: a 2048-bit RSA modulus with a matching declared keyBits.
    let modulus = [0xC1u8; 256];
    let consistent = rsa_pub_area(&modulus, 2048);
    assert!(
        testing::parse_tpm_pub_area(&consistent),
        "a valid TPM pubArea must parse"
    );
    for cut in 0..consistent.len() {
        assert!(
            !testing::parse_tpm_pub_area(&consistent[..cut]),
            "pubArea truncated to {cut} bytes must be rejected"
        );
    }

    // An accepted structure is self-delimiting: an appended byte must be rejected.
    let mut with_trailing = consistent.clone();
    with_trailing.push(0x00);
    assert!(
        !testing::parse_tpm_pub_area(&with_trailing),
        "a pubArea with one appended byte must be rejected"
    );
}
