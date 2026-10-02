//! Shared helpers and fail-open oracles for the fuzz targets.
//!
//! Arbitrary inputs may still legitimately return either `Ok` or `Err` — the primary
//! contract is "never panic". The parser targets additionally run seeded oracles that
//! assert a spurious `Ok` (accepting malformed or semantically-wrong input) is caught
//! rather than discarded. See the per-oracle comments below.

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
// cryptography + a hand-rolled minimal CBOR encoder (tests/vectors/README.md;
// regenerate with python3 tests/vectors/generate_independent_vector.py).
// No Rust helper here builds it, so it is a genuine second implementation.
pub const INDEPENDENT_CHALLENGE_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";
pub const INDEPENDENT_CREDENTIAL_ID: &[u8] = b"independent-vector-cred";
pub const INDEPENDENT_CLIENT_DATA_CREATE: &[u8] = br#"{"type":"webauthn.create","challenge":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","origin":"wsl-webauthn-pam"}"#;
pub const INDEPENDENT_ATTESTATION_OBJECT_HEX: &str = "a363666d74667061636b65646761747453746d74a363616c672663736967584630440220765e058a3b3eebb9dea98bcabc9ce5dc83265e26a2e999652adf3d606adc842902203eb9ee3c1fb0520d2a8b80a95fdbf38285314d1198196ee87687271f5ac6c12363783563835901fc308201f83082019da00302010202021002300a06082a8648ce3d04030230593129302706035504030c20496e646570656e64656e74205465737420496e7465726d656469617465204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a307b3127302506035504030c1e496e646570656e64656e7420546573742041757468656e74696361746f7231223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d030107034200047819ccaa4a7165a4193c5d3d417cf0ab0b3341a90b950be196cb84f2cdfca16459640831a54bf3c98aeb135c1639f8ef71a38f4e8e20a4730cb0869e737934f3a3333031300c0603551d130101ff040230003021060b2b0601040182e51c0101040412041008987058cadc4b81b6e130de50dcbe96300a06082a8648ce3d0403020349003046022100e7951f3bbc8658accc67b0d6454d8fd2ed0c318dfcf18cf37e3db605bb642536022100847c1d6a4c6cdc4c1d9f61a7a2698c175b434fb2b47fbe83c617c3c19069e11d5901b4308201b030820156a00302010202021001300a06082a8648ce3d04030230513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a30593129302706035504030c20496e646570656e64656e74205465737420496e7465726d656469617465204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d03010703420004269d4f50087c9696b8d4643f27635c246b35242c5bb8ef3f82526d59f8208c98d262be1090d09c7e7395efb4c94ba406f5c191966c64da42498a1cb5531e637ea316301430120603551d130101ff040830060101ff020100300a06082a8648ce3d0403020348003045022100d924e939f6fa5ad99da96181fd2717fe6e25e3cc2f5b10802836fb532cea47860220415bfeb4336b2a71012385891fe67499d388c8a3aace02b57584431febd2964d5901a9308201a53082014ba00302010202021000300a06082a8648ce3d04030230513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b3009060355040613025553301e170d3230303130313030303030305a170d3439303130313030303030305a30513121301f06035504030c18496e646570656e64656e74205465737420526f6f74204341311f301d060355040a0c1677736c2d776562617574686e2d70616d207465737473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d0301070342000473179c2827f473838309ecf3f5d7f8ee3e9dbc7405522242ff61c4cb53adfde22f47d92dc596f604eec4ef059c20b13ab2106f81005228c949808950c897799ba3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502201c2794d69302b2cfcd3811e1b73270fa1d1a10267e1aed505fffbbdcd122c15f022100845fedd48c606f2d0e1757b9e3204e7e4fbe9731f48470aa53766001ed4de988686175746844617461589bfec5647d06bb3ea1229a888a153859052540d70fcbad8c93216b805e4f68f451450000000008987058cadc4b81b6e130de50dcbe960017696e646570656e64656e742d766563746f722d63726564a5010203262001215820b9e102424555569c82baff1e9e2eaa65ca3fee3dd80ef86ee6f3191f2d497d8a225820b1b219b202d96ae72dc69801cc399cee0ef83ae03fae220cb1b8a7d5b02bb0d7";
pub const INDEPENDENT_ROOT_FINGERPRINT_HEX: &str = "5e7a2cb6bc38d3dadfa3155a7640f5e27a1d0082b567c40de24f424dcea2b25c";
pub const INDEPENDENT_ASSERT_CLIENT_DATA: &[u8] = br#"{"type":"webauthn.get","challenge":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","origin":"wsl-webauthn-pam"}"#;
pub const INDEPENDENT_ASSERT_AUTH_DATA_HEX: &str = "fec5647d06bb3ea1229a888a153859052540d70fcbad8c93216b805e4f68f4510500000005";
pub const INDEPENDENT_ASSERT_SIGNATURE_HEX: &str = "304402206121627bd2efdcd2603e066f166ba1593136d67010da19fed209b0d7cba66918022033370945cc767595a8b0a5e9fce8d8d0f6ae4802e70a8e412065f983fc527ab8";
pub const INDEPENDENT_CREDENTIAL_COSE_HEX: &str = "a5010203262001215820b9e102424555569c82baff1e9e2eaa65ca3fee3dd80ef86ee6f3191f2d497d8a225820b1b219b202d96ae72dc69801cc399cee0ef83ae03fae220cb1b8a7d5b02bb0d7";
pub const INDEPENDENT_SIGNED_MESSAGE_SHA256_HEX: &str = "50710dc3f91950269e9b917fba3ed4f3ccf232d7b0a2b82e5f70abb55da2503c";

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
// Fail-open oracles
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
/// The declared-`keyBits`-vs-modulus semantic invariant lives in `tpm::verify`,
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
