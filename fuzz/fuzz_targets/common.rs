//! Shared helpers for the fuzz targets.
//!
//! The targets only care that the verifier never panics; inputs are arbitrary bytes
//! and both `Ok` and `Err` are acceptable outcomes.

#![allow(dead_code)]

use ciborium::value::Value;

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
