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

/// Split `data` into two halves at the midpoint.
pub fn split(data: &[u8]) -> (&[u8], &[u8]) {
    let mid = data.len() / 2;
    data.split_at(mid)
}
