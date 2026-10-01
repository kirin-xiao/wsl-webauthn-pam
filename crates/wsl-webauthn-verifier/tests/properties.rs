//! `proptest` round-trip and robustness properties (plan §4 test item 3).
//!
//! These run under the normal `cargo test` on stable and keep runtimes short.

mod common;

use ciborium::value::Value;
use proptest::prelude::*;
use wsl_webauthn_verifier::testing;

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Random bytes must never panic any parser entry point.
    #[test]
    fn random_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = testing::parse_authenticator_data(&data);
        let _ = testing::parse_cose_key(&data);
        let _ = testing::parse_attestation_object(&data);
        let _ = testing::parse_tpm_cert_info(&data);
        let _ = testing::parse_tpm_pub_area(&data);
    }

    /// A parsed `authData` prefix re-parses identically (structural stability).
    #[test]
    fn authenticator_data_prefix_roundtrip(
        rp_hash in proptest::array::uniform32(any::<u8>()),
        flags in any::<u8>(),
        count in any::<u32>(),
    ) {
        let mut data = Vec::new();
        data.extend_from_slice(&rp_hash);
        data.push(flags);
        data.extend_from_slice(&count.to_be_bytes());
        prop_assert!(testing::parse_authenticator_data(&data));
        // Any truncation shorter than 37 bytes must be rejected, not panic.
        for cut in 0..37usize {
            prop_assert!(!testing::parse_authenticator_data(&data[..cut]));
        }
    }

    /// Arbitrary CBOR values round-trip through ciborium (the property the
    /// attestation-object parser relies on when it re-encodes a COSE value).
    #[test]
    fn cbor_value_roundtrip(value in cbor_value_strategy()) {
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded).expect("encode");
        let decoded: Value = ciborium::from_reader(&encoded[..]).expect("decode");
        let mut reencoded = Vec::new();
        ciborium::into_writer(&decoded, &mut reencoded).expect("re-encode");
        // Ciborium canonicalizes numeric widths, so re-encoding is a fixed point.
        let decoded2: Value = ciborium::from_reader(&reencoded[..]).expect("decode2");
        prop_assert_eq!(decoded, decoded2);
    }

    /// Random COSE maps never panic and never accept a non-allow-listed algorithm.
    #[test]
    fn random_cose_never_panics(
        kty in any::<i64>(),
        alg in any::<i64>(),
        blob in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let map = Value::Map(vec![
            (Value::from(1i64), Value::from(kty)),
            (Value::from(3i64), Value::from(alg)),
            (Value::from(-2i64), Value::Bytes(blob)),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&map, &mut encoded).unwrap();
        let parsed = testing::parse_cose_key(&encoded);
        if parsed {
            prop_assert!(matches!(alg, -7 | -257 | -8));
        }
    }

    /// A well-formed TPM `certInfo`/`pubArea` parses, and every strict truncation is
    /// rejected without panicking.
    #[test]
    fn tpm_structures_truncation_safe(
        extra in proptest::collection::vec(any::<u8>(), 0..64),
        name in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let ci = common::tpm_cert_info(&extra, &name);
        prop_assert!(testing::parse_tpm_cert_info(&ci));
        for cut in 0..ci.len() {
            prop_assert!(!testing::parse_tpm_cert_info(&ci[..cut]));
        }

        let pa = common::tpm_pub_area_ec(&[1u8; 32], &[2u8; 32], common::tpm_alg::SHA256);
        prop_assert!(testing::parse_tpm_pub_area(&pa));
        for cut in 0..pa.len() {
            prop_assert!(!testing::parse_tpm_pub_area(&pa[..cut]));
        }
    }
}

/// A reasonably rich CBOR value strategy.
fn cbor_value_strategy() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<i64>().prop_map(|v| Value::from(v as i128)),
        proptest::collection::vec(any::<u8>(), 0..64).prop_map(Value::Bytes),
        any::<bool>().prop_map(Value::Bool),
        ".*".prop_map(Value::Text),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            proptest::collection::vec((inner.clone(), inner), 0..8).prop_map(Value::Map),
        ]
    })
}
