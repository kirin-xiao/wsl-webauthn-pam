//! COSE_Key parsing and signature verification (RFC 8152 / CTAP2).
//!
//! Supported algorithms (the allow-list mandated by plan §4):
//!
//! | alg   | name  | kty | params                        |
//! |-------|-------|-----|-------------------------------|
//! | `-7`  | ES256 | 2   | P-256 (`crv` 1), `x`/`y` 32 B |
//! | `-257`| RS256 | 3   | `n`/`e`, modulus 2048..=4096, `e` ∈ {3, 65537} |
//! | `-8`  | EdDSA | 1   | OKP `crv` 6 (Ed25519), `x` 32 B |
//!
//! Everything else — including COSE keys whose `alg` is absent or is a string — is
//! rejected with a [`VerifyError`]. The public key extracted here is what the caller
//! persists; assertion and attestation verification both go through
//! [`ParsedCoseKey::verify`].

use ciborium::value::Value;
use ecdsa::signature::hazmat::PrehashVerifier as _;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
use rsa::signature::Verifier as _;
use sha2::{Digest as _, Sha256};

use crate::error::VerifyError;

/// COSE algorithm identifier for ECDSA with SHA-256 over P-256.
pub(crate) const ALG_ES256: i64 = -7;
/// COSE algorithm identifier for RSASSA-PKCS1-v1_5 with SHA-256.
pub(crate) const ALG_RS256: i64 = -257;
/// COSE algorithm identifier for Ed25519.
pub(crate) const ALG_EDDSA: i64 = -8;

/// COSE key-type label.
const COSE_KTY: i64 = 1;
/// COSE algorithm label.
const COSE_ALG: i64 = 3;
/// COSE curve label.
const COSE_CRV: i64 = -1;
/// COSE EC x-coordinate label.
const COSE_X: i64 = -2;
/// COSE EC y-coordinate label.
const COSE_Y: i64 = -3;
/// COSE RSA modulus label.
const COSE_N: i64 = -1;
/// COSE RSA exponent label.
const COSE_E: i64 = -2;

/// COSE key type `EC2`.
const KTY_EC2: i64 = 2;
/// COSE key type `RSA`.
const KTY_RSA: i64 = 3;
/// COSE key type `OKP`.
const KTY_OKP: i64 = 1;

/// COSE curve `P-256`.
const CRV_P256: i64 = 1;
/// COSE curve `Ed25519`.
const CRV_ED25519: i64 = 6;

/// Minimum accepted RSA modulus size in bits.
const RSA_MIN_BITS: u64 = 2048;
/// Maximum accepted RSA modulus size in bits.
const RSA_MAX_BITS: u64 = 4096;

/// A COSE public key that passed structural validation and an allow-list check.
#[derive(Debug, Clone)]
pub(crate) enum ParsedCoseKey {
    /// ES256 / P-256.
    Es256(P256VerifyingKey),
    /// RS256.
    Rs256(Box<RsaVerifyingKey<Sha256>>),
    /// EdDSA / Ed25519.
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
}

impl ParsedCoseKey {
    /// The allow-listed COSE algorithm this key is bound to.
    pub(crate) fn alg(&self) -> i64 {
        match self {
            ParsedCoseKey::Es256(_) => ALG_ES256,
            ParsedCoseKey::Rs256(_) => ALG_RS256,
            ParsedCoseKey::Ed25519(_) => ALG_EDDSA,
        }
    }

    /// Verify `signature` over `message`.
    ///
    /// * ES256 signatures are **DER-encoded** `Ecdsa-Sig-Value` (a non-DER encoding
    ///   is rejected before any curve math);
    /// * RS256 signatures are raw PKCS#1 v1.5;
    /// * EdDSA signatures are raw 64-byte Ed25519 signatures, verified strictly.
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        match self {
            ParsedCoseKey::Es256(key) => {
                let sig = p256::ecdsa::DerSignature::from_bytes(signature).map_err(|_| {
                    VerifyError::MalformedSignature {
                        reason: "ES256 signature is not a valid DER Ecdsa-Sig-Value",
                    }
                })?;
                let digest = Sha256::digest(message);
                key.verify_prehash(&digest, &sig)
                    .map_err(|_| VerifyError::SignatureInvalid)
            }
            ParsedCoseKey::Rs256(key) => {
                let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| {
                    VerifyError::MalformedSignature {
                        reason: "RS256 signature is malformed",
                    }
                })?;
                key.verify(message, &sig)
                    .map_err(|_| VerifyError::SignatureInvalid)
            }
            ParsedCoseKey::Ed25519(key) => {
                let sig_bytes: &[u8; 64] =
                    signature
                        .try_into()
                        .map_err(|_| VerifyError::MalformedSignature {
                            reason: "EdDSA signature is not 64 bytes",
                        })?;
                let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
                key.verify_strict(message, &sig)
                    .map_err(|_| VerifyError::SignatureInvalid)
            }
        }
    }

    /// Whether this key is an ES256/P-256 key whose affine coordinates equal `(x, y)`.
    ///
    /// Used by the `tpm` path to bind `pubArea.unique` to the credential public key.
    pub(crate) fn matches_ec_p256(&self, x: &[u8], y: &[u8]) -> bool {
        let ParsedCoseKey::Es256(key) = self else {
            return false;
        };
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        let point = key.as_affine().to_encoded_point(false);
        points_equal(point.x().map(|v| &v[..]), point.y().map(|v| &v[..]), x, y)
    }

    /// Whether this key is an RS256 key whose modulus/exponent equal `(n, e)`.
    ///
    /// Used by the `tpm` path to bind `pubArea.unique`/`parameters` to the credential
    /// public key.
    pub(crate) fn matches_rsa(&self, n: &[u8], e: &[u8]) -> bool {
        use rsa::traits::PublicKeyParts as _;
        let ParsedCoseKey::Rs256(key) = self else {
            return false;
        };
        let public = AsRef::<rsa::RsaPublicKey>::as_ref(key.as_ref());
        // Compare as integers, not byte strings. `TPMS_RSA_PARMS.exponent` is a
        // fixed-width big-endian `u32` (the standard 65537 is therefore
        // `00 01 00 01`), whereas `BigUint::to_bytes_be` yields the minimal form
        // (`01 00 01`); a TPM modulus may likewise carry leading zero bytes.
        // Byte-length equality would reject *every* RSA credential.
        rsa::BigUint::from_bytes_be(n) == *public.n()
            && rsa::BigUint::from_bytes_be(e) == *public.e()
    }
}

/// Compare X/Y coordinates after normalizing leading zero bytes to a fixed-width form.
fn points_equal(ax: Option<&[u8]>, ay: Option<&[u8]>, bx: &[u8], by: &[u8]) -> bool {
    fn norm(v: &[u8]) -> Vec<u8> {
        let stripped = strip_leading_zero(v);
        // Left-pad to 32 bytes (P-256 field element width).
        let mut out = vec![0u8; 32usize.saturating_sub(stripped.len())];
        out.extend_from_slice(stripped);
        out
    }
    match (ax, ay) {
        (Some(ax), Some(ay)) => norm(ax) == norm(bx) && norm(ay) == norm(by),
        _ => false,
    }
}

/// Strip a single leading zero byte from a big-endian integer.
fn strip_leading_zero(v: &[u8]) -> &[u8] {
    match v.split_first() {
        Some((0, rest)) if !rest.is_empty() => rest,
        _ => v,
    }
}

/// Parse a COSE_Key CBOR map and enforce the algorithm allow-list plus structural
/// constraints (EC point on curve and uncompressed only, RSA modulus size bounds).
pub(crate) fn parse(cose_key: &[u8]) -> Result<ParsedCoseKey, VerifyError> {
    let value =
        crate::cbor::decode_exact(cose_key).map_err(|()| VerifyError::MalformedCoseKey {
            reason: "not valid CBOR",
        })?;
    let map = value.as_map().ok_or(VerifyError::MalformedCoseKey {
        reason: "not a CBOR map",
    })?;
    if map.is_empty() {
        return Err(VerifyError::MalformedCoseKey {
            reason: "empty map",
        });
    }

    // Every label we understand is an integer; a string-labelled alg is rejected by
    // lookup returning `None`.
    let kty = get_int(map, COSE_KTY).ok_or(VerifyError::MalformedCoseKey {
        reason: "missing or non-integer kty (label 1)",
    })?;
    let alg = get_int(map, COSE_ALG).ok_or(VerifyError::MalformedCoseKey {
        reason: "missing or non-integer alg (label 3)",
    })?;

    match (kty, alg) {
        (KTY_EC2, ALG_ES256) => parse_es256(map),
        (KTY_RSA, ALG_RS256) => parse_rs256(map),
        (KTY_OKP, ALG_EDDSA) => parse_ed25519(map),
        (_, alg) if !is_known_alg(alg) => Err(VerifyError::UnsupportedAlgorithm { alg }),
        (_, _) => Err(VerifyError::UnsupportedKeyType { kty }),
    }
}

fn is_known_alg(alg: i64) -> bool {
    matches!(alg, ALG_ES256 | ALG_RS256 | ALG_EDDSA)
}

fn parse_es256(map: &[(Value, Value)]) -> Result<ParsedCoseKey, VerifyError> {
    let crv = get_int(map, COSE_CRV).ok_or(VerifyError::MalformedCoseKey {
        reason: "missing EC crv (label -1)",
    })?;
    if crv != CRV_P256 {
        return Err(VerifyError::MalformedCoseKey {
            reason: "EC curve is not P-256",
        });
    }
    let x = get_bytes(map, COSE_X).ok_or(VerifyError::MalformedCoseKey {
        reason: "missing EC x (label -2)",
    })?;
    let y = get_bytes(map, COSE_Y).ok_or(VerifyError::MalformedCoseKey {
        reason: "missing EC y (label -3)",
    })?;
    if x.len() != 32 || y.len() != 32 {
        return Err(VerifyError::MalformedCoseKey {
            reason: "EC x/y must each be 32 bytes",
        });
    }

    // Rebuild the SEC1 uncompressed point (0x04 || X || Y) ourselves rather than
    // trusting any prefix in the input; compressed points are therefore impossible
    // to smuggle in (plan §4: uncompressed only).
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..65].copy_from_slice(y);
    let point =
        p256::EncodedPoint::from_bytes(sec1).map_err(|_| VerifyError::MalformedCoseKey {
            reason: "EC point encoding invalid",
        })?;
    let key = P256VerifyingKey::from_encoded_point(&point).map_err(|_| {
        // `from_encoded_point` rejects the identity and any off-curve point.
        VerifyError::CosePointNotOnCurve
    })?;
    Ok(ParsedCoseKey::Es256(key))
}

fn parse_rs256(map: &[(Value, Value)]) -> Result<ParsedCoseKey, VerifyError> {
    let n = get_bytes(map, COSE_N).ok_or(VerifyError::MalformedCoseKey {
        reason: "missing RSA modulus (label -1)",
    })?;
    let e = get_bytes(map, COSE_E).ok_or(VerifyError::MalformedCoseKey {
        reason: "missing RSA exponent (label -2)",
    })?;
    if n.is_empty() || e.is_empty() {
        return Err(VerifyError::MalformedCoseKey {
            reason: "empty RSA modulus or exponent",
        });
    }
    if n[0] == 0 {
        return Err(VerifyError::MalformedCoseKey {
            reason: "RSA modulus has a leading zero byte",
        });
    }
    // The exponent must use its minimal big-endian encoding; a leading zero byte is a
    // non-canonical encoding of the same integer and is rejected.
    if e[0] == 0 {
        return Err(VerifyError::MalformedCoseKey {
            reason: "RSA exponent has a leading zero byte",
        });
    }

    let modulus = rsa::BigUint::from_bytes_be(n);
    let bits: u64 = modulus
        .bits()
        .try_into()
        .map_err(|_| VerifyError::MalformedCoseKey {
            reason: "RSA modulus size overflow",
        })?;
    if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) {
        return Err(VerifyError::CoseKeyModulusSize { bits });
    }

    // Only the two exponents defined for use with RSA in FIDO/CTAP (`e = 3` and
    // `e = 65537`) are accepted. This rejects `e = 1`/`e = 2`/oversized exponents that
    // `RsaPublicKey::new` would otherwise admit, which would let a trivially weak or
    // degenerate key through the allow-list.
    let exponent = rsa::BigUint::from_bytes_be(e);
    if exponent != rsa::BigUint::from(3u32) && exponent != rsa::BigUint::from(65537u32) {
        return Err(VerifyError::CoseKeyExponentNotAllowed);
    }

    // `RsaPublicKey::new` applies the `rsa` crate's own minimum key-size policy,
    // which agrees with our 2048-bit floor.
    let key = RsaPublicKey::new(modulus, exponent).map_err(|_| VerifyError::MalformedCoseKey {
        reason: "RSA public key rejected by the backend",
    })?;
    Ok(ParsedCoseKey::Rs256(Box::new(RsaVerifyingKey::new(key))))
}

fn parse_ed25519(map: &[(Value, Value)]) -> Result<ParsedCoseKey, VerifyError> {
    let crv = get_int(map, COSE_CRV).ok_or(VerifyError::MalformedCoseKey {
        reason: "missing OKP crv (label -1)",
    })?;
    if crv != CRV_ED25519 {
        return Err(VerifyError::MalformedCoseKey {
            reason: "OKP curve is not Ed25519",
        });
    }
    let x = get_bytes(map, COSE_X).ok_or(VerifyError::MalformedCoseKey {
        reason: "missing OKP x (label -2)",
    })?;
    let bytes: &[u8; 32] = x.try_into().map_err(|_| VerifyError::MalformedCoseKey {
        reason: "Ed25519 public key must be 32 bytes",
    })?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| {
        VerifyError::MalformedCoseKey {
            reason: "invalid Ed25519 public key",
        }
    })?;
    Ok(ParsedCoseKey::Ed25519(Box::new(key)))
}

/// Look up an integer value by integer label.
fn get_int(map: &[(Value, Value)], label: i64) -> Option<i64> {
    map.iter().find_map(|(k, v)| {
        let k = k.as_integer()?;
        if i64::try_from(k).ok()? != label {
            return None;
        }
        v.as_integer().and_then(|i| i64::try_from(i).ok())
    })
}

/// Look up a byte-string value by integer label.
fn get_bytes(map: &[(Value, Value)], label: i64) -> Option<&[u8]> {
    map.iter().find_map(|(k, v)| {
        let k = k.as_integer()?;
        if i64::try_from(k).ok()? != label {
            return None;
        }
        v.as_bytes().map(|b| b.as_slice())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a canonical ES256 COSE key from a fresh signing key.
    fn es256_key() -> (p256::ecdsa::SigningKey, Vec<u8>) {
        let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let x = point.x().unwrap().to_vec();
        let y = point.y().unwrap().to_vec();
        let map = vec![
            (Value::from(1i64), Value::from(2i64)),
            (Value::from(3i64), Value::from(-7i64)),
            (Value::from(-1i64), Value::from(1i64)),
            (Value::from(-2i64), Value::Bytes(x)),
            (Value::from(-3i64), Value::Bytes(y)),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        (sk, out)
    }

    #[test]
    fn parse_and_verify_es256() {
        use ecdsa::signature::Signer as _;
        let (sk, cose) = es256_key();
        let key = parse(&cose).unwrap();
        assert_eq!(key.alg(), ALG_ES256);
        let msg = b"hello world";
        let sig: p256::ecdsa::DerSignature = sk.sign(msg);
        assert!(key.verify(msg, sig.as_bytes()).is_ok());
        assert_eq!(
            key.verify(b"tampered", sig.as_bytes()),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_compressed_point() {
        // A COSE EC2 key with only an `x` coordinate (compressed form) is invalid.
        let map = vec![
            (Value::from(1i64), Value::from(2i64)),
            (Value::from(3i64), Value::from(-7i64)),
            (Value::from(-1i64), Value::from(1i64)),
            (Value::from(-2i64), Value::Bytes(vec![0x02u8; 32])),
            (Value::from(-3i64), Value::Bytes(vec![0x00u8; 32])),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        assert_eq!(parse(&out).unwrap_err(), VerifyError::CosePointNotOnCurve);
    }

    #[test]
    fn rejects_wrong_xy_length() {
        let map = vec![
            (Value::from(1i64), Value::from(2i64)),
            (Value::from(3i64), Value::from(-7i64)),
            (Value::from(-1i64), Value::from(1i64)),
            (Value::from(-2i64), Value::Bytes(vec![0u8; 31])),
            (Value::from(-3i64), Value::Bytes(vec![0u8; 32])),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        assert!(matches!(
            parse(&out),
            Err(VerifyError::MalformedCoseKey { .. })
        ));
    }

    #[test]
    fn rejects_unknown_alg() {
        let map = vec![
            (Value::from(1i64), Value::from(2i64)),
            (Value::from(3i64), Value::from(-47i64)),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        assert_eq!(
            parse(&out).unwrap_err(),
            VerifyError::UnsupportedAlgorithm { alg: -47 }
        );
    }

    #[test]
    fn rejects_malformed_cbor() {
        assert!(matches!(
            parse(&[0xff, 0x00]),
            Err(VerifyError::MalformedCoseKey { .. })
        ));
    }

    /// Encode an RSA COSE key with an arbitrary modulus/exponent.
    fn rsa_cose(n: &[u8], e: &[u8]) -> Vec<u8> {
        let map = vec![
            (Value::from(1i64), Value::from(3i64)),
            (Value::from(3i64), Value::from(-257i64)),
            (Value::from(-1i64), Value::Bytes(n.to_vec())),
            (Value::from(-2i64), Value::Bytes(e.to_vec())),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    /// A fixed odd 2048-bit modulus (exactly at the floor of the accepted range).
    fn rsa_modulus_2048() -> Vec<u8> {
        let mut n = vec![0xC1u8; 256];
        n[255] = 0x0F; // keep it odd
        n
    }

    #[test]
    fn rsa_exponent_allow_list() {
        let n = rsa_modulus_2048();
        // e = 1, 2, 16777217, and a large arbitrary value are all rejected.
        for bad in [
            vec![0x01u8],
            vec![0x02],
            vec![0x01, 0x00, 0x00, 0x01],
            vec![0xff; 8],
        ] {
            assert_eq!(
                parse(&rsa_cose(&n, &bad)).unwrap_err(),
                VerifyError::CoseKeyExponentNotAllowed,
                "e={bad:?} must be rejected"
            );
        }
        // The two documented exponents are accepted.
        for good in [vec![0x03u8], vec![0x01, 0x00, 0x01]] {
            let key = parse(&rsa_cose(&n, &good)).expect("allowed exponent");
            assert_eq!(key.alg(), ALG_RS256);
        }
    }

    #[test]
    fn rsa_exponent_non_minimal_encoding_rejected() {
        let n = rsa_modulus_2048();
        // 65537 with a leading zero byte is a non-canonical encoding.
        assert!(matches!(
            parse(&rsa_cose(&n, &[0x00, 0x01, 0x00, 0x01])),
            Err(VerifyError::MalformedCoseKey { .. })
        ));
    }

    #[test]
    fn rejects_non_map() {
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Array(vec![]), &mut out).unwrap();
        assert!(matches!(
            parse(&out),
            Err(VerifyError::MalformedCoseKey { .. })
        ));
    }
}
