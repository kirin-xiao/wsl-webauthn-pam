//! Small CBOR helpers shared by the byte-string parsers.
//!
//! The WebAuthn structures we consume (`COSE_Key` byte strings, the COSE value
//! trailing `attestedCredentialData`, and the whole `attestationObject`) are each a
//! **single** CBOR item. `ciborium::from_reader` stops at the end of the first item
//! and ignores anything after it, so an attacker could append arbitrary trailing
//! bytes to a signed/attested structure without invalidating it. [`decode_exact`]
//! closes that gap by requiring the decoder to consume every byte.

use ciborium::value::Value;
use std::io::Cursor;

/// Decode exactly one CBOR value from `bytes`, rejecting trailing bytes.
///
/// Returns `Err(())` on malformed CBOR or on any unconsumed input; callers map that
/// to their stage-specific `VerifyError::Malformed*` variant.
pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Value, ()> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor).map_err(|_| ())?;
    if cursor.position() as usize != bytes.len() {
        return Err(());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exactly_one_value() {
        assert!(decode_exact(&[0x01]).is_ok());
        assert!(decode_exact(&[0x40]).is_ok()); // empty byte string
    }

    #[test]
    fn rejects_trailing_bytes() {
        // A valid `1` followed by junk must be rejected.
        assert!(decode_exact(&[0x01, 0x02]).is_err());
        assert!(decode_exact(&[0x40, 0xff]).is_err());
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode_exact(&[0xff, 0x00]).is_err());
        assert!(decode_exact(&[]).is_err());
    }
}
