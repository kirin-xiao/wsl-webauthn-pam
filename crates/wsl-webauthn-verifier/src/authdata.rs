//! `authenticatorData` parsing (WebAuthn §6.1).
//!
//! ```text
//! authenticatorData = rpIdHash          (32 bytes)
//!                   || flags            (1 byte: bit0 UP, bit2 UV, bit6 AT, bit7 ED)
//!                   || signCount        (4 bytes, big-endian)
//!                   [|| attestedCredentialData]   (when AT=1)
//!                   [|| extensions]               (when ED=1; not parsed)
//! ```
//!
//! Every truncation is mapped to [`VerifyError::MalformedAuthenticatorData`]; no
//! indexing can panic because all offsets are bounds-checked first.

use sha2::{Digest as _, Sha256};
use wsl_webauthn_protocol::RP_ID;

use crate::error::VerifyError;

/// Fixed prefix length: `rpIdHash || flags || signCount`.
pub(crate) const FIXED_LEN: usize = 37;

/// Authenticator data flags.
pub(crate) const FLAG_UP: u8 = 0x01;
/// User Verified.
pub(crate) const FLAG_UV: u8 = 0x04;
/// Attested credential data included.
pub(crate) const FLAG_AT: u8 = 0x40;
/// Extension data included (not parsed).
pub(crate) const FLAG_ED: u8 = 0x80;

/// Offset of the AAGUID inside attested credential data, measured from the start of
/// `authData` (that is, `FIXED_LEN`), per WebAuthn §6.5.1.
pub(crate) const AAGUID_OFFSET: usize = FIXED_LEN;
/// Length of an AAGUID.
pub(crate) const AAGUID_LEN: usize = 16;
/// Offset of the 2-byte credential-id length.
pub(crate) const CRED_ID_LEN_OFFSET: usize = AAGUID_OFFSET + AAGUID_LEN;
/// Offset at which the credential id itself begins.
pub(crate) const CRED_ID_OFFSET: usize = CRED_ID_LEN_OFFSET + 2;

/// Parsed view over `authenticatorData`'s fixed prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthDataPrefix {
    /// The 32-byte `rpIdHash`.
    pub(crate) rp_id_hash: [u8; 32],
    /// Raw flags byte.
    pub(crate) flags: u8,
    /// Signature counter, big-endian.
    pub(crate) sign_count: u32,
}

impl AuthDataPrefix {
    /// Whether the User Present flag is set.
    pub(crate) fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }

    /// Whether the User Verified flag is set.
    pub(crate) fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }

    /// Whether attested credential data follows.
    pub(crate) fn has_attested_credential_data(&self) -> bool {
        self.flags & FLAG_AT != 0
    }

    /// Whether authenticator extensions follow the attested credential data.
    pub(crate) fn has_extensions(&self) -> bool {
        self.flags & FLAG_ED != 0
    }
}

/// Parse the fixed prefix and validate `rpIdHash` and both user flags.
///
/// Used by both the assertion and enrollment paths. `rpIdHash` is compared against
/// `SHA-256(RP_ID)` in constant time for the length-32 digest.
pub(crate) fn parse_and_validate_prefix(auth_data: &[u8]) -> Result<AuthDataPrefix, VerifyError> {
    let prefix = parse_prefix(auth_data)?;

    let expected = Sha256::digest(RP_ID.as_bytes());
    if !constant_time_eq(&prefix.rp_id_hash, &expected) {
        return Err(VerifyError::RpIdHashMismatch);
    }
    if !prefix.user_present() {
        return Err(VerifyError::UserPresenceRequired);
    }
    if !prefix.user_verified() {
        return Err(VerifyError::UserVerificationRequired);
    }
    Ok(prefix)
}

/// Parse the fixed prefix without any semantic validation.
pub(crate) fn parse_prefix(auth_data: &[u8]) -> Result<AuthDataPrefix, VerifyError> {
    if auth_data.len() < FIXED_LEN {
        return Err(VerifyError::MalformedAuthenticatorData {
            reason: "shorter than 37-byte fixed prefix",
        });
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[..32]);
    let flags = auth_data[32];
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    Ok(AuthDataPrefix {
        rp_id_hash,
        flags,
        sign_count,
    })
}

/// Parsed attested credential data (WebAuthn §6.5.1).
#[derive(Debug)]
pub(crate) struct AttestedCredentialData<'a> {
    /// The authenticator's AAGUID.
    pub(crate) aaguid: [u8; 16],
    /// Credential id bytes.
    pub(crate) credential_id: &'a [u8],
    /// The credential public key, still encoded as a COSE_Key CBOR map.
    pub(crate) cose_public_key: &'a [u8],
}

/// Parse `attestedCredentialData` starting at [`AAGUID_OFFSET`] of `auth_data`.
///
/// The trailing COSE key is delimited by re-encoding the CBOR value, so the parser
/// never has to guess where the key ends. The decoded value must re-encode
/// byte-for-byte to the input it came from (rejecting non-canonical encodings), and
/// any bytes past the key are accepted only when the ED (extensions) flag is set.
pub(crate) fn parse_attested_credential_data(
    auth_data: &[u8],
) -> Result<AttestedCredentialData<'_>, VerifyError> {
    let prefix = parse_prefix(auth_data)?;
    if !prefix.has_attested_credential_data() {
        return Err(VerifyError::MalformedAuthenticatorData {
            reason: "AT flag not set",
        });
    }
    if auth_data.len() < CRED_ID_OFFSET {
        return Err(VerifyError::MalformedAuthenticatorData {
            reason: "truncated attested credential data",
        });
    }

    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&auth_data[AAGUID_OFFSET..AAGUID_OFFSET + AAGUID_LEN]);

    let cred_id_len = u16::from_be_bytes([
        auth_data[CRED_ID_LEN_OFFSET],
        auth_data[CRED_ID_LEN_OFFSET + 1],
    ]) as usize;
    if cred_id_len == 0 {
        return Err(VerifyError::MalformedAuthenticatorData {
            reason: "zero-length credential id",
        });
    }
    let cred_id_end =
        CRED_ID_OFFSET
            .checked_add(cred_id_len)
            .ok_or(VerifyError::MalformedAuthenticatorData {
                reason: "credential id length overflow",
            })?;
    if cred_id_end > auth_data.len() {
        return Err(VerifyError::MalformedAuthenticatorData {
            reason: "credential id extends past end of authData",
        });
    }
    let credential_id = &auth_data[CRED_ID_OFFSET..cred_id_end];

    // The COSE key is a self-delimiting CBOR value; encode it back to find its length.
    let rest = &auth_data[cred_id_end..];
    let value: ciborium::value::Value =
        ciborium::from_reader(rest).map_err(|_| VerifyError::MalformedCoseKey {
            reason: "credential public key is not valid CBOR",
        })?;
    let mut encoded = Vec::new();
    ciborium::into_writer(&value, &mut encoded).map_err(|_| VerifyError::Internal {
        reason: "re-encoding parsed COSE value failed",
    })?;
    // The re-encoded form delimits the key. The decoder accepts non-canonical CBOR
    // (indefinite lengths, over-long integers, …); if such a key re-encoded to a
    // *different* byte string, slicing `rest` at `encoded.len()` could truncate the
    // key or pick the wrong boundary. Require the decoded value to re-encode back to
    // the exact leading bytes it came from, so the returned slice is provably the
    // whole, canonical key.
    if encoded.is_empty() || encoded.len() > rest.len() || rest[..encoded.len()] != encoded[..] {
        return Err(VerifyError::MalformedCoseKey {
            reason: "credential public key is not canonically encoded",
        });
    }
    let cose_public_key = &rest[..encoded.len()];

    // Everything after the key is either authenticator extensions (ED=1, which we do
    // not consume) or a malformed input. Trailing bytes without the ED flag are
    // rejected rather than silently swallowed.
    if !rest[encoded.len()..].is_empty() && !prefix.has_extensions() {
        return Err(VerifyError::MalformedAuthenticatorData {
            reason: "trailing bytes after the credential public key without the ED flag",
        });
    }

    Ok(AttestedCredentialData {
        aaguid,
        credential_id,
        cose_public_key,
    })
}

/// Constant-time equality for equal-length byte slices.
///
/// Compares every byte regardless of early mismatches. Unequal lengths compare
/// unequal without reading out of bounds.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_prefix() {
        for len in 0..FIXED_LEN {
            assert!(matches!(
                parse_prefix(&vec![0u8; len]),
                Err(VerifyError::MalformedAuthenticatorData { .. })
            ));
        }
    }

    #[test]
    fn parses_prefix() {
        let mut ad = Vec::new();
        ad.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
        ad.push(FLAG_UP | FLAG_UV);
        ad.extend_from_slice(&7u32.to_be_bytes());
        let p = parse_prefix(&ad).unwrap();
        assert_eq!(p.sign_count, 7);
        assert!(p.user_present() && p.user_verified());
        assert!(!p.has_attested_credential_data());
    }

    #[test]
    fn requires_up_uv() {
        let mut ad = Vec::new();
        ad.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
        ad.push(FLAG_UV); // no UP
        ad.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            parse_and_validate_prefix(&ad),
            Err(VerifyError::UserPresenceRequired)
        );

        ad[32] = FLAG_UP; // no UV
        assert_eq!(
            parse_and_validate_prefix(&ad),
            Err(VerifyError::UserVerificationRequired)
        );
    }

    #[test]
    fn rejects_bad_rp_id_hash() {
        let mut ad = vec![0u8; FIXED_LEN];
        ad[32] = FLAG_UP | FLAG_UV;
        assert_eq!(
            parse_and_validate_prefix(&ad),
            Err(VerifyError::RpIdHashMismatch)
        );
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
    }

    /// A canonical 5-entry ES256 COSE_Key map (contents irrelevant to this parser,
    /// which only slices the key bytes).
    fn cose_key_es256() -> Vec<u8> {
        use ciborium::value::Value;
        let map = vec![
            (Value::from(1i64), Value::from(2i64)),
            (Value::from(3i64), Value::from(-7i64)),
            (Value::from(-1i64), Value::from(1i64)),
            (Value::from(-2i64), Value::Bytes(vec![1u8; 32])),
            (Value::from(-3i64), Value::Bytes(vec![2u8; 32])),
        ];
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(map), &mut out).unwrap();
        out
    }

    /// Build authData with AT set, a fixed credential id, `cose` as the key, and any
    /// extra flag bits (e.g. ED) and trailing bytes.
    fn auth_data_with(cose: &[u8], extra_flags: u8, tail: &[u8]) -> Vec<u8> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&Sha256::digest(RP_ID.as_bytes()));
        ad.push(FLAG_UP | FLAG_UV | FLAG_AT | extra_flags);
        ad.extend_from_slice(&0u32.to_be_bytes());
        ad.extend_from_slice(&[0xAAu8; 16]);
        let cred = b"cred";
        ad.extend_from_slice(&(cred.len() as u16).to_be_bytes());
        ad.extend_from_slice(cred);
        ad.extend_from_slice(cose);
        ad.extend_from_slice(tail);
        ad
    }

    #[test]
    fn parses_canonical_key_without_trailing() {
        let cose = cose_key_es256();
        let ad = auth_data_with(&cose, 0, &[]);
        let parsed = parse_attested_credential_data(&ad).unwrap();
        assert_eq!(parsed.cose_public_key, &cose[..]);
        assert_eq!(parsed.credential_id, b"cred");
    }

    #[test]
    fn rejects_trailing_bytes_without_ed() {
        let cose = cose_key_es256();
        let ad = auth_data_with(&cose, 0, &[0x00, 0x01]);
        assert!(matches!(
            parse_attested_credential_data(&ad),
            Err(VerifyError::MalformedAuthenticatorData { .. })
        ));
    }

    #[test]
    fn accepts_trailing_extensions_with_ed() {
        let cose = cose_key_es256();
        let ad = auth_data_with(&cose, FLAG_ED, &[0x00, 0x01]);
        let parsed = parse_attested_credential_data(&ad).unwrap();
        assert_eq!(parsed.cose_public_key, &cose[..]);
    }

    #[test]
    fn rejects_non_canonical_key() {
        let cose = cose_key_es256();
        // Rewrite the definite 5-entry map header (0xa5) as indefinite length: the
        // decoder accepts it, but re-encoding is canonical and differs byte-for-byte.
        assert_eq!(cose[0], 0xa5);
        let mut non_canonical = vec![0xbf];
        non_canonical.extend_from_slice(&cose[1..]);
        non_canonical.push(0xff);
        let ad = auth_data_with(&non_canonical, 0, &[]);
        assert!(matches!(
            parse_attested_credential_data(&ad),
            Err(VerifyError::MalformedCoseKey { .. })
        ));
    }
}
