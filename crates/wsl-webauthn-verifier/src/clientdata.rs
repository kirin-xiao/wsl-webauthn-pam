//! `clientDataJSON` parsing and validation (WebAuthn §5.8.1).
//!
//! We parse with `serde_json` into a typed projection and then compare:
//!
//! * `type` against the ceremony's exact string,
//! * `challenge` against `base64url(expected_challenge)`, compared on the **decoded
//!   bytes** so that alternative-but-equivalent encodings cannot slip through, and
//! * `origin` **byte-equal** to the pinned [`wsl_webauthn_protocol::ORIGIN`].
//!
//! Unknown members are permitted (the spec allows extensions such as `crossOrigin`);
//! unknown *required* members are not a thing, so we only require `type`,
//! `challenge`, and `origin`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use wsl_webauthn_protocol::{ClientDataKind, ORIGIN};

use crate::error::VerifyError;

/// The subset of `clientDataJSON` we consume. Unknown fields are ignored.
#[derive(Debug, Deserialize)]
struct ClientDataProjection<'a> {
    #[serde(rename = "type")]
    type_: &'a str,
    challenge: &'a str,
    origin: &'a str,
}

/// Parse and validate `client_data_json` for the given ceremony.
///
/// On success the caller knows the ceremony type, encoded challenge, and origin were
/// all consistent with what the Linux side minted.
pub(crate) fn validate(
    client_data_json: &[u8],
    kind: ClientDataKind,
    expected_challenge: &[u8],
) -> Result<(), VerifyError> {
    // 1. UTF-8 / JSON object.
    let text =
        std::str::from_utf8(client_data_json).map_err(|_| VerifyError::MalformedClientData {
            reason: "not valid UTF-8",
        })?;
    let projection: ClientDataProjection<'_> =
        serde_json::from_str(text).map_err(|_| VerifyError::MalformedClientData {
            reason: "not a JSON object with type/challenge/origin",
        })?;

    // 2. `type` must be the exact ceremony string.
    if projection.type_ != kind.as_str() {
        return Err(VerifyError::ClientDataTypeMismatch);
    }

    // 3. `origin` byte-equal to the pinned origin. `ORIGIN` is ASCII, so a byte
    //    comparison is equivalent to a string comparison and cannot be tricked by
    //    Unicode normalization.
    if projection.origin.as_bytes() != ORIGIN.as_bytes() {
        return Err(VerifyError::OriginMismatch);
    }

    // 4. `challenge` compared on decoded bytes. Decoding failure is a malformed
    //    challenge, not a match failure.
    let decoded = URL_SAFE_NO_PAD
        .decode(projection.challenge.as_bytes())
        .map_err(|_| VerifyError::MalformedClientData {
            reason: "challenge is not base64url",
        })?;
    if decoded != expected_challenge {
        return Err(VerifyError::ChallengeMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsl_webauthn_protocol::build_client_data;

    fn good(kind: ClientDataKind, challenge: &[u8]) -> Vec<u8> {
        build_client_data(kind, challenge).expect("build")
    }

    #[test]
    fn accepts_canonical_client_data() {
        let challenge = [0x11u8; 32];
        let cd = good(ClientDataKind::Get, &challenge);
        assert!(validate(&cd, ClientDataKind::Get, &challenge).is_ok());
    }

    #[test]
    fn rejects_wrong_type() {
        let challenge = [0x22u8; 32];
        let cd = good(ClientDataKind::Get, &challenge);
        assert_eq!(
            validate(&cd, ClientDataKind::Create, &challenge),
            Err(VerifyError::ClientDataTypeMismatch)
        );
    }

    #[test]
    fn rejects_wrong_origin() {
        let challenge = [0x33u8; 32];
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://evil.example"}}"#,
            URL_SAFE_NO_PAD.encode(challenge)
        );
        assert_eq!(
            validate(cd.as_bytes(), ClientDataKind::Get, &challenge),
            Err(VerifyError::OriginMismatch)
        );
    }

    #[test]
    fn rejects_wrong_challenge() {
        let challenge = [0x44u8; 32];
        let other = [0x55u8; 32];
        let cd = good(ClientDataKind::Get, &challenge);
        assert_eq!(
            validate(&cd, ClientDataKind::Get, &other),
            Err(VerifyError::ChallengeMismatch)
        );
    }

    #[test]
    fn challenge_is_compared_on_decoded_bytes() {
        let challenge = [0x66u8; 32];
        let cd = good(ClientDataKind::Get, &challenge);
        // Same bytes, canonical encoding: accept.
        assert!(validate(&cd, ClientDataKind::Get, &challenge).is_ok());
        // A challenge that decodes to different bytes: reject.
        assert_eq!(
            validate(&cd, ClientDataKind::Get, &[0x67u8; 32]),
            Err(VerifyError::ChallengeMismatch)
        );
    }

    #[test]
    fn rejects_invalid_utf8() {
        let bytes = [0xff, 0xfe, 0xfd];
        assert!(matches!(
            validate(&bytes, ClientDataKind::Get, &[0u8; 32]),
            Err(VerifyError::MalformedClientData { .. })
        ));
    }

    #[test]
    fn rejects_non_object_json() {
        let bytes = b"[]";
        assert!(matches!(
            validate(bytes, ClientDataKind::Get, &[0u8; 32]),
            Err(VerifyError::MalformedClientData { .. })
        ));
    }

    #[test]
    fn rejects_missing_fields() {
        let bytes = br#"{"type":"webauthn.get"}"#;
        assert!(matches!(
            validate(bytes, ClientDataKind::Get, &[0u8; 32]),
            Err(VerifyError::MalformedClientData { .. })
        ));
    }

    #[test]
    fn rejects_non_base64url_challenge() {
        let bytes = br#"{"type":"webauthn.get","challenge":"!!!","origin":"io.github.kirin-xiao.wsl-webauthn-pam"}"#;
        assert!(matches!(
            validate(bytes, ClientDataKind::Get, &[0u8; 32]),
            Err(VerifyError::MalformedClientData { .. })
        ));
    }

    #[test]
    fn permits_extra_members() {
        let challenge = [0x77u8; 32];
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(challenge),
            ORIGIN
        );
        assert!(validate(cd.as_bytes(), ClientDataKind::Get, &challenge).is_ok());
    }
}
