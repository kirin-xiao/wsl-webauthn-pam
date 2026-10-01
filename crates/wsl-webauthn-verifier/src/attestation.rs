//! Attestation-object parsing and verification (WebAuthn §6.5).
//!
//! Supported formats (D3, as amended after the Windows spike):
//!
//! * `tpm` with `x5c`: full chain verification to the pinned Microsoft root plus the
//!   TPM `certInfo`/`pubArea` checks (§8.3). Windows Hello emits this on TPM-equipped
//!   machines; it is the primary expected enrollment path. Accepted under **both**
//!   policies (it is fully verified).
//! * `packed` with `x5c`: full chain verification to the pinned root
//!   (`StrictVerified`); accepted under **both** policies.
//! * `packed` without `x5c`: self-attestation; accepted **only** under
//!   [`AttestationPolicy::AllowUnattested`], and only when `attStmt.alg` equals the
//!   credential key's algorithm.
//! * `none`: an empty attestation statement; accepted **only** under
//!   [`AttestationPolicy::AllowUnattested`].
//!
//! Any other format is rejected outright. In every case the authData AAGUID must be on
//! [`crate::STRICT_AAGUIDS`].

use std::time::SystemTime;

use ciborium::value::Value;
use sha2::{Digest as _, Sha256};

use crate::authdata::parse_and_validate_prefix;
use crate::authdata::parse_attested_credential_data;
use crate::chain::{self, ChainProfile};
use crate::clientdata;
use crate::cose;
use crate::error::VerifyError;
use crate::tpm;
use crate::{AttestationMetadata, AttestationMode, AttestationPolicy};
use wsl_webauthn_protocol::ClientDataKind;

/// Verify a registration ceremony and return the enrollment outcome.
///
/// `anchor_fingerprint` is the SHA-256 of the trusted root certificate; the public
/// entry point supplies [`crate::MS_TPM_ROOT_2014_SHA256`], while tests inject a
/// synthetic root through [`crate::verify_attestation_with_anchor`].
pub(crate) fn verify(
    attestation_object: &[u8],
    client_data_json: &[u8],
    expected_challenge: &[u8],
    reported_credential_id: &[u8],
    policy: &AttestationPolicy,
    now: SystemTime,
    anchor_fingerprint: &[u8; 32],
) -> Result<crate::EnrollOutcome, VerifyError> {
    // 1. clientDataJSON must be a `webauthn.create` for our challenge/origin.
    clientdata::validate(client_data_json, ClientDataKind::Create, expected_challenge)?;

    // 2. Parse the CBOR attestation object.
    let obj: Value = ciborium::from_reader(attestation_object).map_err(|_| {
        VerifyError::MalformedAttestationObject {
            reason: "not valid CBOR",
        }
    })?;
    let map = obj
        .as_map()
        .ok_or(VerifyError::MalformedAttestationObject {
            reason: "attestationObject is not a CBOR map",
        })?;

    let fmt = map_get_text(map, "fmt").ok_or(VerifyError::MissingAttestationField)?;
    let auth_data = map_get_bytes(map, "authData").ok_or(VerifyError::MissingAttestationField)?;
    let att_stmt = map_get(map, "attStmt")
        .and_then(Value::as_map)
        .ok_or(VerifyError::InvalidAttestationStatement)?;

    // 3. authenticatorData: fixed prefix (rpIdHash + UP + UV) then attested data.
    let prefix = parse_and_validate_prefix(auth_data)?;
    let attested = parse_attested_credential_data(auth_data)?;

    // 4. Cross-check the bridge-reported credential id against the attested one.
    if reported_credential_id != attested.credential_id {
        return Err(VerifyError::CredentialIdMismatch);
    }

    // 5. Parse and allow-list the credential's COSE key.
    let credential_key = cose::parse(attested.cose_public_key)?;

    // 6. Dispatch on the attestation format.
    let signed = {
        let mut buf = Vec::with_capacity(auth_data.len() + 32);
        buf.extend_from_slice(auth_data);
        buf.extend_from_slice(&Sha256::digest(client_data_json));
        buf
    };

    let (mode, leaf_sha256) = match fmt {
        "packed" => match map_get(att_stmt, "x5c") {
            Some(x5c) => {
                let certs = parse_x5c(x5c)?;
                let info = chain::verify_chain(
                    &certs,
                    &attested.aaguid,
                    now,
                    anchor_fingerprint,
                    ChainProfile::Packed,
                    None,
                )?;
                let attestation_key = chain::cose_key_from_spki(&info.leaf_spki)?;
                let alg = att_stmt_alg(att_stmt)?;
                if alg != attestation_key.alg() {
                    return Err(VerifyError::AlgorithmMismatch);
                }
                let sig = att_stmt_sig(att_stmt)?;
                attestation_key.verify(&signed, sig)?;
                (AttestationMode::StrictVerified, Some(info.leaf_sha256))
            }
            None => {
                if !matches!(policy, AttestationPolicy::AllowUnattested) {
                    return Err(VerifyError::AttestationNotAllowed);
                }
                let alg = att_stmt_alg(att_stmt)?;
                if alg != credential_key.alg() {
                    return Err(VerifyError::AlgorithmMismatch);
                }
                let sig = att_stmt_sig(att_stmt)?;
                credential_key.verify(&signed, sig)?;
                (AttestationMode::SelfAttested, None)
            }
        },
        "tpm" => {
            // `tpm` is AttCA; it is always fully verified and needs no policy opt-in.
            let x5c = map_get(att_stmt, "x5c").ok_or(VerifyError::InvalidAttestationStatement)?;
            let certs = parse_x5c(x5c)?;
            // The anchor must be the pinned root; when `x5c` omits it (as Windows
            // Hello does) the compiled-in public root completes the chain, still
            // gated by the fingerprint pin.
            let bundle_root = crate::ms_root::MS_TPM_ROOT_2014_DER;
            let info = chain::verify_chain(
                &certs,
                &attested.aaguid,
                now,
                anchor_fingerprint,
                ChainProfile::Tpm,
                Some(&bundle_root),
            )?;
            verify_tpm(att_stmt, &credential_key, &signed, &info.leaf_spki)?;
            (AttestationMode::StrictVerified, Some(info.leaf_sha256))
        }
        "none" => {
            if !matches!(policy, AttestationPolicy::AllowUnattested) {
                return Err(VerifyError::AttestationNotAllowed);
            }
            // The `none` statement MUST be empty (WebAuthn §8.7).
            if !att_stmt.is_empty() {
                return Err(VerifyError::InvalidAttestationStatement);
            }
            (AttestationMode::None, None)
        }
        other => {
            return Err(VerifyError::UnsupportedAttestationFormat {
                format: other.to_string(),
            });
        }
    };

    Ok(crate::EnrollOutcome {
        credential_id: attested.credential_id.to_vec(),
        cose_public_key: attested.cose_public_key.to_vec(),
        aaguid: attested.aaguid,
        sign_count: prefix.sign_count,
        attestation: AttestationMetadata {
            format: fmt.to_string(),
            mode,
            leaf_sha256,
        },
    })
}

/// Parse the `x5c` array (each element a byte string) into raw DER certificates.
fn parse_x5c(value: &Value) -> Result<Vec<Vec<u8>>, VerifyError> {
    let arr = value
        .as_array()
        .ok_or(VerifyError::MalformedAttestationObject {
            reason: "x5c is not an array",
        })?;
    let mut certs = Vec::with_capacity(arr.len());
    for item in arr {
        let bytes = item.as_bytes().ok_or(VerifyError::MalformedCertificate {
            reason: "x5c entry is not a byte string",
        })?;
        certs.push(bytes.clone());
    }
    Ok(certs)
}

/// Read `attStmt["alg"]` as an integer.
fn att_stmt_alg(att_stmt: &[(Value, Value)]) -> Result<i64, VerifyError> {
    map_get(att_stmt, "alg")
        .and_then(Value::as_integer)
        .and_then(|i| i64::try_from(i).ok())
        .ok_or(VerifyError::InvalidAttestationStatement)
}

/// Read `attStmt["sig"]` as a byte string.
fn att_stmt_sig(att_stmt: &[(Value, Value)]) -> Result<&[u8], VerifyError> {
    map_get(att_stmt, "sig")
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
        .ok_or(VerifyError::InvalidAttestationStatement)
}

/// Verify a `tpm` attestation statement (§8.3) against the AIK certificate key.
fn verify_tpm(
    att_stmt: &[(Value, Value)],
    credential_key: &cose::ParsedCoseKey,
    att_to_be_signed: &[u8],
    aik_spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> Result<(), VerifyError> {
    let ver = map_get_text(att_stmt, "ver").ok_or(VerifyError::InvalidAttestationStatement)?;
    let alg = att_stmt_alg(att_stmt)?;
    let sig = att_stmt_sig(att_stmt)?;
    let cert_info =
        map_get_bytes(att_stmt, "certInfo").ok_or(VerifyError::InvalidAttestationStatement)?;
    let pub_area =
        map_get_bytes(att_stmt, "pubArea").ok_or(VerifyError::InvalidAttestationStatement)?;

    tpm::verify(&tpm::TpmCheck {
        ver,
        alg,
        sig,
        cert_info,
        pub_area,
        credential_key,
        att_to_be_signed,
        aik_spki,
    })
}

/// Fetch a map value by a text key.
fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
}

/// Fetch a text value by a text key.
fn map_get_text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map_get(map, key).and_then(Value::as_text)
}

/// Fetch a byte-string value by a text key.
fn map_get_bytes<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a [u8]> {
    map_get(map, key)
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
}
