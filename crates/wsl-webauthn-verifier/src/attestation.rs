//! Attestation-object parsing and verification (WebAuthn §6.5).
//!
//! Supported formats:
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
//! Any other format is rejected outright. The authData AAGUID must be on
//! [`crate::STRICT_AAGUIDS`] on **every** attestation path — it is checked once, before
//! the format/policy dispatch below, so no arm (including self-attested `packed` and
//! `none` under [`AttestationPolicy::AllowUnattested`]) can return an outcome for a
//! disallowed AAGUID.

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
use crate::{AttestationMetadata, AttestationMode, AttestationPolicy, STRICT_AAGUIDS};
use wsl_webauthn_protocol::ClientDataKind;

/// Verify a registration ceremony and return the enrollment outcome.
///
/// `anchor_fingerprint` is the SHA-256 of the trusted root certificate; the public
/// entry point supplies [`crate::MS_TPM_ROOT_2014_SHA256`], while the (feature-gated)
/// test seam `crate::verify_attestation_with_anchor` injects a synthetic root.
pub(crate) fn verify(
    attestation_object: &[u8],
    client_data_json: &[u8],
    expected_challenge: &[u8],
    reported_credential_id: &[u8],
    policy: &AttestationPolicy,
    now: SystemTime,
    anchor_fingerprint: &[u8; 32],
) -> Result<crate::EnrollOutcome, VerifyError> {
    if attestation_object.len() > crate::MAX_ATTESTATION_BYTES {
        return Err(VerifyError::MalformedAttestationObject {
            reason: "exceeds the maximum accepted size",
        });
    }
    if client_data_json.len() > crate::MAX_CLIENT_DATA_BYTES {
        return Err(VerifyError::InputTooLarge {
            field: "clientDataJSON",
            len: client_data_json.len(),
            max: crate::MAX_CLIENT_DATA_BYTES,
        });
    }

    // 1. clientDataJSON must be a `webauthn.create` for our challenge/origin.
    clientdata::validate(client_data_json, ClientDataKind::Create, expected_challenge)?;

    // 2. Parse the CBOR attestation object. The whole input must be exactly one CBOR
    //    item: trailing bytes after the map are rejected (`decode_exact`).
    let obj = crate::cbor::decode_exact(attestation_object).map_err(|()| {
        VerifyError::MalformedAttestationObject {
            reason: "not valid CBOR, or has trailing bytes",
        }
    })?;
    let map = obj
        .as_map()
        .ok_or(VerifyError::MalformedAttestationObject {
            reason: "attestationObject is not a CBOR map",
        })?;

    let fmt = map_get_unique(map, "fmt")?
        .and_then(Value::as_text)
        .ok_or(VerifyError::MissingAttestationField)?;
    let auth_data = map_get_unique(map, "authData")?
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
        .ok_or(VerifyError::MissingAttestationField)?;
    let att_stmt = map_get_unique(map, "attStmt")?
        .and_then(Value::as_map)
        .ok_or(VerifyError::InvalidAttestationStatement)?;

    // 3. authenticatorData: fixed prefix (rpIdHash + UP + UV) then attested data.
    let prefix = parse_and_validate_prefix(auth_data)?;
    let attested = parse_attested_credential_data(auth_data)?;

    // 3a. The authData AAGUID must be on the strict allow-list. It is enforced here,
    //     before any policy arm or format dispatch can return an outcome, so the
    //     allow-list cannot be bypassed by choosing a weaker format.
    if !STRICT_AAGUIDS.contains(&attested.aaguid) {
        return Err(VerifyError::AaguidNotAllowed);
    }

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
        "packed" => {
            // §8.2: a packed statement carries only `alg`, `sig`, and (AttCA) `x5c`.
            reject_unknown_att_stmt_keys(att_stmt, &["alg", "sig", "x5c"])?;
            match map_get_unique(att_stmt, "x5c")? {
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
            }
        }
        "tpm" => {
            // `tpm` is AttCA; it is always fully verified and needs no policy opt-in.
            // §8.3: allowed members are `ver`, `alg`, `sig`, `x5c`, `certInfo`, `pubArea`.
            reject_unknown_att_stmt_keys(
                att_stmt,
                &["ver", "alg", "sig", "x5c", "certInfo", "pubArea"],
            )?;
            let x5c =
                map_get_unique(att_stmt, "x5c")?.ok_or(VerifyError::InvalidAttestationStatement)?;
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
        alg: i32::try_from(credential_key.alg()).map_err(|_| VerifyError::Internal {
            reason: "credential COSE alg does not fit i32",
        })?,
        aaguid: attested.aaguid,
        sign_count: prefix.sign_count,
        attestation: AttestationMetadata {
            format: fmt.to_string(),
            mode,
            leaf_sha256,
        },
    })
}

/// Parse the `x5c` array (each element a byte string) into raw DER certificate
/// slices, borrowed from the attestation value (no per-certificate copy).
fn parse_x5c(value: &Value) -> Result<Vec<&[u8]>, VerifyError> {
    let arr = value
        .as_array()
        .ok_or(VerifyError::MalformedAttestationObject {
            reason: "x5c is not an array",
        })?;
    let mut certs = Vec::with_capacity(arr.len());
    for item in arr {
        let bytes =
            item.as_bytes()
                .map(Vec::as_slice)
                .ok_or(VerifyError::MalformedCertificate {
                    reason: "x5c entry is not a byte string",
                })?;
        certs.push(bytes);
    }
    Ok(certs)
}

/// Read `attStmt["alg"]` as an integer.
fn att_stmt_alg(att_stmt: &[(Value, Value)]) -> Result<i64, VerifyError> {
    map_get_unique(att_stmt, "alg")?
        .and_then(Value::as_integer)
        .and_then(|i| i64::try_from(i).ok())
        .ok_or(VerifyError::InvalidAttestationStatement)
}

/// Read `attStmt["sig"]` as a byte string.
fn att_stmt_sig(att_stmt: &[(Value, Value)]) -> Result<&[u8], VerifyError> {
    map_get_unique(att_stmt, "sig")?
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
    let ver = map_get_unique(att_stmt, "ver")?
        .and_then(Value::as_text)
        .ok_or(VerifyError::InvalidAttestationStatement)?;
    let alg = att_stmt_alg(att_stmt)?;
    let sig = att_stmt_sig(att_stmt)?;
    let cert_info = map_get_unique(att_stmt, "certInfo")?
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
        .ok_or(VerifyError::InvalidAttestationStatement)?;
    let pub_area = map_get_unique(att_stmt, "pubArea")?
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
        .ok_or(VerifyError::InvalidAttestationStatement)?;

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

/// Fetch a map value by a text key, rejecting a repeated key.
///
/// CBOR maps may technically carry duplicate keys; a first-wins lookup (`find_map`)
/// would silently ignore the later value and let a duplicate `fmt`/`attStmt` shadow
/// a stricter one. Any repeated key is a malformed attestation object here.
fn map_get_unique<'a>(
    map: &'a [(Value, Value)],
    key: &str,
) -> Result<Option<&'a Value>, VerifyError> {
    let mut found: Option<&'a Value> = None;
    for (k, v) in map {
        if k.as_text() == Some(key) {
            if found.is_some() {
                return Err(VerifyError::MalformedAttestationObject {
                    reason: "duplicate CBOR map key",
                });
            }
            found = Some(v);
        }
    }
    Ok(found)
}

/// Reject any `attStmt` member outside the per-format allow-set.
///
/// Each WebAuthn statement format defines the exact members it may carry. An
/// unexpected (or non-text) key means the statement is not well-formed, so it is
/// rejected rather than silently ignored.
fn reject_unknown_att_stmt_keys(
    att_stmt: &[(Value, Value)],
    allowed: &[&str],
) -> Result<(), VerifyError> {
    for (k, _) in att_stmt {
        match k.as_text() {
            Some(key) if allowed.contains(&key) => {}
            _ => return Err(VerifyError::InvalidAttestationStatement),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_attestation_object() {
        let big = vec![0u8; crate::MAX_ATTESTATION_BYTES + 1];
        let err = verify(
            &big,
            &[],
            b"challenge",
            b"cred",
            &AttestationPolicy::Strict,
            SystemTime::now(),
            &crate::MS_TPM_ROOT_2014_SHA256,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            VerifyError::MalformedAttestationObject {
                reason: "exceeds the maximum accepted size"
            }
        ));
    }

    #[test]
    fn rejects_oversized_client_data() {
        let big = vec![0u8; crate::MAX_CLIENT_DATA_BYTES + 1];
        let err = verify(
            &[],
            &big,
            b"challenge",
            b"cred",
            &AttestationPolicy::Strict,
            SystemTime::now(),
            &crate::MS_TPM_ROOT_2014_SHA256,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            VerifyError::InputTooLarge {
                field: "clientDataJSON",
                ..
            }
        ));
    }
}
