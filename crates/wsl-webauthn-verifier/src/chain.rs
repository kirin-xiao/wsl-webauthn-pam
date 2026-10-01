//! X.509 attestation chain verification to a pinned trust anchor.
//!
//! The `packed`/`tpm` attestation statements carry the attestation certificate chain
//! in `x5c`. We do **not** trust a vendored root certificate: we pin its SHA-256
//! ([`MS_TPM_ROOT_2014_SHA256`]). The matching root either appears as the topmost
//! element of `x5c` (packed) or is completed from the bundled public copy (tpm, whose
//! integrity is checked against the pin). Every link below the anchor is
//! signature-checked, and the leaf is constrained to the exact shape the FIDO spec
//! requires for the relevant profile.
//!
//! ## Test-only anchor injection
//!
//! Because no test can forge a real Microsoft-root certificate, the anchor
//! fingerprint is threaded through as a parameter. The public entry points use
//! [`MS_TPM_ROOT_2014_SHA256`]; [`crate::verify_attestation_with_anchor`] lets the
//! test suite substitute a synthetic root's fingerprint. The production default is
//! unchanged and documented on that function.

use std::time::SystemTime;

use der::Decode as _;
use der::Encode as _;
use der::Tagged as _;
use der::referenced::OwnedToRef as _;
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use crate::STRICT_AAGUIDS;
use crate::cose::ParsedCoseKey;
use crate::error::VerifyError;
use rsa::signature::Verifier as _;

/// Maximum number of certificates accepted in `x5c` (defensive bound).
const MAX_CHAIN_LEN: usize = 8;

/// OID `id-fido-gen-ce-aaguid` (1.3.6.1.4.1.45724.1.1.4).
pub(crate) const ID_FIDO_GEN_CE_AAGUID: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");

/// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
const ECDSA_WITH_SHA256: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `sha1WithRSAEncryption` (1.2.840.113549.1.1.5). Present in the Microsoft TPM
/// intermediate observed in the spike; accepted for chain links (the leaf and anchor
/// are still pinned by fingerprint and constraints).
const SHA1_WITH_RSA: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
/// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
const SHA256_WITH_RSA: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
/// `sha384WithRSAEncryption` (1.2.840.113549.1.1.12).
const SHA384_WITH_RSA: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
/// `sha512WithRSAEncryption` (1.2.840.113549.1.1.13).
const SHA512_WITH_RSA: der::asn1::ObjectIdentifier =
    der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
/// `Ed25519` (1.3.101.112).
const ED25519: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112");

/// The Subject OU string an attestation leaf MUST carry.
const ATTESTATION_OU: &str = "Authenticator Attestation";

/// Facts extracted from a verified chain.
#[derive(Debug, Clone)]
pub(crate) struct ChainInfo {
    /// SHA-256 of the leaf certificate's DER encoding.
    pub(crate) leaf_sha256: [u8; 32],
    /// The leaf certificate's public key, used to bind the attestation `alg`.
    pub(crate) leaf_spki: SubjectPublicKeyInfoOwned,
}

/// Chain-profile-specific leaf constraints.
///
/// `packed`/AttCA (WebAuthn §8.2.1) requires a non-empty Subject with OU
/// `Authenticator Attestation` and an `id-fido-gen-ce-aaguid` extension matching the
/// authData AAGUID. `tpm` (WebAuthn §8.3.1) instead requires an **empty** Subject, a
/// SubjectAltName and an AIK EKU, and carries no AAGUID extension — so the packed
/// checks must not be applied to it. Both profiles still pin the AAGUID allow-list
/// against the *authData* AAGUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainProfile {
    /// `packed` / AttCA rules.
    Packed,
    /// `tpm` / AIK rules.
    Tpm,
}

/// Verify an attestation `x5c` chain against `anchor_fingerprint` and the authData
/// AAGUID. `certs_der` is the raw DER of each certificate in leaf-first order.
///
/// `bundle_root` is the DER of a trust anchor supplied out-of-band. It is used only
/// when the pinned anchor is **absent** from `x5c` (as Windows Hello TPM attestations
/// do), and only after its SHA-256 is checked against `anchor_fingerprint` — so it can
/// never broaden trust beyond the compile-time pin. When the anchor *is* present in
/// `x5c` it must be the topmost certificate and `bundle_root` is ignored.
pub(crate) fn verify_chain(
    certs_der: &[Vec<u8>],
    auth_aaguid: &[u8; 16],
    now: SystemTime,
    anchor_fingerprint: &[u8; 32],
    profile: ChainProfile,
    bundle_root: Option<&[u8]>,
) -> Result<ChainInfo, VerifyError> {
    if certs_der.is_empty() {
        return Err(VerifyError::CertificateChainEmpty);
    }
    if certs_der.len() > MAX_CHAIN_LEN {
        return Err(VerifyError::MalformedCertificate {
            reason: "x5c longer than the 8-certificate bound",
        });
    }

    // Parse every certificate up front; keep DER alongside so we can fingerprint.
    let mut parsed: Vec<Certificate> = Vec::with_capacity(certs_der.len());
    for der_bytes in certs_der {
        let cert =
            Certificate::from_der(der_bytes).map_err(|_| VerifyError::MalformedCertificate {
                reason: "certificate is not valid DER",
            })?;
        parsed.push(cert);
    }

    // Locate the pinned anchor. Either it is the topmost certificate in `x5c`, or it is
    // supplied out-of-band as `bundle_root` (integrity-pinned by fingerprint).
    let anchor_in_chain = certs_der
        .iter()
        .position(|der| &sha256(der) == anchor_fingerprint);
    let (chain_top, external_root): (usize, Option<Certificate>) = match anchor_in_chain {
        Some(index) => {
            if index != parsed.len() - 1 {
                // A certificate above the anchor (or a misplaced anchor) is not a
                // chain we can reason about.
                return Err(VerifyError::CertificateChainAnchorNotFound);
            }
            (index, None)
        }
        None => {
            let root_der = bundle_root.ok_or(VerifyError::CertificateChainAnchorNotFound)?;
            if &sha256(root_der) != anchor_fingerprint {
                // The bundled root does not match the pin; refuse rather than guess.
                return Err(VerifyError::CertificateChainAnchorNotFound);
            }
            let root =
                Certificate::from_der(root_der).map_err(|_| VerifyError::MalformedCertificate {
                    reason: "bundled trust anchor is not valid DER",
                })?;
            (parsed.len(), Some(root))
        }
    };

    // Validity window for every certificate in the chain (including the anchor).
    for cert in &parsed {
        check_validity(cert, now)?;
    }
    if let Some(root) = &external_root {
        check_validity(root, now)?;
    }

    // Link signatures: leaf <- ... <- top, where the issuer of the last in-`x5c`
    // certificate is either the next certificate or the bundled root.
    for i in 0..chain_top {
        let child = &parsed[i];
        let (issuer_subject, issuer_spki) = match parsed.get(i + 1) {
            Some(issuer) => (
                &issuer.tbs_certificate.subject,
                &issuer.tbs_certificate.subject_public_key_info,
            ),
            None => {
                let root = external_root.as_ref().ok_or(VerifyError::Internal {
                    reason: "chain has no issuer for its top certificate",
                })?;
                (
                    &root.tbs_certificate.subject,
                    &root.tbs_certificate.subject_public_key_info,
                )
            }
        };
        if &child.tbs_certificate.issuer != issuer_subject {
            return Err(VerifyError::CertificateChainIssuerMismatch);
        }
        verify_certificate_signature(child, issuer_spki)?;
    }

    let leaf = &parsed[0];

    // Leaf version 3.
    if leaf.tbs_certificate.version != Version::V3 {
        return Err(VerifyError::CertificateVersionNotV3);
    }

    // BasicConstraints: CA=false on the leaf, CA=true on everything above it.
    let leaf_bc = basic_constraints(leaf)?;
    if leaf_bc.ca {
        return Err(VerifyError::CertificateLeafIsCa);
    }
    for cert in &parsed[1..] {
        let bc = basic_constraints(cert)?;
        if !bc.ca {
            return Err(VerifyError::CertificateIntermediateNotCa);
        }
    }

    // Leaf Subject OU must be exactly "Authenticator Attestation".
    if profile == ChainProfile::Packed && !subject_has_ou(leaf, ATTESTATION_OU) {
        return Err(VerifyError::CertificateSubjectOuMismatch);
    }

    // TPM AIK certificates MUST have an empty Subject (WebAuthn §8.3.1).
    if profile == ChainProfile::Tpm && !leaf.tbs_certificate.subject.0.is_empty() {
        return Err(VerifyError::TpmAikSubjectNotEmpty);
    }

    // AAGUID extension on the leaf, and it must equal the authData AAGUID. The `tpm`
    // profile carries no AAGUID extension by design (WebAuthn §8.3.1); if present we
    // still require it to match.
    if profile == ChainProfile::Packed {
        let ext_aaguid = leaf_aaguid(leaf)?;
        if &ext_aaguid != auth_aaguid {
            return Err(VerifyError::CertificateAaguidMismatch);
        }
    } else if let Ok(ext_aaguid) = leaf_aaguid(leaf) {
        if &ext_aaguid != auth_aaguid {
            return Err(VerifyError::CertificateAaguidMismatch);
        }
    }

    // The authData AAGUID must be on the strict allow-list in all cases.
    if !STRICT_AAGUIDS.contains(auth_aaguid) {
        return Err(VerifyError::AaguidNotAllowed);
    }

    Ok(ChainInfo {
        leaf_sha256: sha256(&certs_der[0]),
        leaf_spki: leaf.tbs_certificate.subject_public_key_info.clone(),
    })
}

/// SHA-256 helper.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Check that `now` lies within `[not_before, not_after]`.
fn check_validity(cert: &Certificate, now: SystemTime) -> Result<(), VerifyError> {
    let validity = &cert.tbs_certificate.validity;
    let not_before = validity.not_before.to_system_time();
    let not_after = validity.not_after.to_system_time();
    if now < not_before {
        return Err(VerifyError::CertificateNotYetValid);
    }
    if now > not_after {
        return Err(VerifyError::CertificateExpired);
    }
    Ok(())
}

/// Extract and parse the BasicConstraints extension, which must be present.
fn basic_constraints(cert: &Certificate) -> Result<BasicConstraints, VerifyError> {
    let tbs = &cert.tbs_certificate;
    let bc = tbs
        .get::<BasicConstraints>()
        .map_err(|_| VerifyError::MalformedCertificate {
            reason: "BasicConstraints extension failed to parse",
        })?
        .map(|(_, bc)| bc)
        .ok_or(VerifyError::CertificateMissingBasicConstraints)?;
    Ok(bc)
}

/// Whether the certificate's Subject contains an OU attribute with UTF8 value `want`.
fn subject_has_ou(cert: &Certificate, want: &str) -> bool {
    use der::Tag;
    use der::asn1::Utf8StringRef;

    cert.tbs_certificate.subject.0.iter().any(|rdn| {
        rdn.0.iter().any(|atv| {
            atv.oid == const_oid::db::rfc4519::ORGANIZATIONAL_UNIT_NAME
                && atv.value.tag() == Tag::Utf8String
                && Utf8StringRef::try_from(&atv.value)
                    .map(|s| s.as_str() == want)
                    .unwrap_or(false)
        })
    })
}

/// Extract the 16-byte AAGUID from the leaf's `id-fido-gen-ce-aaguid` extension.
///
/// The extension's `extnValue` is an OCTET STRING whose content is the DER value of
/// the extension; both single (`04 10 …`) and the double-wrapped
/// (`04 12 04 10 …`) encodings seen in the wild are accepted.
fn leaf_aaguid(cert: &Certificate) -> Result<[u8; 16], VerifyError> {
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_deref()
        .ok_or(VerifyError::CertificateAaguidExtensionMissing)?;
    let ext = extensions
        .iter()
        .find(|e| e.extn_id == ID_FIDO_GEN_CE_AAGUID)
        .ok_or(VerifyError::CertificateAaguidExtensionMissing)?;

    let content = ext.extn_value.as_bytes();
    decode_aaguid(content)
}

/// Decode an AAGUID, tolerating one or two layers of OCTET STRING wrapping.
fn decode_aaguid(content: &[u8]) -> Result<[u8; 16], VerifyError> {
    let outer = der::asn1::OctetString::from_der(content)
        .map_err(|_| VerifyError::CertificateAaguidMalformed)?;
    let bytes = outer.as_bytes();
    if bytes.len() == 16 {
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        return Ok(out);
    }
    // Possibly double-wrapped.
    let inner = der::asn1::OctetString::from_der(bytes)
        .map_err(|_| VerifyError::CertificateAaguidMalformed)?;
    let inner_bytes = inner.as_bytes();
    if inner_bytes.len() == 16 {
        let mut out = [0u8; 16];
        out.copy_from_slice(inner_bytes);
        return Ok(out);
    }
    Err(VerifyError::CertificateAaguidMalformed)
}

/// Verify `child`'s signature over its TBS bytes using `issuer_spki`.
fn verify_certificate_signature(
    child: &Certificate,
    issuer_spki: &SubjectPublicKeyInfoOwned,
) -> Result<(), VerifyError> {
    let tbs = child
        .tbs_certificate
        .to_der()
        .map_err(|_| VerifyError::MalformedCertificate {
            reason: "TBS certificate failed to re-encode",
        })?;
    let signature = child
        .signature
        .as_bytes()
        .ok_or(VerifyError::MalformedCertificate {
            reason: "certificate signature is not octet-aligned",
        })?;
    let spki_ref = issuer_spki.owned_to_ref();
    let alg = child.signature_algorithm.oid;

    if alg == ECDSA_WITH_SHA256 {
        use ecdsa::signature::hazmat::PrehashVerifier as _;
        let key = p256::ecdsa::VerifyingKey::try_from(spki_ref).map_err(|_| {
            VerifyError::MalformedCertificate {
                reason: "issuer key is not a P-256 public key",
            }
        })?;
        let sig = p256::ecdsa::DerSignature::from_bytes(signature).map_err(|_| {
            VerifyError::MalformedCertificate {
                reason: "certificate ECDSA signature is not DER",
            }
        })?;
        key.verify_prehash(&Sha256::digest(&tbs), &sig)
            .map_err(|_| VerifyError::CertificateChainSignatureInvalid)
    } else if alg == SHA1_WITH_RSA {
        use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
        let key = rsa::RsaPublicKey::try_from(spki_ref).map_err(|_| {
            VerifyError::MalformedCertificate {
                reason: "issuer key is not an RSA public key",
            }
        })?;
        let sig =
            RsaSignature::try_from(signature).map_err(|_| VerifyError::MalformedCertificate {
                reason: "certificate RSA signature is malformed",
            })?;
        RsaVerifyingKey::<sha1::Sha1>::new(key)
            .verify(&tbs, &sig)
            .map_err(|_| VerifyError::CertificateChainSignatureInvalid)
    } else if matches!(alg, SHA256_WITH_RSA | SHA384_WITH_RSA | SHA512_WITH_RSA) {
        use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
        let key = rsa::RsaPublicKey::try_from(spki_ref).map_err(|_| {
            VerifyError::MalformedCertificate {
                reason: "issuer key is not an RSA public key",
            }
        })?;
        let sig =
            RsaSignature::try_from(signature).map_err(|_| VerifyError::MalformedCertificate {
                reason: "certificate RSA signature is malformed",
            })?;
        if alg == SHA256_WITH_RSA {
            RsaVerifyingKey::<Sha256>::new(key)
                .verify(&tbs, &sig)
                .map_err(|_| VerifyError::CertificateChainSignatureInvalid)
        } else if alg == SHA384_WITH_RSA {
            RsaVerifyingKey::<sha2::Sha384>::new(key)
                .verify(&tbs, &sig)
                .map_err(|_| VerifyError::CertificateChainSignatureInvalid)
        } else {
            RsaVerifyingKey::<sha2::Sha512>::new(key)
                .verify(&tbs, &sig)
                .map_err(|_| VerifyError::CertificateChainSignatureInvalid)
        }
    } else if alg == ED25519 {
        use ed25519_dalek::Verifier as _;
        let bytes =
            issuer_spki
                .subject_public_key
                .as_bytes()
                .ok_or(VerifyError::MalformedCertificate {
                    reason: "issuer Ed25519 key is not octet-aligned",
                })?;
        let arr: &[u8; 32] = bytes
            .try_into()
            .map_err(|_| VerifyError::MalformedCertificate {
                reason: "issuer Ed25519 key is not 32 bytes",
            })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(arr).map_err(|_| {
            VerifyError::MalformedCertificate {
                reason: "issuer Ed25519 key is invalid",
            }
        })?;
        let sig_bytes: &[u8; 64] =
            signature
                .try_into()
                .map_err(|_| VerifyError::MalformedCertificate {
                    reason: "certificate Ed25519 signature is not 64 bytes",
                })?;
        let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
        key.verify(&tbs, &sig)
            .map_err(|_| VerifyError::CertificateChainSignatureInvalid)
    } else {
        Err(VerifyError::UnsupportedCertificateAlgorithm)
    }
}

/// Build a [`ParsedCoseKey`] from a certificate SubjectPublicKeyInfo.
///
/// Used by `packed`/x5c attestation to bind `attStmt.alg` to the attestation leaf
/// certificate's public key. Only the three allow-listed algorithms are accepted.
pub(crate) fn cose_key_from_spki(
    spki: &SubjectPublicKeyInfoOwned,
) -> Result<ParsedCoseKey, VerifyError> {
    const OID_EC_PUBLIC_KEY: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const OID_RSA_ENCRYPTION: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

    let spki_ref = spki.owned_to_ref();
    let oid = spki.algorithm.oid;

    if oid == OID_EC_PUBLIC_KEY {
        let key = p256::ecdsa::VerifyingKey::try_from(spki_ref).map_err(|_| {
            VerifyError::MalformedCertificate {
                reason: "leaf key is not a P-256 public key",
            }
        })?;
        Ok(ParsedCoseKey::Es256(key))
    } else if oid == OID_RSA_ENCRYPTION {
        let key = rsa::RsaPublicKey::try_from(spki_ref).map_err(|_| {
            VerifyError::MalformedCertificate {
                reason: "leaf key is not an RSA public key",
            }
        })?;
        Ok(ParsedCoseKey::Rs256(Box::new(
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key),
        )))
    } else if oid == ED25519 {
        let bytes =
            spki.subject_public_key
                .as_bytes()
                .ok_or(VerifyError::MalformedCertificate {
                    reason: "leaf Ed25519 key is not octet-aligned",
                })?;
        let arr: &[u8; 32] = bytes
            .try_into()
            .map_err(|_| VerifyError::MalformedCertificate {
                reason: "leaf Ed25519 key is not 32 bytes",
            })?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(arr).map_err(|_| {
            VerifyError::MalformedCertificate {
                reason: "leaf Ed25519 key is invalid",
            }
        })?;
        Ok(ParsedCoseKey::Ed25519(Box::new(key)))
    } else {
        Err(VerifyError::UnsupportedCertificateAlgorithm)
    }
}
