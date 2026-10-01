//! Exhaustive error type for every verification path.
//!
//! Every parser stage has a dedicated `Malformed*` variant; every semantic check
//! (clientData equality, `rpIdHash`, flags, credential-id match, allow-listed
//! algorithms, chain constraints) has its own variant. No path panics: all parsing
//! failures are mapped here (plan §4).

use thiserror::Error;

/// Failure of a WebAuthn assertion or attestation verification.
///
/// Variants are exhaustive and stable so that callers (the PAM module and the CLI)
/// can map them to PAM result codes per plan §8 without guessing.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    // ------------------------------------------------------------------
    // clientDataJSON
    // ------------------------------------------------------------------
    /// `clientDataJSON` was not valid UTF-8 or not a valid JSON object.
    #[error("malformed clientDataJSON: {reason}")]
    MalformedClientData {
        /// Short, non-sensitive reason string.
        reason: &'static str,
    },

    /// A required `clientDataJSON` member was absent or had the wrong type.
    #[error("clientDataJSON member missing or wrongly typed")]
    ClientDataFieldMissing,

    /// The `type` member did not match the expected ceremony.
    #[error("clientDataJSON type does not match the expected ceremony")]
    ClientDataTypeMismatch,

    /// The decoded `challenge` did not match the expected challenge bytes.
    #[error("clientDataJSON challenge mismatch")]
    ChallengeMismatch,

    /// The `origin` member was not byte-equal to the pinned origin.
    #[error("clientDataJSON origin mismatch")]
    OriginMismatch,

    // ------------------------------------------------------------------
    // authenticatorData
    // ------------------------------------------------------------------
    /// `authenticatorData` was truncated or otherwise structurally invalid.
    #[error("malformed authenticatorData: {reason}")]
    MalformedAuthenticatorData {
        /// Short, non-sensitive reason string.
        reason: &'static str,
    },

    /// `rpIdHash` did not equal `SHA-256(RP_ID)`.
    #[error("authenticatorData rpIdHash mismatch")]
    RpIdHashMismatch,

    /// The User Present (UP) flag was not set.
    #[error("authenticatorData user-present flag not set")]
    UserPresenceRequired,

    /// The User Verified (UV) flag was not set.
    #[error("authenticatorData user-verified flag not set")]
    UserVerificationRequired,

    // ------------------------------------------------------------------
    // attestationObject
    // ------------------------------------------------------------------
    /// The CBOR `attestationObject` could not be parsed.
    #[error("malformed attestationObject: {reason}")]
    MalformedAttestationObject {
        /// Short, non-sensitive reason string.
        reason: &'static str,
    },

    /// A required `attestationObject` member was absent or wrongly typed.
    #[error("attestationObject member missing or wrongly typed")]
    MissingAttestationField,

    /// The attestation statement format is not supported.
    #[error("unsupported attestation format: {format}")]
    UnsupportedAttestationFormat {
        /// The `fmt` value as reported by the authenticator.
        format: String,
    },

    /// A required attestation-statement member was absent or wrongly typed.
    #[error("attestation statement member missing or wrongly typed")]
    InvalidAttestationStatement,

    /// `none`/self attestation was presented but the policy requires a verified chain.
    #[error("attestation is not acceptable under the configured policy")]
    AttestationNotAllowed,

    // ------------------------------------------------------------------
    // COSE key / algorithms
    // ------------------------------------------------------------------
    /// The COSE public key was structurally invalid.
    #[error("malformed COSE key: {reason}")]
    MalformedCoseKey {
        /// Short, non-sensitive reason string.
        reason: &'static str,
    },

    /// The COSE key used a compressed EC point (only uncompressed is accepted).
    #[error("COSE key uses a compressed EC point")]
    CoseKeyCompressedPoint,

    /// The COSE EC point was not on the curve.
    #[error("COSE key EC point is not on the curve")]
    CosePointNotOnCurve,

    /// The COSE RSA modulus was outside the accepted size range.
    #[error("COSE RSA modulus size {bits} bits is outside 2048..=4096")]
    CoseKeyModulusSize {
        /// Observed modulus size in bits.
        bits: u64,
    },

    /// The COSE key type is not supported.
    #[error("unsupported COSE key type: {kty}")]
    UnsupportedKeyType {
        /// The COSE `kty` label value.
        kty: i64,
    },

    /// The COSE algorithm is not on the allow-list.
    #[error("unsupported COSE algorithm: {alg}")]
    UnsupportedAlgorithm {
        /// The COSE `alg` label value.
        alg: i64,
    },

    /// The attestation statement algorithm did not match the signing key's algorithm.
    #[error("attestation algorithm does not match the signing key algorithm")]
    AlgorithmMismatch,

    // ------------------------------------------------------------------
    // assertion
    // ------------------------------------------------------------------
    /// The supplied credential id was empty.
    #[error("credential id must not be empty")]
    EmptyCredentialId,

    /// The reported credential id did not match the attested credential id.
    #[error("credential id mismatch")]
    CredentialIdMismatch,

    /// The signature was structurally malformed for the selected algorithm.
    #[error("malformed signature: {reason}")]
    MalformedSignature {
        /// Short, non-sensitive reason string.
        reason: &'static str,
    },

    /// The cryptographic signature did not verify.
    #[error("signature verification failed")]
    SignatureInvalid,

    // ------------------------------------------------------------------
    // X.509 chain
    // ------------------------------------------------------------------
    /// A certificate in the chain could not be parsed.
    #[error("malformed certificate: {reason}")]
    MalformedCertificate {
        /// Short, non-sensitive reason string.
        reason: &'static str,
    },

    /// The `x5c` array was empty.
    #[error("x5c certificate chain is empty")]
    CertificateChainEmpty,

    /// No certificate in `x5c` matched the pinned trust-anchor fingerprint.
    #[error("x5c did not chain to the pinned trust anchor")]
    CertificateChainAnchorNotFound,

    /// A certificate signature did not verify against its issuer.
    #[error("certificate chain signature verification failed")]
    CertificateChainSignatureInvalid,

    /// Issuer/subject names did not chain between adjacent certificates.
    #[error("certificate chain issuer/subject mismatch")]
    CertificateChainIssuerMismatch,

    /// The leaf certificate was not X.509 version 3.
    #[error("leaf certificate is not X.509 version 3")]
    CertificateVersionNotV3,

    /// The leaf certificate asserted CA=true.
    #[error("leaf certificate is a CA certificate")]
    CertificateLeafIsCa,

    /// An intermediate (or the anchor) certificate did not assert CA=true.
    #[error("intermediate certificate is not a CA certificate")]
    CertificateIntermediateNotCa,

    /// A certificate was missing the BasicConstraints extension.
    #[error("certificate is missing the BasicConstraints extension")]
    CertificateMissingBasicConstraints,

    /// The leaf Subject OU was not `Authenticator Attestation`.
    #[error("leaf certificate Subject OU is not \"Authenticator Attestation\"")]
    CertificateSubjectOuMismatch,

    /// A certificate was expired relative to the verification instant.
    #[error("certificate is expired")]
    CertificateExpired,

    /// A certificate was not yet valid relative to the verification instant.
    #[error("certificate is not yet valid")]
    CertificateNotYetValid,

    /// The `id-fido-gen-ce-aaguid` extension was absent from the leaf.
    #[error("leaf certificate is missing the id-fido-gen-ce-aaguid extension")]
    CertificateAaguidExtensionMissing,

    /// The `id-fido-gen-ce-aaguid` extension value was malformed.
    #[error("leaf certificate id-fido-gen-ce-aaguid extension is malformed")]
    CertificateAaguidMalformed,

    /// The certificate AAGUID did not match the authenticatorData AAGUID.
    #[error("certificate AAGUID does not match authenticatorData AAGUID")]
    CertificateAaguidMismatch,

    /// The AAGUID was not on the strict allow-list.
    #[error("AAGUID is not on the strict allow-list")]
    AaguidNotAllowed,

    /// The certificate signature algorithm is not supported.
    #[error("unsupported certificate signature algorithm")]
    UnsupportedCertificateAlgorithm,

    // ------------------------------------------------------------------
    // TPM attestation (WebAuthn §8.3)
    // ------------------------------------------------------------------
    /// The TPM `ver` field was not `"2.0"`.
    #[error("unsupported TPM attestation version: {ver}")]
    TpmVersionUnsupported {
        /// The version string as reported.
        ver: String,
    },

    /// The TPM `TPMS_ATTEST` (`certInfo`) structure was malformed.
    #[error("malformed TPM certInfo: {reason}")]
    MalformedTpmCertInfo {
        /// Short, non-sensitive reason string.
        reason: &'static str,
    },

    /// The TPM `TPMT_PUBLIC` (`pubArea`) structure was malformed.
    #[error("malformed TPM pubArea: {reason}")]
    MalformedTpmPubArea {
        /// Short, non-sensitive reason string.
        reason: &'static str,
    },

    /// `certInfo.magic` was not `TPM_GENERATED`.
    #[error("TPM certInfo magic is not TPM_GENERATED")]
    TpmCertInfoMagic,

    /// `certInfo.type` was not `TPM_ST_ATTEST_CERTIFY`.
    #[error("TPM certInfo type is not TPM_ST_ATTEST_CERTIFY")]
    TpmCertInfoType,

    /// `certInfo.extraData` did not equal the hash of `authData || clientDataHash`.
    #[error("TPM certInfo extraData does not match the hash of attToBeSigned")]
    TpmCertInfoExtraDataMismatch,

    /// The `name` attested in `certInfo` did not equal the Name of `pubArea`.
    #[error("TPM certInfo attested name does not match the computed pubArea Name")]
    TpmCertInfoNameMismatch,

    /// The `nameAlg` declared by `pubArea` is not supported.
    #[error("unsupported TPM nameAlg: {name_alg:#06x}")]
    TpmNameAlgUnsupported {
        /// The raw `TPMI_ALG_HASH` value.
        name_alg: u16,
    },

    /// The public key described by `pubArea` did not match the credential public key.
    #[error("TPM pubArea public key does not match the credential public key")]
    TpmPubAreaKeyMismatch,

    /// The `attStmt.alg` could not be mapped to a signature scheme and hash.
    #[error("unsupported TPM attestation algorithm: {alg}")]
    TpmAlgorithmUnsupported {
        /// The COSE algorithm identifier from `attStmt.alg`.
        alg: i64,
    },

    /// The TPM AIK leaf certificate had a non-empty Subject (§8.3.1 requires empty).
    #[error("TPM AIK certificate Subject is not empty")]
    TpmAikSubjectNotEmpty,

    /// A supported operation was invoked with an internally inconsistent input.
    #[error("internal verification inconsistency: {reason}")]
    Internal {
        /// Short, non-sensitive reason string.
        reason: &'static str,
    },
}
