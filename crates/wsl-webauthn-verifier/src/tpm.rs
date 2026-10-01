//! TPM attestation statement verification (WebAuthn §8.3, TPM 2.0 Part 2).
//!
//! Windows Hello emits `fmt: "tpm"` attestations on TPM-equipped machines (D3 amended
//! after the spike). The `attStmt` carries:
//!
//! ```text
//! { ver: "2.0", alg: COSEAlgorithmIdentifier, x5c: [aikCert, …],
//!   sig: bytes, certInfo: bytes, pubArea: bytes }
//! ```
//!
//! Verification sequence (all fail-closed):
//!
//! 1. `ver == "2.0"`.
//! 2. `x5c` chains to the pinned anchor under the [`ChainProfile::Tpm`] leaf rules
//!    (empty Subject, no packed OU/AAGUID-extension requirements); the authData
//!    AAGUID must still be on [`crate::STRICT_AAGUIDS`].
//! 3. `sig` is verified over the raw `certInfo` bytes using the AIK public key from
//!    `x5c[0]`. The signature scheme is taken from `attStmt.alg` when it maps to a
//!    scheme compatible with the AIK key type; otherwise a small compatible set is
//!    tried and the signature must verify under one of them (Windows Hello reports
//!    `alg: -65535` = COSE `RS1`, i.e. RSA PKCS#1 v1.5 with SHA-1). The digest that
//!    actually verified is returned and is the **only** digest accepted for
//!    `extraData` below.
//! 4. `certInfo` (TPMS_ATTEST) is parsed: `magic == TPM_GENERATED`,
//!    `type == TPM_ST_ATTEST_CERTIFY`, and `extraData == H(authData || clientDataHash)`
//!    where `H` is exactly the digest that verified the AIK signature (SHA-1 for
//!    `RS1`, SHA-256 for `RS256`, …).
//! 5. The `name` attested inside `TPMS_CERTIFY_INFO` equals `nameAlg || H_name(pubArea)`
//!    (TPM 2.0 Part 1 §16). The Name is computed over the **entire** `pubArea` bytes
//!    *without* any outer `TPM2B` size prefix (the CBOR field is the bare
//!    `TPMT_PUBLIC`, confirmed against the captured vector).
//! 6. The public key described by `pubArea.parameters`/`pubArea.unique` equals the
//!    credential public key from `authData`.
//!
//! The `alg` allow-list of credential key algorithms ({−7,−257,−8}) does **not** apply
//! here: `attStmt.alg` identifies the AIK signature, which is independent of the
//! credential's COSE algorithm.
//!
//! Supported `nameAlg`s: SHA-1, SHA-256, SHA-384, SHA-512. Any other value is rejected
//! ([`VerifyError::TpmNameAlgUnsupported`]). Only SHA-256 is emitted by Windows Hello
//! today; the others are cheap, standards-defined options.

use der::referenced::OwnedToRef as _;
use sha2::{Digest as _, Sha256};
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use crate::cose::ParsedCoseKey;
use crate::error::VerifyError;

// TPM constants (TPM 2.0 Part 2).
const TPM_GENERATED: u32 = 0xff54_4347;
const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ECC_NIST_P256: u16 = 0x0003;

// TPMI_ALG_HASH values.
const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA512: u16 = 0x000d;

// COSE algorithm identifiers relevant to the AIK signature.
const COSE_RS1: i64 = -65535;
const COSE_RS256: i64 = -257;
const COSE_RS384: i64 = -258;
const COSE_RS512: i64 = -259;
const COSE_ES256: i64 = -7;
const COSE_ES384: i64 = -35;
const COSE_ES512: i64 = -36;
const COSE_EDDSA: i64 = -8;

/// Which digest a scheme uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashKind {
    /// Digest `data` with this algorithm.
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashKind::Sha1 => sha1::Sha1::digest(data).to_vec(),
            HashKind::Sha256 => Sha256::digest(data).to_vec(),
            HashKind::Sha384 => sha2::Sha384::digest(data).to_vec(),
            HashKind::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    /// The `TPMI_ALG_HASH` value.
    fn tpm_id(self) -> u16 {
        match self {
            HashKind::Sha1 => TPM_ALG_SHA1,
            HashKind::Sha256 => TPM_ALG_SHA256,
            HashKind::Sha384 => TPM_ALG_SHA384,
            HashKind::Sha512 => TPM_ALG_SHA512,
        }
    }
}

/// Map a `TPMI_ALG_HASH` to a supported [`HashKind`].
fn hash_from_tpm_id(id: u16) -> Result<HashKind, VerifyError> {
    match id {
        TPM_ALG_SHA1 => Ok(HashKind::Sha1),
        TPM_ALG_SHA256 => Ok(HashKind::Sha256),
        TPM_ALG_SHA384 => Ok(HashKind::Sha384),
        TPM_ALG_SHA512 => Ok(HashKind::Sha512),
        other => Err(VerifyError::TpmNameAlgUnsupported { name_alg: other }),
    }
}

/// The signature scheme to use for the AIK signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// RSA PKCS#1 v1.5 with the given digest.
    Rsa(HashKind),
    /// ECDSA with the given digest (P-256/384/512).
    Ecdsa(HashKind),
}

/// Map a COSE algorithm to a scheme, if we recognise it.
fn scheme_from_alg(alg: i64) -> Option<Scheme> {
    match alg {
        COSE_RS1 => Some(Scheme::Rsa(HashKind::Sha1)),
        COSE_RS256 => Some(Scheme::Rsa(HashKind::Sha256)),
        COSE_RS384 => Some(Scheme::Rsa(HashKind::Sha384)),
        COSE_RS512 => Some(Scheme::Rsa(HashKind::Sha512)),
        COSE_ES256 => Some(Scheme::Ecdsa(HashKind::Sha256)),
        COSE_ES384 => Some(Scheme::Ecdsa(HashKind::Sha384)),
        COSE_ES512 => Some(Scheme::Ecdsa(HashKind::Sha512)),
        // EdDSA has no pre-hash; TPM does not use it. Fall back to trial verification.
        COSE_EDDSA => None,
        _ => None,
    }
}

/// A minimal, bounds-checked big-endian cursor over TPM structures.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VerifyError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(VerifyError::MalformedTpmCertInfo {
                reason: "length overflow",
            })?;
        if end > self.bytes.len() {
            return Err(VerifyError::MalformedTpmCertInfo {
                reason: "truncated TPM structure",
            });
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, VerifyError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, VerifyError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, VerifyError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a `TPM2B_*`: a big-endian u16 length followed by that many bytes.
    fn sized(&mut self) -> Result<&'a [u8], VerifyError> {
        let len = self.u16()? as usize;
        self.take(len)
    }
}

/// Parsed `TPMS_ATTEST` (the `certInfo` field).
#[derive(Debug)]
struct CertInfo<'a> {
    /// Raw `extraData` bytes (the digest of `attToBeSigned`).
    extra_data: &'a [u8],
    /// The `name` inside `TPMS_CERTIFY_INFO` (`nameAlg || digest`).
    name: &'a [u8],
}

/// Parse the `certInfo` (`TPMS_ATTEST`) structure, validating magic and type.
fn parse_cert_info(bytes: &[u8]) -> Result<CertInfo<'_>, VerifyError> {
    let mut c = Cursor::new(bytes);
    let magic = c.u32()?;
    if magic != TPM_GENERATED {
        return Err(VerifyError::TpmCertInfoMagic);
    }
    let ty = c.u16()?;
    if ty != TPM_ST_ATTEST_CERTIFY {
        return Err(VerifyError::TpmCertInfoType);
    }
    let _qualified_signer = c.sized()?;
    let extra_data = c.sized()?;
    // clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1).
    let _clock = c.u64()?;
    let _reset = c.u32()?;
    let _restart = c.u32()?;
    let _safe = c.take(1)?;
    let _firmware_version = c.u64()?;
    // attested = TPMS_CERTIFY_INFO { name TPM2B_NAME, qualifiedName TPM2B_NAME }.
    let name = c.sized()?;
    let _qualified_name = c.sized()?;
    if c.remaining() != 0 {
        return Err(VerifyError::MalformedTpmCertInfo {
            reason: "trailing bytes after TPMS_ATTEST",
        });
    }
    Ok(CertInfo { extra_data, name })
}

/// Parsed `TPMT_PUBLIC` (`pubArea`) — enough to compute the Name and compare keys.
#[derive(Debug)]
struct PubArea<'a> {
    ty: u16,
    /// Raw `nameAlg` (`TPMI_ALG_HASH`); mapped to a supported digest in [`verify`].
    name_alg: u16,
    /// ECC `x`/`y`, when `ty == TPM_ALG_ECC`.
    ecc: Option<(&'a [u8], &'a [u8])>,
    /// RSA modulus, when `ty == TPM_ALG_RSA`.
    rsa_modulus: Option<&'a [u8]>,
    /// RSA public exponent (already defaulted to 65537 when TPM encoded 0).
    rsa_exponent: u32,
    /// The `keyBits` declared in `TPMS_RSA_PARMS` (0 for ECC keys).
    key_bits: u16,
}

/// Parse `pubArea` as a bare `TPMT_PUBLIC` (no `TPM2B_PUBLIC` size prefix).
///
/// This validates structure only; the `nameAlg` support check happens in [`verify`].
fn parse_pub_area(bytes: &[u8]) -> Result<PubArea<'_>, VerifyError> {
    let mut c = Cursor::new(bytes);
    let ty = c.u16().map_err(as_pubarea)?;
    let name_alg = c.u16().map_err(as_pubarea)?;
    let _object_attributes = c.u32().map_err(as_pubarea)?;
    let _auth_policy = c.sized().map_err(as_pubarea)?;

    let mut ecc = None;
    let mut rsa_modulus = None;
    let mut rsa_exponent = 65537u32;
    let mut key_bits = 0u16;

    match ty {
        TPM_ALG_ECC => {
            // TPMS_ECC_PARMS: symmetric(2) scheme(2) curveID(2) kdf(2).
            let _symmetric = c.u16().map_err(as_pubarea)?;
            let _scheme = c.u16().map_err(as_pubarea)?;
            let curve_id = c.u16().map_err(as_pubarea)?;
            let _kdf = c.u16().map_err(as_pubarea)?;
            if curve_id != TPM_ECC_NIST_P256 {
                return Err(VerifyError::MalformedTpmPubArea {
                    reason: "ECC curve is not NIST P-256",
                });
            }
            // TPMS_ECC_POINT: x TPM2B_ECC_PARAMETER, y TPM2B_ECC_PARAMETER.
            let x = c.sized().map_err(as_pubarea)?;
            let y = c.sized().map_err(as_pubarea)?;
            ecc = Some((x, y));
        }
        TPM_ALG_RSA => {
            // TPMS_RSA_PARMS: symmetric(2) scheme(2) keyBits(2) exponent(4).
            let _symmetric = c.u16().map_err(as_pubarea)?;
            let _scheme = c.u16().map_err(as_pubarea)?;
            key_bits = c.u16().map_err(as_pubarea)?;
            let exponent = c.u32().map_err(as_pubarea)?;
            rsa_exponent = if exponent == 0 { 65537 } else { exponent };
            // TPMS_RSA unique: TPM2B_PUBLIC_KEY_RSA (modulus).
            let modulus = c.sized().map_err(as_pubarea)?;
            rsa_modulus = Some(modulus);
        }
        _ => {
            return Err(VerifyError::MalformedTpmPubArea {
                reason: "pubArea type is neither RSA nor ECC",
            });
        }
    }

    if c.remaining() != 0 {
        return Err(VerifyError::MalformedTpmPubArea {
            reason: "trailing bytes after TPMT_PUBLIC",
        });
    }

    Ok(PubArea {
        ty,
        name_alg,
        ecc,
        rsa_modulus,
        rsa_exponent,
        key_bits,
    })
}

/// Re-tag a cursor error as a pubArea parse error.
fn as_pubarea(_e: VerifyError) -> VerifyError {
    VerifyError::MalformedTpmPubArea {
        reason: "truncated TPMT_PUBLIC",
    }
}

/// Whether `bytes` parse as a valid `TPMS_ATTEST` (`certInfo`) structure.
///
/// Panic-free; used by the fuzz/proptest smoke suite.
pub(crate) fn parse_cert_info_ok(bytes: &[u8]) -> bool {
    parse_cert_info(bytes).is_ok()
}

/// Whether `bytes` parse as a valid `TPMT_PUBLIC` (`pubArea`) structure.
///
/// Panic-free; used by the fuzz/proptest smoke suite.
pub(crate) fn parse_pub_area_ok(bytes: &[u8]) -> bool {
    parse_pub_area(bytes).is_ok()
}

/// Inputs to [`verify`].
pub(crate) struct TpmCheck<'a> {
    pub(crate) ver: &'a str,
    pub(crate) alg: i64,
    pub(crate) sig: &'a [u8],
    pub(crate) cert_info: &'a [u8],
    pub(crate) pub_area: &'a [u8],
    /// SHA-256 of the authData AAGUID's credential public key (`ParsedCoseKey`).
    pub(crate) credential_key: &'a ParsedCoseKey,
    /// `authData || SHA-256(clientDataJSON)`.
    pub(crate) att_to_be_signed: &'a [u8],
    /// The AIK certificate public key (from `x5c[0]`).
    pub(crate) aik_spki: &'a SubjectPublicKeyInfoOwned,
}

/// Verify the TPM attestation statement; returns `Ok(())` on success.
pub(crate) fn verify(check: &TpmCheck<'_>) -> Result<(), VerifyError> {
    if check.ver != "2.0" {
        return Err(VerifyError::TpmVersionUnsupported {
            ver: check.ver.to_string(),
        });
    }

    let scheme = scheme_from_alg(check.alg);
    if scheme.is_none() && !alg_is_trialable(check.alg) {
        return Err(VerifyError::TpmAlgorithmUnsupported { alg: check.alg });
    }

    // 1. Verify the AIK signature over the raw certInfo bytes. The returned
    //    `HashKind` is the digest that actually verified; it is the only digest the
    //    `extraData` check below accepts, so `attStmt.alg` (or, for an unrecognised
    //    alg, the scheme that genuinely verified) binds the hash deterministically.
    let verified_hash = verify_aik_signature(check.sig, check.cert_info, check.aik_spki, scheme)?;

    // 2. Parse and validate certInfo.
    let cert_info = parse_cert_info(check.cert_info)?;

    // 3. extraData must equal H(attToBeSigned) under exactly the digest that verified
    //    the AIK signature. Accepting any other supported digest would decouple the
    //    declared scheme from the attested transcript.
    if verified_hash.digest(check.att_to_be_signed) != cert_info.extra_data {
        return Err(VerifyError::TpmCertInfoExtraDataMismatch);
    }

    // 4. Parse pubArea and check the attested Name.
    let pub_area = parse_pub_area(check.pub_area)?;
    let name_alg = hash_from_tpm_id(pub_area.name_alg)?;
    let digest = name_alg.digest(check.pub_area);
    let mut expected_name = Vec::with_capacity(2 + digest.len());
    expected_name.extend_from_slice(&name_alg.tpm_id().to_be_bytes());
    expected_name.extend_from_slice(&digest);
    if expected_name.as_slice() != cert_info.name {
        return Err(VerifyError::TpmCertInfoNameMismatch);
    }

    // 5. pubArea must describe the same key as the credential. For RSA, the declared
    //    `keyBits` must also agree with the modulus actually present in `unique`, so a
    //    mismatch between the two attested fields is rejected even though `matches_rsa`
    //    compares only `(n, e)`.
    let key_matches = match pub_area.ty {
        TPM_ALG_ECC => match pub_area.ecc {
            Some((x, y)) => check.credential_key.matches_ec_p256(x, y),
            None => false,
        },
        TPM_ALG_RSA => match pub_area.rsa_modulus {
            Some(n) => {
                let actual_bits: u64 = rsa::BigUint::from_bytes_be(n).bits() as u64;
                if actual_bits != u64::from(pub_area.key_bits) {
                    return Err(VerifyError::TpmPubAreaKeyBitsMismatch {
                        declared: pub_area.key_bits,
                        actual: actual_bits,
                    });
                }
                let e = pub_area.rsa_exponent.to_be_bytes();
                check.credential_key.matches_rsa(n, &e)
            }
            None => false,
        },
        _ => false,
    };
    if !key_matches {
        return Err(VerifyError::TpmPubAreaKeyMismatch);
    }

    Ok(())
}

/// Whether an unrecognised `alg` should still be trial-verified (rather than rejected).
///
/// We accept unknown algorithms only if the signature genuinely verifies under a
/// scheme compatible with the AIK key type; this preserves interoperability with
/// future/exotic AIK algorithms without weakening the check.
fn alg_is_trialable(alg: i64) -> bool {
    // Any value other than the COSE EdDSA sentinel is eligible for trial verification.
    alg != COSE_EDDSA
}

/// Verify `sig` over `message` using the AIK key.
///
/// When `scheme` is `Some`, only that scheme is tried. Otherwise every scheme
/// compatible with the key type is tried and the signature must verify under one.
/// Returns the [`HashKind`] that actually verified, which the caller binds to the
/// `extraData` check.
fn verify_aik_signature(
    sig: &[u8],
    message: &[u8],
    spki: &SubjectPublicKeyInfoOwned,
    scheme: Option<Scheme>,
) -> Result<HashKind, VerifyError> {
    const OID_EC_PUBLIC_KEY: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const OID_RSA_ENCRYPTION: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    const OID_ED25519: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112");

    let spki_ref = spki.owned_to_ref();
    let oid = spki.algorithm.oid;

    if oid == OID_RSA_ENCRYPTION {
        return verify_rsa(sig, message, spki_ref, scheme);
    }
    if oid == OID_EC_PUBLIC_KEY {
        return verify_ecdsa(sig, message, spki_ref, scheme);
    }
    if oid == OID_ED25519 {
        verify_ed25519(sig, message, spki)?;
        // EdDSA has no pre-hash; TPM does not use it. Pin SHA-256 as the extraData
        // digest so the check stays deterministic rather than accepting any hash.
        return Ok(HashKind::Sha256);
    }
    Err(VerifyError::UnsupportedCertificateAlgorithm)
}

/// Verify an RSA PKCS#1 v1.5 AIK signature, returning the digest that verified.
fn verify_rsa(
    sig: &[u8],
    message: &[u8],
    spki: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
    scheme: Option<Scheme>,
) -> Result<HashKind, VerifyError> {
    use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
    use rsa::signature::Verifier as _;

    let key = rsa::RsaPublicKey::try_from(spki).map_err(|_| VerifyError::MalformedCertificate {
        reason: "AIK key is not an RSA public key",
    })?;
    let sig = RsaSignature::try_from(sig).map_err(|_| VerifyError::MalformedSignature {
        reason: "TPM RSA signature is malformed",
    })?;

    let try_hash = |h: HashKind| -> bool {
        match h {
            HashKind::Sha1 => RsaVerifyingKey::<sha1::Sha1>::new(key.clone())
                .verify(message, &sig)
                .is_ok(),
            HashKind::Sha256 => RsaVerifyingKey::<Sha256>::new(key.clone())
                .verify(message, &sig)
                .is_ok(),
            HashKind::Sha384 => RsaVerifyingKey::<sha2::Sha384>::new(key.clone())
                .verify(message, &sig)
                .is_ok(),
            HashKind::Sha512 => RsaVerifyingKey::<sha2::Sha512>::new(key.clone())
                .verify(message, &sig)
                .is_ok(),
        }
    };

    let verified = match scheme {
        Some(Scheme::Rsa(h)) => try_hash(h).then_some(h),
        Some(Scheme::Ecdsa(_)) => {
            // An ECDSA algorithm cannot be valid for an RSA AIK.
            return Err(VerifyError::TpmAlgorithmUnsupported {
                alg: scheme_alg_hint(scheme),
            });
        }
        None => [HashKind::Sha1, HashKind::Sha256]
            .into_iter()
            .find(|h| try_hash(*h)),
    };
    verified.ok_or(VerifyError::SignatureInvalid)
}

/// Verify an ECDSA (P-256) AIK signature (always SHA-256), returning its digest.
fn verify_ecdsa(
    sig: &[u8],
    message: &[u8],
    spki: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
    scheme: Option<Scheme>,
) -> Result<HashKind, VerifyError> {
    use ecdsa::signature::hazmat::PrehashVerifier as _;

    let key = p256::ecdsa::VerifyingKey::try_from(spki).map_err(|_| {
        VerifyError::MalformedCertificate {
            reason: "AIK key is not a P-256 public key",
        }
    })?;
    let sig = p256::ecdsa::DerSignature::from_bytes(sig).map_err(|_| {
        VerifyError::MalformedSignature {
            reason: "TPM ECDSA signature is not DER",
        }
    })?;

    // Only ES256 is compatible with a P-256 AIK key; any other declared algorithm
    // conflicts with the key type and is rejected outright.
    match scheme {
        None | Some(Scheme::Ecdsa(HashKind::Sha256)) => {}
        other => {
            return Err(VerifyError::TpmAlgorithmUnsupported {
                alg: scheme_alg_hint(other),
            });
        }
    }
    key.verify_prehash(&Sha256::digest(message), &sig)
        .map_err(|_| VerifyError::SignatureInvalid)?;
    Ok(HashKind::Sha256)
}

/// Verify an Ed25519 AIK signature (not used by Windows Hello TPMs; supported defensively).
fn verify_ed25519(
    sig: &[u8],
    message: &[u8],
    spki: &SubjectPublicKeyInfoOwned,
) -> Result<(), VerifyError> {
    let bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(VerifyError::MalformedCertificate {
            reason: "AIK Ed25519 key is not octet-aligned",
        })?;
    let arr: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| VerifyError::MalformedCertificate {
            reason: "AIK Ed25519 key is not 32 bytes",
        })?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(arr).map_err(|_| {
        VerifyError::MalformedCertificate {
            reason: "AIK Ed25519 key is invalid",
        }
    })?;
    let sig_bytes: &[u8; 64] = sig
        .try_into()
        .map_err(|_| VerifyError::MalformedSignature {
            reason: "TPM Ed25519 signature is not 64 bytes",
        })?;
    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
    key.verify_strict(message, &sig)
        .map_err(|_| VerifyError::SignatureInvalid)
}

/// The COSE alg corresponding to a scheme, for error reporting.
fn scheme_alg_hint(scheme: Option<Scheme>) -> i64 {
    match scheme {
        Some(Scheme::Rsa(HashKind::Sha1)) => COSE_RS1,
        Some(Scheme::Rsa(HashKind::Sha256)) => COSE_RS256,
        Some(Scheme::Rsa(HashKind::Sha384)) => COSE_RS384,
        Some(Scheme::Rsa(HashKind::Sha512)) => COSE_RS512,
        Some(Scheme::Ecdsa(HashKind::Sha256)) => COSE_ES256,
        Some(Scheme::Ecdsa(HashKind::Sha384)) => COSE_ES384,
        Some(Scheme::Ecdsa(HashKind::Sha512)) => COSE_ES512,
        // No defined COSE value for ECDSA/SHA-1; report ES256 as the closest.
        Some(Scheme::Ecdsa(HashKind::Sha1)) => COSE_ES256,
        None => COSE_EDDSA,
    }
}
