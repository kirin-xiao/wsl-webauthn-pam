//! `wsl-webauthn-verifier` — the security core (plan §4).
//!
//! This crate is deliberately pure Rust: no OS dependencies, no `unsafe`, and no
//! panic on any input. It takes the raw bytes produced by the Windows bridge
//! (`clientDataJSON`, `authenticatorData`, `attestationObject`, signatures) and the
//! bytes the Linux side minted (challenge, enrolled credential id, enrolled COSE
//! key), and returns either a positive outcome or an exhaustive [`VerifyError`].
//!
//! # Trust model
//!
//! * The RP ID and origin are compile-time constants in `wsl-webauthn-protocol`;
//!   `clientDataJSON` is validated byte-for-byte against them.
//! * The assertion signature is verified over
//!   `authenticatorData || SHA-256(clientDataJSON)`.
//! * Attestation is `tpm` (fully verified, the Windows Hello path) or `packed` (AttCA
//!   with a chain to the pinned Microsoft TPM Root 2014, or self-attestation), or
//!   `none`; self and `none` are admitted only under
//!   [`AttestationPolicy::AllowUnattested`], never as a silent fallback.
//!
//! The Windows Hello `tpm` chain carries only the AIK leaf and its intermediate in
//! `x5c`; the root is completed from a bundled copy of the public Microsoft root,
//! which is trusted **only** after its SHA-256 matches [`MS_TPM_ROOT_2014_SHA256`]
//! (see [`crate::ms_root`] and [`crate::chain`]).
//!
//! # Verified invariants
//!
//! | Area | Check |
//! |---|---|
//! | clientData | `type` exact (`webauthn.get`/`create`); `challenge` compared on **decoded** bytes; `origin` byte-equal to [`wsl_webauthn_protocol::ORIGIN`]; UTF-8 |
//! | authData | `rpIdHash == SHA-256(RP_ID)`; `UP=1`; `UV=1`; attested-credential-data length bounds |
//! | credential id | enrolled (assertion) / reported-vs-attested (enrollment) must match |
//! | COSE key | allow-list `{-7, -257, -8}`; P-256 uncompressed point-on-curve; RSA `n` 2048..=4096; Ed25519 `x` 32 B |
//! | signature | ES256 DER; RS256 PKCS#1 v1.5; EdDSA `verify_strict` (raw 64 B) |
//! | packed/x5c | chain to pinned root; leaf v3 + `CA=false` + `OU="Authenticator Attestation"` + `id-fido-gen-ce-aaguid` == authData AAGUID; `attStmt.alg` == leaf key alg |
//! | tpm | §8.3: `ver=="2.0"`; `certInfo` magic `TPM_GENERATED` / type `TPM_ST_ATTEST_CERTIFY`; `extraData == H_alg(authData‖clientDataHash)`; attested `name == nameAlg‖H_nameAlg(pubArea)`; AIK `sig` over raw `certInfo`; `pubArea` key == credential key |
//! | policy | `tpm`/`packed`+x5c accepted under both policies; self/`none` only under [`AttestationPolicy::AllowUnattested`] |
//! | AAGUID | authData AAGUID must be one of [`STRICT_AAGUIDS`] on every verified path |
//!
//! # `tpm` vs `packed` rule asymmetry
//!
//! The two AttCA profiles deliberately apply **different leaf rules**, because the
//! specs differ:
//!
//! * `packed` (§8.2.1) requires a non-empty Subject with `OU = "Authenticator
//!   Attestation"` and an `id-fido-gen-ce-aaguid` extension equal to the authData
//!   AAGUID.
//! * `tpm` (§8.3.1) requires an **empty** Subject and carries no AAGUID extension;
//!   the AAGUID check is instead against the **authData** AAGUID. If a `tpm` leaf does
//!   carry the extension it must still match. Both profiles require leaf v3,
//!   `CA=false`, and a valid chain to the pinned root.
//!
//! # Empirical Windows Hello facts (baked into the `tpm` path)
//!
//! * Windows Hello emits `fmt: "tpm"` with `alg: -65535` (**COSE RS1** = RSA PKCS#1
//!   v1.5 with SHA-1), so `extraData` is `SHA-1(authData || clientDataHash)`. SHA-1 is
//!   therefore accepted **only** as the AIK signature/`nameAlg` digest, never for a
//!   credential signature or a chain link's integrity beyond what the pinned root
//!   already guarantees.
//! * The attested `name` is computed over the **bare `TPMT_PUBLIC`** (the CBOR
//!   `pubArea` field), i.e. with the outer `TPM2B_PUBLIC` two-byte length removed, per
//!   §8.3's explicit note. SHA-1/256/384/512 are accepted as `nameAlg` (TPM2 defines
//!   all four; Windows Hello uses SHA-256).
//! * The bundled root is trusted only through the [`MS_TPM_ROOT_2014_SHA256`] pin; the
//!   `#[doc(hidden)]` [`verify_attestation_with_anchor`] seam exists solely so the test
//!   suite can substitute a synthetic root and cannot weaken production.
//!
//! # Wave B consumer notes
//!
//! * Use [`verify_attestation`] (never `verify_attestation_with_anchor`) and pass the
//!   [`AttestationPolicy`] chosen from `--allow-unattested`.
//! * Persist [`EnrollOutcome::sign_count`] and [`AssertionOutcome::sign_count`], but do
//!   **not** reject on a non-increasing counter: Windows Hello is a zero/constant-counter
//!   authenticator and the counter is an advisory clone signal, not an authentication
//!   gate (see [`AssertionOutcome`]).
//! * Treat every [`VerifyError`] as a failure; there is no partial success.
//!
//! # Example
//!
//! ```
//! use wsl_webauthn_verifier::{AssertionCheck, verify_assertion};
//! # fn main() -> Result<(), wsl_webauthn_verifier::VerifyError> {
//! let check = AssertionCheck::new(
//!     b"0123456789abcdef", // expected challenge
//!     b"credential-id",
//!     &[],                 // COSE key (empty → rejected on this path)
//!     br#"{"type":"webauthn.get","challenge":"MDEyMzQ1Njc4OWFiY2RlZg","origin":"io.github.kirin-xiao.wsl-webauthn-pam"}"#,
//!     &[],
//!     &[],
//! );
//! assert!(verify_assertion(&check).is_err());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod assertion;
mod attestation;
mod authdata;
mod cbor;
mod chain;
mod clientdata;
mod cose;
mod error;
mod ms_root;
mod tpm;

pub use error::VerifyError;

use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Pinned trust material (plan D3)
// ---------------------------------------------------------------------------

/// SHA-256 fingerprint of the pinned **Microsoft TPM Root Certificate Authority
/// 2014** certificate.
///
/// The verifier trusts this fingerprint, not a certificate: the matching certificate
/// either appears as the topmost element of an attestation `x5c` chain, or is
/// completed from the bundled copy in [`crate::ms_root`] (whose bytes are asserted to
/// hash to this value). Overriding this is only possible through the `#[doc(hidden)]`
/// [`verify_attestation_with_anchor`] test seam.
pub const MS_TPM_ROOT_2014_SHA256: [u8; 32] = [
    0x87, 0x0C, 0x7A, 0x35, 0xCE, 0xAB, 0x3D, 0x59, 0x97, 0x9F, 0x2C, 0x6A, 0x52, 0x40, 0x42, 0xD4,
    0x04, 0xCB, 0x71, 0x51, 0x80, 0x04, 0x35, 0x09, 0x25, 0xFB, 0x2C, 0xED, 0x79, 0xA9, 0x99, 0xDA,
];

/// AAGUIDs accepted under [`AttestationPolicy::Strict`] (plan D3).
///
/// * `08987058-cadc-4b81-b6e1-30de50dcbe96` — Windows Hello software TPM.
/// * `9ddd1817-af5a-4672-a2b9-3e3dd95000a9` — Windows Hello hardware TPM.
pub const STRICT_AAGUIDS: [[u8; 16]; 2] = [
    [
        0x08, 0x98, 0x70, 0x58, 0xCA, 0xDC, 0x4B, 0x81, 0xB6, 0xE1, 0x30, 0xDE, 0x50, 0xDC, 0xBE,
        0x96,
    ],
    [
        0x9D, 0xDD, 0x18, 0x17, 0xAF, 0x5A, 0x46, 0x72, 0xA2, 0xB9, 0x3E, 0x3D, 0xD9, 0x50, 0x00,
        0xA9,
    ],
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// How much attestation trust is required at enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationPolicy {
    /// Require a fully verified TPM (`tpm`) attestation **or** a `packed`/AttCA
    /// attestation whose chain verifies to the pinned root and whose AAGUID is on
    /// [`STRICT_AAGUIDS`]. Self and `none` are rejected. (D3, amended after the spike:
    /// Windows Hello emits `tpm`, so `tpm` is a first-class Strict format.)
    Strict,
    /// Additionally admit self-attestation (`packed` without `x5c`) and `none`
    /// attestation. Used only when the operator explicitly opted in with
    /// `--allow-unattested`.
    AllowUnattested,
}

/// Which attestation mode a successful enrollment used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    /// A `tpm` attestation or a `packed` attestation with `x5c`, verified against the
    /// pinned root.
    StrictVerified,
    /// `packed` without `x5c`, signed by the credential key itself.
    SelfAttested,
    /// `none`.
    None,
}

/// Attestation metadata recorded alongside the credential (plan §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationMetadata {
    /// The attestation statement format (`packed`, `none`, …).
    pub format: String,
    /// The verified mode.
    pub mode: AttestationMode,
    /// SHA-256 of the attestation leaf certificate's DER, when one was used.
    pub leaf_sha256: Option<[u8; 32]>,
}

/// Inputs to an assertion (login) verification.
///
/// Construct with [`AssertionCheck::new`], which sets `now` to
/// [`SystemTime::now`]. Tests may set `now` directly to pin the clock.
#[derive(Debug)]
pub struct AssertionCheck<'a> {
    /// The raw (≥16 byte) challenge we minted and put in `clientDataJSON`.
    pub expected_challenge: &'a [u8],
    /// The enrolled credential id.
    pub credential_id: &'a [u8],
    /// The enrolled COSE public key bytes.
    pub cose_public_key: &'a [u8],
    /// The exact `clientDataJSON` bytes we built and hashed.
    pub client_data_json: &'a [u8],
    /// The authenticator data from the assertion.
    pub authenticator_data: &'a [u8],
    /// The assertion signature.
    pub signature: &'a [u8],
    /// The previously persisted signature counter from the credential store, if any.
    /// `Some(n)` applies the WebAuthn §7.2 step 22 counter policy: a clone signal
    /// (observed `<=` stored) is rejected whenever either count is non-zero;
    /// `None` (or a stored count of 0 on a zero-counter authenticator) skips the
    /// check. Pass the value loaded with the credential record.
    pub expected_sign_count: Option<u32>,
    /// The instant used for any time-based checks. Defaults to `SystemTime::now()`.
    pub now: SystemTime,
}

impl<'a> AssertionCheck<'a> {
    /// Build an assertion check with `now = SystemTime::now()`.
    pub fn new(
        expected_challenge: &'a [u8],
        credential_id: &'a [u8],
        cose_public_key: &'a [u8],
        client_data_json: &'a [u8],
        authenticator_data: &'a [u8],
        signature: &'a [u8],
    ) -> Self {
        Self {
            expected_challenge,
            credential_id,
            cose_public_key,
            client_data_json,
            authenticator_data,
            signature,
            // No stored count by default: the counter check is skipped. The PAM
            // module and CLI set this from the loaded credential record.
            expected_sign_count: None,
            now: SystemTime::now(),
        }
    }

    /// Set the persisted counter for clone detection (WebAuthn §7.2 step 22).
    pub fn with_expected_sign_count(mut self, count: u32) -> Self {
        self.expected_sign_count = Some(count);
        self
    }
}

/// Result of a successful assertion verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertionOutcome {
    /// The authenticator's signature counter as observed. Persist it; the counter is
    /// never used to reject (Windows Hello reports zero).
    pub sign_count: u32,
}

/// Inputs to an enrollment (registration) verification.
///
/// Construct with [`EnrollCheck::new`], which sets `now` to [`SystemTime::now`].
#[derive(Debug)]
pub struct EnrollCheck<'a> {
    /// The raw (≥16 byte) challenge we minted and put in `clientDataJSON`.
    pub expected_challenge: &'a [u8],
    /// The full CBOR `attestationObject` from the bridge.
    pub attestation_object: &'a [u8],
    /// The exact `clientDataJSON` bytes we built and hashed.
    pub client_data_json: &'a [u8],
    /// The bridge's reported credential id; must match the attested credential id.
    pub reported_credential_id: &'a [u8],
    /// The instant used for certificate validity checks. Defaults to
    /// `SystemTime::now()`.
    pub now: SystemTime,
}

impl<'a> EnrollCheck<'a> {
    /// Build an enrollment check with `now = SystemTime::now()`.
    pub fn new(
        expected_challenge: &'a [u8],
        attestation_object: &'a [u8],
        client_data_json: &'a [u8],
        reported_credential_id: &'a [u8],
    ) -> Self {
        Self {
            expected_challenge,
            attestation_object,
            client_data_json,
            reported_credential_id,
            now: SystemTime::now(),
        }
    }
}

/// Result of a successful enrollment verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollOutcome {
    /// The attested credential id.
    pub credential_id: Vec<u8>,
    /// The credential's COSE public key bytes (as found in `authData`).
    pub cose_public_key: Vec<u8>,
    /// The authenticator's AAGUID.
    pub aaguid: [u8; 16],
    /// The signature counter at registration.
    pub sign_count: u32,
    /// Attestation metadata to record.
    pub attestation: AttestationMetadata,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Verify a WebAuthn assertion (login) against an enrolled credential.
///
/// See [`AssertionCheck`] for the inputs and [`crate::assertion`]'s module docs for
/// the exact checks. Never panics.
pub fn verify_assertion(check: &AssertionCheck) -> Result<AssertionOutcome, VerifyError> {
    assertion::verify(
        check.expected_challenge,
        check.credential_id,
        check.cose_public_key,
        check.client_data_json,
        check.authenticator_data,
        check.signature,
        check.expected_sign_count,
    )
}

/// Verify a WebAuthn registration (enrollment) against `policy`.
///
/// Uses [`MS_TPM_ROOT_2014_SHA256`] as the chain trust anchor. Tests substitute a
/// synthetic root via [`verify_attestation_with_anchor`]. Never panics.
pub fn verify_attestation(
    check: &EnrollCheck,
    policy: &AttestationPolicy,
) -> Result<EnrollOutcome, VerifyError> {
    verify_attestation_with_anchor(check, policy, &MS_TPM_ROOT_2014_SHA256)
}

/// Like [`verify_attestation`], but with an explicit trust-anchor fingerprint.
///
/// This is the **test seam** that makes the chain logic exercisable: no test can
/// forge a certificate that hashes to the real Microsoft root, so the synthesized
/// mini-CA tests pass their own root's fingerprint here. Production callers must use
/// [`verify_attestation`]; the anchor fingerprint is otherwise not operator-tunable.
#[doc(hidden)]
pub fn verify_attestation_with_anchor(
    check: &EnrollCheck,
    policy: &AttestationPolicy,
    anchor_fingerprint: &[u8; 32],
) -> Result<EnrollOutcome, VerifyError> {
    attestation::verify(
        check.attestation_object,
        check.client_data_json,
        check.expected_challenge,
        check.reported_credential_id,
        policy,
        check.now,
        anchor_fingerprint,
    )
}

// ---------------------------------------------------------------------------
// Fuzzing / external smoke-test seam
// ---------------------------------------------------------------------------

/// Stable, panic-free parse entry points for the `fuzz/` crate and other external
/// smoke tests (plan §4 test item 4).
///
/// Each returns `true` on success; a `false` return (including malformed input)
/// must never be accompanied by a panic.
#[doc(hidden)]
pub mod testing {
    /// Parse a COSE public key, returning whether it passed allow-listing.
    pub fn parse_cose_key(bytes: &[u8]) -> bool {
        crate::cose::parse(bytes).is_ok()
    }

    /// Parse the fixed `authenticatorData` prefix, returning whether it is
    /// structurally valid.
    pub fn parse_authenticator_data(bytes: &[u8]) -> bool {
        crate::authdata::parse_prefix(bytes).is_ok()
    }

    /// Parse an `attestationObject`, returning whether the CBOR is a map carrying
    /// the required `fmt`/`authData`/`attStmt` members.
    pub fn parse_attestation_object(bytes: &[u8]) -> bool {
        match ciborium::from_reader::<ciborium::value::Value, _>(bytes) {
            Ok(value) => match value.as_map() {
                Some(map) => {
                    let has = |key: &str| map.iter().any(|(k, _)| k.as_text() == Some(key));
                    has("fmt") && has("authData") && has("attStmt")
                }
                None => false,
            },
            Err(_) => false,
        }
    }

    /// Parse a TPM `certInfo` (`TPMS_ATTEST`), returning whether it is structurally
    /// valid. Panic-free (plan §4 test item 4).
    pub fn parse_tpm_cert_info(bytes: &[u8]) -> bool {
        crate::tpm::parse_cert_info_ok(bytes)
    }

    /// Parse a TPM `pubArea` (`TPMT_PUBLIC`), returning whether it is structurally
    /// valid. Panic-free (plan §4 test item 4).
    pub fn parse_tpm_pub_area(bytes: &[u8]) -> bool {
        crate::tpm::parse_pub_area_ok(bytes)
    }
}
