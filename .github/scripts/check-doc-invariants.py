#!/usr/bin/env python3
"""Make the documented security invariants executable (REVIEW.md Theme #1, L13-7).

The verifier trust table (`crates/wsl-webauthn-verifier/src/lib.rs`) and
`SECURITY.md` are treated as a specification, but nothing forced that
specification to match the code.  The L1-1/L1-2/L13-6 class of defect — a
documented invariant ("the AAGUID allow-list runs on every attestation path",
"the tpm AIK carries an EKU") that the code did not actually enforce — survived
because prose is not executable.

This guard keeps a *curated* mapping from each invariant to the negative
(or positive) test that pins it, and fails CI when:

  (a) a mapped test no longer exists (a rename/deletion is caught at once);
  (b) a mapped negative test no longer asserts the documented direction
      (e.g. an invariant "X must be rejected" whose test stopped asserting
      the rejection);
  (c) a documented claim anchor disappears from `SECURITY.md` / the verifier
      trust table while the mapping still references it;
  (d) a `<!-- INVARIANT: ID -->` marker in a machine-checked doc names an id
      with no mapping entry (a new documented invariant with no test); or
  (e) a high-value invariant's marker is removed from the docs.

Invariants that are documented but genuinely have no executable test yet are
listed in `KNOWN_UNCOVERED` and reported distinctly at the end of a run —
visible, but they do not fail unrelated work.  Use this instead of silently
dropping a claim.

How to extend it
----------------
Add an entry to `INVARIANTS` with:

    id          A stable, upper-case, hyphenated name.
    level       "high" or "medium" (informational; high entries must carry at
                least a marker, a static anchor, or a test).
    claims      [(relative path, substring), ...] — the documented claim(s)
                that must still be present, so a prose removal is caught.
    tests       [{"name": ..., "expect": [...], "forbid": [...]}, ...] —
                `expect` substrings must all appear in the named test's body,
                `forbid` (optional) substrings must not.  `expect` encodes the
                documented direction: a "must be rejected" invariant expects an
                `Err(VerifyError::…)` / `PAM_AUTH_ERR` and forbids `PAM_SUCCESS`.
    static      [(path, substring), ...] — non-test code/doc anchors (e.g. a
                `compile_error!` guard) that must exist.
    marker      True if the id must appear as `<!-- INVARIANT: ID -->` in a
                file listed in `MARKER_FILES`.

This is deliberately a hand-maintained table, not NLP: a reworded test name is
a one-line mapping update, and a genuinely new invariant is an explicit
decision.  The mapping is checked by `--self-test` (mirroring
`check-pam-profile.py`).

Usage:
    check-doc-invariants.py              # check the repository (default: repo root)
    check-doc-invariants.py --root DIR   # check a different checkout
    check-doc-invariants.py --self-test  # exercise the checker's own logic

Exit status is 0 only when every documented invariant maps to a test that still
exists and still asserts the documented direction.  No third-party deps.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Machine-checked documents: any `<!-- INVARIANT: ID -->` here must have a
# mapping entry below (or be listed in KNOWN_UNCOVERED).
# ---------------------------------------------------------------------------

MARKER_FILES = (
    "SECURITY.md",
    "crates/wsl-webauthn-verifier/src/lib.rs",
)

# `<!-- INVARIANT: A, B - C -->` (ids separated by commas/whitespace).
MARKER_RE = re.compile(r"<!--\s*INVARIANT:\s*(?P<ids>[A-Za-z0-9_,.\s\-]+?)\s*-->")
ID_SPLIT_RE = re.compile(r"[\s,]+")

# Where Rust test functions live.  Both integration tests (`tests/*.rs`) and
# `#[cfg(test)]` modules inside `src/` are searched.
CRATE_GLOB = "crates/**/*.rs"

# ---------------------------------------------------------------------------
# The curated invariant -> test mapping.
# ---------------------------------------------------------------------------

VERIFIER = "crates/wsl-webauthn-verifier/tests"
AT = f"{VERIFIER}/attestation.rs"
AS = f"{VERIFIER}/assertion.rs"
PROPS = f"{VERIFIER}/properties.rs"
IND = f"{VERIFIER}/independent.rs"
PAM = "crates/wsl-webauthn-pam/tests/pam.rs"
STORE = "crates/wsl-webauthn-store/tests/store.rs"
RUNNER = "crates/wsl-webauthn-runner/tests/runner.rs"
CLI = "crates/wsl-webauthn-cli/src/main.rs"
VERIFIER_LIB = "crates/wsl-webauthn-verifier/src/lib.rs"
COBR = "SECURITY.md"

INVARIANTS = [
    # ------------------------------------------------------------------
    # AAGUID / attestation policy
    # ------------------------------------------------------------------
    {
        "id": "AAGUID-ALLOWLIST-EVERY-ATTESTATION-PATH",
        "level": "high",
        "claims": [
            (COBR, "**every** attestation path"),
            (VERIFIER_LIB, "on every verified **attestation** path"),
        ],
        "tests": [
            {"name": "negative_aaguid_not_in_allowlist", "expect": ["Err(VerifyError::AaguidNotAllowed)"]},
            {"name": "negative_self_attestation_aaguid_not_in_allowlist", "expect": ["Err(VerifyError::AaguidNotAllowed)"]},
            {"name": "negative_none_aaguid_not_in_allowlist", "expect": ["Err(VerifyError::AaguidNotAllowed)"]},
        ],
        "marker": True,
    },
    {
        "id": "ATTESTATION-ALLOW-UNATTESTED-OPT-IN",
        "level": "high",
        "claims": [
            (COBR, "admitted **only** under explicit"),
            (VERIFIER_LIB, "only under [`AttestationPolicy::AllowUnattested`]"),
        ],
        "tests": [
            {"name": "negative_self_attestation_under_strict", "expect": ["AttestationNotAllowed"]},
            {"name": "negative_none_under_strict", "expect": ["AttestationNotAllowed"]},
            {"name": "positive_self_attestation_under_allow_unattested", "expect": ["AttestationMode::SelfAttested"]},
            {"name": "positive_none_under_allow_unattested", "expect": ["AttestationMode::None"]},
        ],
        "marker": True,
    },
    # ------------------------------------------------------------------
    # TPM attestation
    # ------------------------------------------------------------------
    {
        "id": "TPM-AIK-EKU-REQUIRED",
        "level": "high",
        "claims": [
            (COBR, "TCG AIK Extended Key Usage"),
            (VERIFIER_LIB, "TCG AIK EKU (`2.23.133.8.3`)"),
        ],
        "tests": [
            {"name": "negative_tpm_aik_eku_missing", "expect": ["Err(VerifyError::TpmAikEkuMissing)"]},
            {"name": "negative_tpm_aik_subject_not_empty", "expect": ["Err(VerifyError::TpmAikSubjectNotEmpty)"]},
        ],
        "marker": True,
    },
    {
        "id": "TPM-AIK-KEYUSAGE-DIGITALSIGNATURE",
        "level": "high",
        "claims": [
            (COBR, "KeyUsage, when"),
            (VERIFIER_LIB, "KeyUsage permitting `digitalSignature`"),
        ],
        "tests": [
            {"name": "negative_tpm_aik_key_usage_forbids_signature", "expect": ["Err(VerifyError::TpmAikKeyUsageForbidsSignature)"]},
            {"name": "positive_tpm_aik_no_key_usage_extension", "expect": [".expect("]},
        ],
        "marker": True,
    },
    {
        "id": "TPM-CERTINFO-BINDING",
        "level": "high",
        "claims": [
            (VERIFIER_LIB, "`extraData == H_verified(authData‖clientDataHash)`"),
        ],
        "tests": [
            {"name": "negative_tpm_bad_version", "expect": ["TpmVersionUnsupported"]},
            {"name": "negative_tpm_magic", "expect": ["TpmCertInfoMagic"]},
            {"name": "negative_tpm_type", "expect": ["TpmCertInfoType"]},
            {"name": "negative_tpm_wrong_extra_data", "expect": ["TpmCertInfoExtraDataMismatch"]},
            {"name": "negative_tpm_wrong_name", "expect": ["TpmCertInfoNameMismatch"]},
            {"name": "negative_tpm_pub_area_key_mismatch", "expect": ["TpmPubAreaKeyMismatch"]},
            {"name": "negative_tpm_tampered_cert_info_signature", "expect": ["SignatureInvalid"]},
        ],
        "marker": True,
    },
    {
        "id": "TPM-PUBAREA-KEYBITS",
        "level": "high",
        "claims": [
            (VERIFIER_LIB, "declared `keyBits`"),
        ],
        "tests": [
            {"name": "negative_tpm_pub_area_key_bits_mismatch", "expect": ["TpmPubAreaKeyBitsMismatch"]},
        ],
        "marker": True,
    },
    # ------------------------------------------------------------------
    # X.509 chain
    # ------------------------------------------------------------------
    {
        "id": "CHAIN-PINNED-ROOT",
        "level": "high",
        "claims": [
            (VERIFIER_LIB, "chain to pinned root"),
            (VERIFIER_LIB, "MS_TPM_ROOT_2014_SHA256"),
        ],
        "tests": [
            {"name": "negative_missing_anchor", "expect": ["Err(VerifyError::CertificateChainAnchorNotFound)"]},
            {"name": "negative_real_policy_rejects_synthetic_root", "expect": ["CertificateChainAnchorNotFound"]},
            {"name": "bundled_root_matches_pinned_fingerprint", "expect": ["MS_TPM_ROOT_2014_SHA256"]},
        ],
        "marker": True,
    },
    {
        "id": "CHAIN-LEAF-V3-AND-CA-FALSE",
        "level": "high",
        "claims": [(VERIFIER_LIB, "leaf v3 + `CA=false`")],
        "tests": [
            {"name": "negative_leaf_not_v3", "expect": ["Err(VerifyError::CertificateVersionNotV3)"]},
            {"name": "negative_leaf_is_ca", "expect": ["Err(VerifyError::CertificateLeafIsCa)"]},
            {"name": "negative_intermediate_not_ca", "expect": ["Err(VerifyError::CertificateIntermediateNotCa)"]},
        ],
        "marker": True,
    },
    {
        "id": "CHAIN-PACKED-OU",
        "level": "high",
        "claims": [(VERIFIER_LIB, 'OU="Authenticator Attestation"')],
        "tests": [
            {"name": "negative_wrong_ou", "expect": ["Err(VerifyError::CertificateSubjectOuMismatch)"]},
        ],
        "marker": True,
    },
    {
        "id": "CHAIN-AAGUID-EXT-MATCH",
        "level": "high",
        "claims": [(VERIFIER_LIB, "id-fido-gen-ce-aaguid` == authData AAGUID")],
        "tests": [
            {"name": "negative_missing_aaguid_extension", "expect": ["Err(VerifyError::CertificateAaguidExtensionMissing)"]},
            {"name": "negative_cert_aaguid_mismatch", "expect": ["Err(VerifyError::CertificateAaguidMismatch)"]},
            {"name": "negative_malformed_aaguid_extension", "expect": ["Err(VerifyError::CertificateAaguidMalformed)"]},
        ],
        "marker": True,
    },
    {
        "id": "CHAIN-ATTSTMT-ALG-MATCH",
        "level": "high",
        "claims": [(VERIFIER_LIB, "`attStmt.alg` == leaf key alg")],
        "tests": [
            {"name": "negative_attstmt_alg_mismatch_x5c", "expect": ["Err(VerifyError::AlgorithmMismatch)"]},
        ],
        "marker": True,
    },
    {
        "id": "CHAIN-ISSUER-SUBJECT-LINK",
        "level": "medium",
        "claims": [(VERIFIER_LIB, "chain")],
        "tests": [
            {"name": "negative_issuer_subject_mismatch", "expect": ["Err(VerifyError::CertificateChainIssuerMismatch)"]},
        ],
        "marker": False,
    },
    {
        "id": "CHAIN-PATHLEN",
        "level": "high",
        "claims": [(VERIFIER_LIB, "chain to pinned root")],
        "tests": [
            {"name": "negative_path_len_exceeded", "expect": ["Err(VerifyError::CertificatePathLenExceeded)"]},
            {"name": "positive_path_len_within_limit", "expect": [".expect("]},
        ],
        "marker": False,
    },
    {
        "id": "CHAIN-VALIDITY-WINDOW",
        "level": "medium",
        "claims": [(VERIFIER_LIB, "packed/x5c")],
        "tests": [
            {"name": "negative_expired_leaf", "expect": ["Err(VerifyError::CertificateExpired)"]},
            {"name": "negative_not_yet_valid_leaf", "expect": ["Err(VerifyError::CertificateNotYetValid)"]},
            {"name": "negative_expired_intermediate", "expect": ["Err(VerifyError::CertificateExpired)"]},
            {"name": "negative_expired_root", "expect": ["Err(VerifyError::CertificateExpired)"]},
        ],
        "marker": False,
    },
    # ------------------------------------------------------------------
    # COSE keys
    # ------------------------------------------------------------------
    {
        "id": "COSE-ALG-ALLOWLIST",
        "level": "high",
        "claims": [(VERIFIER_LIB, "allow-list `{-7, -257, -8}`")],
        "tests": [
            {"name": "negative_credential_key_disallowed_alg", "expect": ["Err(VerifyError::UnsupportedAlgorithm"]},
            {"name": "negative_credential_key_unknown_alg", "expect": ["Err(VerifyError::UnsupportedAlgorithm"]},
        ],
        "marker": True,
    },
    {
        "id": "COSE-P256-UNCOMPRESSED-ON-CURVE",
        "level": "high",
        "claims": [(VERIFIER_LIB, "P-256 uncompressed point-on-curve")],
        "tests": [
            {"name": "negative_credential_key_compressed_point", "expect": ["Err(VerifyError::CosePointNotOnCurve)"]},
            {"name": "rejects_compressed_point", "expect": ["VerifyError::CosePointNotOnCurve"]},
        ],
        "marker": True,
    },
    {
        "id": "COSE-RSA-MODULUS-SIZE",
        "level": "high",
        "claims": [(VERIFIER_LIB, "RSA `n` 2048..=4096")],
        "tests": [
            {"name": "negative_credential_key_rsa_modulus_too_small", "expect": ["VerifyError::CoseKeyModulusSize"]},
        ],
        "marker": True,
    },
    {
        "id": "COSE-RSA-EXPONENT",
        "level": "high",
        "claims": [(VERIFIER_LIB, "`e` ∈ {3, 65537}")],
        "tests": [
            {"name": "rsa_exponent_allow_list", "expect": ["VerifyError::CoseKeyExponentNotAllowed"]},
            {"name": "rsa_exponent_non_minimal_encoding_rejected", "expect": ["Err(VerifyError::MalformedCoseKey"]},
        ],
        "marker": True,
    },
    {
        "id": "COSE-ED25519-X-LENGTH",
        "level": "medium",
        "claims": [(VERIFIER_LIB, "Ed25519 `x` 32 B")],
        "tests": [
            {"name": "negative_credential_key_bad_x_length", "expect": ["Err(VerifyError::MalformedCoseKey"]},
        ],
        "marker": False,
    },
    {
        "id": "COSE-KTY-ALG-CONSISTENCY",
        "level": "medium",
        "claims": [(VERIFIER_LIB, "allow-list `{-7, -257, -8}`")],
        "tests": [
            {"name": "negative_credential_key_kty_alg_mismatch", "expect": ["Err(VerifyError::KeyTypeAlgorithmMismatch"]},
            {"name": "negative_credential_key_unknown_kty_known_alg", "expect": ["Err(VerifyError::UnsupportedKeyType"]},
        ],
        "marker": False,
    },
    # ------------------------------------------------------------------
    # CBOR canonicality / duplicates / trailing
    # ------------------------------------------------------------------
    {
        "id": "CBOR-EXACT-NO-TRAILING",
        "level": "high",
        "claims": [(VERIFIER_LIB, "attested-credential-data length bounds")],
        "tests": [
            {"name": "negative_attestation_object_trailing_bytes", "expect": ["MalformedAttestationObject"]},
            {"name": "cose_trailing_byte_rejected", "expect": ["!testing::parse_cose_key"]},
        ],
        "marker": True,
    },
    {
        "id": "CBOR-NO-DUPLICATE-KEYS",
        "level": "high",
        "claims": [(VERIFIER_LIB, "attestation_object")],
        "tests": [
            {"name": "negative_duplicate_fmt_rejected", "expect": ["MalformedAttestationObject"]},
            {"name": "negative_duplicate_auth_data_rejected", "expect": ["MalformedAttestationObject"]},
        ],
        "marker": True,
    },
    {
        "id": "AUTHDATA-CANONICAL-COSE-FIRST",
        "level": "high",
        "claims": [(VERIFIER_LIB, "attested-credential-data length bounds")],
        "tests": [
            {"name": "rejects_non_canonical_key", "expect": ["Err(VerifyError::MalformedCoseKey"]},
        ],
        "marker": True,
    },
    {
        "id": "AUTHDATA-ED-GATES-TRAILING",
        "level": "high",
        "claims": [(VERIFIER_LIB, "attested-credential-data length bounds")],
        "tests": [
            {"name": "rejects_trailing_bytes_without_ed", "expect": ["MalformedAuthenticatorData"]},
            {"name": "accepts_trailing_extensions_with_ed", "expect": ["parse_attested_credential_data", "cose_public_key"]},
        ],
        "marker": True,
    },
    # ------------------------------------------------------------------
    # Assertion path
    # ------------------------------------------------------------------
    {
        "id": "ASSERTION-SIGNED-MESSAGE-DEFINITION",
        "level": "high",
        "claims": [
            (COBR, "authenticatorData ‖ SHA-256(clientDataJSON)"),
            (VERIFIER_LIB, "`authenticatorData || SHA-256(clientDataJSON)`"),
        ],
        "tests": [
            {"name": "independent_golden_digests", "expect": ["SHA256_SIGNED_MESSAGE_HEX"]},
            {"name": "negative_signature_over_wrong_message", "expect": ["SignatureInvalid"]},
        ],
        "marker": True,
    },
    {
        "id": "ASSERTION-CLIENTDATA-TYPE-EXACT",
        "level": "high",
        "claims": [(VERIFIER_LIB, "`type` exact")],
        "tests": [{"name": "negative_wrong_type", "expect": ["Err(VerifyError::ClientDataTypeMismatch)"]}],
        "marker": True,
    },
    {
        "id": "ASSERTION-CLIENTDATA-CHALLENGE-DECODED",
        "level": "high",
        "claims": [(VERIFIER_LIB, "`challenge` compared on **decoded** bytes")],
        "tests": [{"name": "negative_wrong_challenge", "expect": ["Err(VerifyError::ChallengeMismatch)"]}],
        "marker": True,
    },
    {
        "id": "ASSERTION-CLIENTDATA-ORIGIN-PINNED",
        "level": "high",
        "claims": [(VERIFIER_LIB, "`origin` byte-equal to")],
        "tests": [{"name": "negative_wrong_origin", "expect": ["Err(VerifyError::OriginMismatch)"]}],
        "marker": True,
    },
    {
        "id": "ASSERTION-RPIDHASH",
        "level": "high",
        "claims": [(VERIFIER_LIB, "`rpIdHash == SHA-256(RP_ID)`")],
        "tests": [{"name": "negative_bad_rpid_hash", "expect": ["Err(VerifyError::RpIdHashMismatch)"]}],
        "marker": True,
    },
    {
        "id": "ASSERTION-UP-UV",
        "level": "high",
        "claims": [(VERIFIER_LIB, "`UP=1`; `UV=1`")],
        "tests": [
            {"name": "negative_user_presence_zero", "expect": ["Err(VerifyError::UserPresenceRequired)"]},
            {"name": "negative_user_verification_zero", "expect": ["Err(VerifyError::UserVerificationRequired)"]},
        ],
        "marker": True,
    },
    {
        "id": "ASSERTION-CREDENTIAL-ID-BINDING",
        "level": "high",
        "claims": [(VERIFIER_LIB, "must match")],
        "tests": [
            {"name": "negative_empty_credential_id", "expect": ["Err(VerifyError::EmptyCredentialId)"]},
            {"name": "negative_embedded_credential_id_mismatch", "expect": ["Err(VerifyError::CredentialIdMismatch)"]},
        ],
        "marker": True,
    },
    {
        "id": "ASSERTION-COUNTER-POLICY",
        "level": "medium",
        "claims": [(COBR, "Signature-counter clone signal")],
        "tests": [
            {"name": "counter_regression_is_rejected", "expect": ["CounterRegression"]},
            {"name": "observed_zero_with_persisted_nonzero_is_rejected", "expect": ["CounterRegression"]},
            {"name": "counter_policy_monotone", "expect": ["CounterRegression"]},
        ],
        "marker": False,
    },
    # ------------------------------------------------------------------
    # PAM fail-closed mapping
    # ------------------------------------------------------------------
    {
        "id": "PAM-ONE-SUCCESS-PATH",
        "level": "high",
        "claims": [
            (COBR, "There is exactly one path to `PAM_SUCCESS`"),
            ("crates/wsl-webauthn-pam/src/lib.rs", "every row is covered by a test"),
        ],
        "tests": [
            {"name": "success_is_authenticated_under_pam_silent", "expect": ["PAM_SUCCESS"]},
            {"name": "tampered_signature_is_auth_err", "expect": ["PAM_AUTH_ERR"], "forbid": ["PAM_SUCCESS"]},
            {"name": "wrong_challenge_is_auth_err", "expect": ["PAM_AUTH_ERR"], "forbid": ["PAM_SUCCESS"]},
            {"name": "timeout_is_authinfo_unavail", "expect": ["PAM_AUTHINFO_UNAVAIL"], "forbid": ["PAM_SUCCESS"]},
            {"name": "config_missing_is_authinfo_unavail", "expect": ["PAM_AUTHINFO_UNAVAIL"], "forbid": ["PAM_SUCCESS"]},
            {"name": "bridge_missing_is_authinfo_unavail", "expect": ["PAM_AUTHINFO_UNAVAIL"], "forbid": ["PAM_SUCCESS"]},
        ],
        "marker": True,
    },
    {
        "id": "PAM-BRIDGE-PIN-FAIL-CLOSED",
        "level": "high",
        "claims": [
            (COBR, "there is no module argument that disables it"),
            ("crates/wsl-webauthn-pam/src/lib.rs", "no `noverifypin` argument"),
        ],
        "tests": [
            {"name": "pin_mismatch_is_authinfo_unavail", "expect": ["PAM_AUTHINFO_UNAVAIL"]},
            {"name": "noverifypin_token_no_longer_bypasses_a_pin_mismatch", "expect": ["PAM_AUTHINFO_UNAVAIL"]},
            {"name": "untrusted_bridge_path_is_authinfo_unavail", "expect": ["PAM_AUTHINFO_UNAVAIL"]},
            {"name": "production_trust_check_accepts_regular_file_and_rejects_symlink",
             "expect": ["bridge_path_is_trusted(&real, dir.path()).is_ok()", ".is_err()"]},
        ],
        "marker": True,
    },
    {
        "id": "PAM-PANIC-ABORT",
        "level": "high",
        "claims": [
            (COBR, "Panic in module code"),
            ("crates/wsl-webauthn-pam/src/lib.rs", "PAM_ABORT"),
        ],
        "tests": [
            {"name": "injected_panic_returns_pam_abort", "expect": ["PAM_ABORT"]},
        ],
        "marker": True,
    },
    {
        "id": "PAM-FAIL-DELAY",
        "level": "medium",
        "claims": [(COBR, "pam_fail_delay(pamh, 2_000_000)")],
        "tests": [
            {"name": "failure_requests_two_second_fail_delay", "expect": ["FAIL_DELAY_USEC"]},
        ],
        "marker": False,
    },
    {
        "id": "PAM-NON-AUTH-EXPORTS",
        "level": "medium",
        "claims": [(COBR, "Any other non-authentication `pam_sm_*`"), ("crates/wsl-webauthn-pam/src/lib.rs", "`PAM_IGNORE`")],
        "tests": [
            {"name": "non_auth_exports_return_expected_codes", "expect": ["PAM_IGNORE"]},
        ],
        "marker": False,
    },
    # ------------------------------------------------------------------
    # Store
    # ------------------------------------------------------------------
    {
        "id": "STORE-ROOT-ONLY-OWNERSHIP-MODE",
        "level": "high",
        "claims": [(COBR, "all root-owned")],
        "tests": [
            {"name": "load_rejects_wrong_base_owner", "expect": ["InsecureBase"]},
            {"name": "load_rejects_bad_credentials_dir_mode", "expect": ["BadOwnership"]},
            {"name": "load_rejects_bad_record_mode", "expect": ["BadOwnership"]},
        ],
        "marker": True,
    },
    {
        "id": "STORE-SYMLINK-HARDENED",
        "level": "high",
        "claims": [(COBR, "Every path component is `lstat`ed; a symlink is refused")],
        "tests": [
            {"name": "load_refuses_symlinked_record", "expect": ["SymlinkedPath"]},
            {"name": "load_refuses_symlinked_credentials_dir", "expect": ["SymlinkedPath"]},
            {"name": "save_refuses_symlinked_base", "expect": ["SymlinkedPath"]},
        ],
        "marker": True,
    },
    {
        "id": "STORE-ATOMIC-NO-TEMP-LEFTOVER",
        "level": "medium",
        "claims": [(COBR, "Failure paths remove")],
        "tests": [
            {"name": "no_temp_files_after_successful_saves", "expect": ["no_temp_files"]},
        ],
        "marker": False,
    },
    {
        "id": "STORE-BOUNDED-READS",
        "level": "medium",
        "claims": [(COBR, "capped at 256 KiB")],
        "tests": [
            {"name": "load_oversized_record_is_too_large", "expect": ["TooLarge"]},
            {"name": "config_oversized_is_too_large", "expect": ["TooLarge"]},
        ],
        "marker": False,
    },
    {
        "id": "STORE-MODE-VALIDATED-ON-LOAD",
        "level": "medium",
        "claims": [(COBR, "credential record")],
        "tests": [
            {"name": "load_rejects_unknown_attestation_mode_as_corrupt", "expect": ["Corrupt"]},
        ],
        "marker": False,
    },
    # ------------------------------------------------------------------
    # Runner
    # ------------------------------------------------------------------
    {
        "id": "RUNNER-NO-SHELL",
        "level": "high",
        "claims": [(COBR, "there is no shell and no on-disk challenge")],
        "tests": [],
        "marker": True,
    },
    {
        "id": "RUNNER-BOUNDED-READ",
        "level": "high",
        "claims": [(COBR, "all fail closed")],
        "tests": [
            {"name": "oversized_response_is_transport", "expect": ["Transport"]},
            {"name": "oversized_declared_is_transport", "expect": ["Transport"]},
            {"name": "truncated_frame_is_transport", "expect": ["Transport"]},
        ],
        "marker": True,
    },
    {
        "id": "RUNNER-EXACTLY-ONE-FRAME",
        "level": "medium",
        "claims": [(COBR, "bounded read loop")],
        "tests": [
            {"name": "trailing_bytes_after_frame_are_transport", "expect": ["Transport"]},
        ],
        "marker": False,
    },
    {
        "id": "RUNNER-TIMEOUT-REAP",
        "level": "medium",
        "claims": [(COBR, "bounded read loop")],
        "tests": [
            {"name": "timeout_fires_and_child_is_reaped", "expect": ["Timeout"]},
        ],
        "marker": False,
    },
    {
        "id": "RUNNER-SIGPIPE-SAFE",
        "level": "high",
        "claims": [(COBR, "bounded read loop")],
        "tests": [
            {"name": "closed_stdin_write_cannot_sigpipe_kill_host", "expect": ["status.success"]},
        ],
        "marker": False,
    },
    # ------------------------------------------------------------------
    # CLI enrollment
    # ------------------------------------------------------------------
    {
        "id": "ENROLL-VERIFY-BEFORE-PERSIST",
        "level": "high",
        "claims": [(COBR, "only writes a record after")],
        "tests": [
            {"name": "enroll_fails_closed_on_an_unreadable_store", "expect": ["ceremony.calls.get()", "0"]},
        ],
        "marker": True,
    },
    {
        "id": "ENROLL-DOUBLE-ENROLL-DISCARDS-FIRST",
        "level": "high",
        "claims": [(COBR, "the CLI discards that outcome and re-runs exactly")],
        "tests": [
            {"name": "double_enroll_discards_the_first_ceremony_outcome",
             "expect": ["ceremony #2's, never ceremony #1's"]},
        ],
        "marker": True,
    },
    {
        "id": "ENROLL-REPLACE-ORPHAN-GUARD",
        "level": "medium",
        "claims": [(COBR, "never persists anything")],
        "tests": [
            {"name": "enroll_without_replace_runs_zero_ceremonies", "expect": ["ceremony.calls.get()", "0"]},
        ],
        "marker": False,
    },
    {
        "id": "ENROLL-STORAGE-ERROR-FAILS-CLOSED",
        "level": "high",
        "claims": [(COBR, "never persists anything")],
        "tests": [
            {"name": "enroll_fails_closed_on_an_unreadable_store", "expect": ["ceremony.calls.get()", "0"]},
        ],
        "marker": False,
    },
    # ------------------------------------------------------------------
    # Build-level invariants (non-test static anchors)
    # ------------------------------------------------------------------
    {
        "id": "PAM-BUILD-PANIC-UNWIND",
        "level": "high",
        "claims": [(COBR, "Build requirement — unwinding panics")],
        "static": [
            ("crates/wsl-webauthn-pam/src/lib.rs", '#[cfg(not(panic = "unwind"))]'),
            ("crates/wsl-webauthn-bridge/src/main.rs", '#[cfg(not(panic = "unwind"))]'),
        ],
        "tests": [],
        "marker": True,
    },
    {
        "id": "MSRV-1.88",
        "level": "high",
        "claims": [("Cargo.toml", 'rust-version = "1.88"')],
        "static": [
            ("Cargo.toml", 'rust-version = "1.88"'),
            (".github/workflows/ci.yaml", "cargo check --workspace --all-targets --locked"),
        ],
        "tests": [],
        "marker": False,
    },
]

# Documented invariants with no executable test yet.  Reported distinctly on
# every run so the gap stays visible, without failing unrelated work.
KNOWN_UNCOVERED = {
    "RUNNER-NO-SHELL": (
        "The runner/doc invariant \"spawned with an argument array, no shell\" is "
        "structural (Command::new + .arg) and has no test that would fail if a "
        "future edit introduced a shell. Add a spawn-argv capture test."
    ),
}


def rel(root: Path, *parts: str) -> Path:
    return root.joinpath(*parts)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Marker / claim / test extraction
# ---------------------------------------------------------------------------


def extract_markers(text: str) -> dict[str, list[int]]:
    """Return {invariant_id: [line numbers]} for every `<!-- INVARIANT: ... -->`."""
    out: dict[str, list[int]] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in MARKER_RE.finditer(line):
            for ident in ID_SPLIT_RE.split(m.group("ids").strip()):
                if ident:
                    out.setdefault(ident, []).append(lineno)
    return out


def iter_rust_files(root: Path):
    crates = rel(root, "crates")
    if crates.is_dir():
        yield from sorted(crates.rglob("*.rs"))


def find_test_body(root: Path, name: str) -> tuple[Path | None, str]:
    """Locate `fn <name>(...) { ... }`, returning (path, body) or (None, "").

    The body is brace-matched with a tiny scanner that skips `//`/`/* */`
    comments and string literals, so a `}` inside a message cannot truncate it.
    """
    pattern = re.compile(r"\bfn\s+" + re.escape(name) + r"\s*\(")
    for path in iter_rust_files(root):
        text = read_text(path)
        m = pattern.search(text)
        if not m:
            continue
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        depth = 0
        i = brace
        n = len(text)
        while i < n:
            c = text[i]
            if c == "/" and i + 1 < n and text[i + 1] == "/":
                nl = text.find("\n", i)
                i = n if nl < 0 else nl
            elif c == "/" and i + 1 < n and text[i + 1] == "*":
                close = text.find("*/", i + 2)
                i = n if close < 0 else close + 2
            elif c == '"':
                i += 1
                while i < n and text[i] != '"':
                    if text[i] == "\\":
                        i += 1
                    i += 1
                i += 1
            elif c == "{":
                depth += 1
                i += 1
            elif c == "}":
                depth -= 1
                i += 1
                if depth == 0:
                    break
            else:
                i += 1
        return path, text[m.start():i]
    return None, ""


def body_problems(body: str, expect, forbid) -> list[str]:
    problems = []
    for needle in expect or []:
        if needle not in body:
            problems.append(f"missing required assertion text {needle!r}")
    for needle in forbid or []:
        if needle in body:
            problems.append(f"contains forbidden text {needle!r}")
    return problems


# ---------------------------------------------------------------------------
# Core validation
# ---------------------------------------------------------------------------


def check_invariants(root: Path, invariants, known_uncovered, marker_files) -> tuple[list[str], list[str]]:
    """Return (errors, uncovered_notes)."""
    errors: list[str] = []

    # (1) structural self-checks on the mapping table itself.
    seen_ids: set[str] = set()
    for inv in invariants:
        if inv["id"] in seen_ids:
            errors.append(f"mapping: duplicate invariant id {inv['id']!r}")
        seen_ids.add(inv["id"])

    # (2) collect documented markers.
    doc_markers: dict[str, list[tuple[str, int]]] = {}
    for relpath in marker_files:
        path = rel(root, relpath)
        if not path.is_file():
            errors.append(f"machine-checked document missing: {relpath}")
            continue
        for ident, lines in extract_markers(read_text(path)).items():
            for line in lines:
                doc_markers.setdefault(ident, []).append((relpath, line))

    mapping = {inv["id"]: inv for inv in invariants}

    # (3) unknown markers: a documented invariant with no mapping entry.
    for ident, where in sorted(doc_markers.items()):
        if ident not in mapping and ident not in known_uncovered:
            locs = ", ".join(f"{p}:{ln}" for p, ln in where)
            errors.append(
                f"documented invariant {ident!r} ({locs}) has no mapping entry: "
                f"add it to INVARIANTS (with a test) or to KNOWN_UNCOVERED"
            )

    # (4) per-invariant checks.
    for inv in invariants:
        ident = inv["id"]
        level = inv.get("level", "medium")
        if inv.get("marker") and ident not in doc_markers and ident not in known_uncovered:
            errors.append(
                f"{ident}: expected a `<!-- INVARIANT: {ident} -->` marker in "
                + " or ".join(marker_files)
            )

        for relpath, needle in inv.get("claims", []):
            path = rel(root, relpath)
            if not path.is_file():
                errors.append(f"{ident}: claim file missing: {relpath}")
                continue
            if needle not in read_text(path):
                errors.append(f"{ident}: documented claim not found in {relpath}: {needle!r}")

        for relpath, needle in inv.get("static", []):
            path = rel(root, relpath)
            if not path.is_file():
                errors.append(f"{ident}: static anchor file missing: {relpath}")
                continue
            if needle not in read_text(path):
                errors.append(f"{ident}: static anchor not found in {relpath}: {needle!r}")

        tests = inv.get("tests", [])
        has_static = bool(inv.get("static"))
        if level == "high" and not tests and not has_static and ident not in known_uncovered:
            errors.append(f"{ident}: high-value invariant has no test and no static anchor")

        for test in tests:
            name = test["name"]
            path, body = find_test_body(root, name)
            if path is None:
                errors.append(f"{ident}: test {name!r} not found in the tree")
                continue
            for problem in body_problems(body, test.get("expect"), test.get("forbid")):
                errors.append(f"{ident}: test {name} ({path}): {problem}")

    uncovered_notes = []
    for ident, why in sorted(known_uncovered.items()):
        inv = mapping.get(ident)
        if inv is None:
            uncovered_notes.append(f"{ident}: in KNOWN_UNCOVERED but absent from INVARIANTS")
            continue
        marked = ident in doc_markers
        uncovered_notes.append(f"{ident}{'' if marked else ' (unmarked)'}: {why}")

    return errors, uncovered_notes


# ---------------------------------------------------------------------------
# --self-test: exercise the checker's own logic on synthetic inputs.
# ---------------------------------------------------------------------------


def self_test() -> int:
    failures: list[str] = []

    def expect(cond: bool, what: str) -> None:
        if not cond:
            failures.append(what)

    # Marker extraction, including a multi-id marker and a non-marker comment.
    text = (
        "<!-- INVARIANT: A, B-C -->\n"
        "<!-- not an invariant -->\n"
        "some prose <!-- INVARIANT: D -->\n"
    )
    markers = extract_markers(text)
    expect(set(markers) == {"A", "B-C", "D"}, f"marker extraction: {markers}")

    # Test-body extraction with a string containing a brace and a `//` comment.
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / "crates" / "demo" / "src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text(
            "fn helper() {}\n"
            "#[test]\n"
            "fn keeps_braces() {\n"
            '    let s = "} not the end";\n'
            "    // } also not the end\n"
            "    assert_eq!(1, 1);\n"
            "}\n"
        )
        path, body = find_test_body(root, "keeps_braces")
        expect(path is not None, "find_test_body found the function")
        expect("assert_eq!(1, 1);" in body, "body not truncated at a string brace")
        expect(find_test_body(root, "nope")[0] is None, "missing test reported as missing")

        # Direction enforcement: a negative invariant expecting a rejection in a
        # positive body must fail.
        expect(
            body_problems("assert!(verify(&x).is_ok());", ["is_err()"], None) == ["missing required assertion text 'is_err()'"],
            "expect-mismatch detected",
        )
        expect(
            body_problems("assert!(verify(&x).is_err());", ["is_err()"], ["is_ok()"]) == [],
            "expect-match accepted",
        )
        expect(
            body_problems("assert!(x.is_ok()); // is_err()", [], ["is_err()"]) != [],
            "forbid-mismatch detected",
        )

        # Unknown marker detection against a tiny mapping.
        (root / "SECURITY.md").write_text("<!-- INVARIANT: KNOWN -->\n<!-- INVARIANT: GHOST -->\n")
        mapping = [
            {
                "id": "KNOWN", "level": "high", "claims": [], "tests": [],
                "static": [("Cargo.toml", "x")], "marker": True,
            }
        ]
        (root / "Cargo.toml").write_text("x = 1\n")
        errors, _ = check_invariants(root, mapping, {}, ("SECURITY.md",))
        expect(any("GHOST" in e for e in errors), "unknown marker detected")
        expect(not any("invariant 'KNOWN'" in e for e in errors), "known marker accepted")

        # Missing mapped test is an error.
        mapping2 = [
            {
                "id": "T", "level": "high", "claims": [], "tests": [{"name": "does_not_exist", "expect": ["x"]}],
                "marker": False,
            }
        ]
        errors2, _ = check_invariants(root, mapping2, {}, ("SECURITY.md",))
        expect(any("does_not_exist" in e for e in errors2), "missing test detected")

    if failures:
        for f in failures:
            print(f"[UNEXPECTED] {f}")
        print(f"\nself-test FAILED ({len(failures)} case(s))")
        return 1
    print("self-test passed (marker extraction, body matching, direction, unknowns)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--root", default=".", help="repository root (default: cwd)")
    ap.add_argument("--self-test", action="store_true", help="exercise the checker logic and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    root = Path(args.root).resolve()
    if not (root / "Cargo.toml").is_file():
        print(f"error: {root} does not look like the repository root", file=sys.stderr)
        return 2

    errors, uncovered = check_invariants(root, INVARIANTS, KNOWN_UNCOVERED, MARKER_FILES)

    if uncovered:
        print("Known-uncovered invariants (documented, no executable test yet):")
        for note in uncovered:
            print(f"  - {note}")
        print()

    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        print(
            f"\nFAILED: {len(errors)} documented-invariant problem(s); "
            f"{len(INVARIANTS)} invariants checked",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {len(INVARIANTS)} documented invariants each map to a test that exists "
        f"and asserts the documented direction "
        f"({len(KNOWN_UNCOVERED)} known-uncovered reported)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
