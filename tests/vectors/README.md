# Verifier test vectors

This directory documents the provenance of any externally-sourced test material
used by `wsl-webauthn-verifier`, and records why no third-party binary vectors are
committed here.

## What is committed

* `crates/wsl-webauthn-verifier/tests/independent.rs` — a **committed, sanitized
  independent vector**. Every byte (ECDSA P-256 chain, `packed` attestation
  object, credential COSE key, `clientDataJSON`, and both signatures) was produced
  **off-line, outside Rust**, with `python3` + the `cryptography` package and a
  hand-rolled minimal CBOR encoder. The test calls neither `tests/common`'s
  builders nor `build_client_data`, so it is a second implementation of the
  signed-message/certificate construction and does not share the verifier's
  assumptions (L14-5). It also pins the signed-message definition to an off-line
  SHA-256 literal and runs a mutation oracle (every single-byte corruption of the
  known-good object must be rejected). The synthetic names are obviously fake
  ("Independent Test …"); no real machine identifier, serial, key, or user is
  present.
* The remainder of the behavioural gate is covered by
  `crates/wsl-webauthn-verifier/tests/` — the **synthesized** positive/negative
  suite. Every COSE key, `authenticatorData`, `attestationObject`, `attStmt`,
  X.509 chain, and TPM `certInfo`/`pubArea` is generated in-process, so there is
  no third-party licensing or machine-identifier concern. It covers one negative
  test per invariant (plan §4, §12.1/§12.2).
* `tests/attestation.rs::local_vector_tpm_strict_round_trip` — an `#[ignore]`d,
  env-gated test (`WSL_WEBAUTHN_LOCAL_VECTOR=/path/to/spike-enroll-assert.json`)
  that runs the verifier against a **real Windows Hello `tpm`** enrollment +
  assertion captured on the spike machine. That vector is deliberately
  **git-ignored** (`tests/vectors/local/`) because it contains machine
  identifiers; it is never committed.

## Why no vendored third-party vectors

The plan (§4, test item 1) suggested vendoring webauthn4j / Yubico
java-webauthn-server fixtures. On inspection:

* **webauthn4j** (Apache-2.0) does not ship copyable attestation JSON fixtures —
  its `webauthn4j-test` module *generates* registration/assertion objects at
  runtime from embedded Java, and its `src/test/resources` contains only DER/PEM
  test PKI material (`test.crt`, `google-root-CA.crt`, `.jks`, `.p12`). There is no
  static positive/negative attestation-vector file to copy.
* **Yubico java-webauthn-server** (Apache-2.0) likewise generates its packed/none
  cases in Scala test code; its `src/test/resources` holds test certificates and
  keys, not attestation JSON.

Vendoring a fragment of a reference implementation's *Java/Scala source* as a "test
vector" would be both impractical and of low value, so the synthesized suite is
used instead. The reference implementations were consulted to validate the
semantics (see below), and their licenses are recorded under `LICENSES/`.

## References consulted (for semantics, not copied)

| Project | License | Used to validate |
|---|---|---|
| [webauthn4j](https://github.com/webauthn4j/webauthn4j) | Apache-2.0 | TPM §8.3: `pubArea` byte layout, `Name` = `nameAlg ‖ H(pubArea)` over the bare `TPMT_PUBLIC`, `extraData` = H(authData ‖ clientDataHash) using the `alg` hash, RSA exponent 0 → 65537, `nameAlg` support set |
| [Yubico java-webauthn-server](https://github.com/Yubico/java-webauthn-server) | Apache-2.0 | packed/none attestation shapes |
| [W3C WebAuthn Level 2, §8.3 / §8.3.1](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation) | W3C Document License | normative TPM verification procedure and AIK certificate requirements |

No W3C Document License material is copied into this repository.
