# Verifier test vectors

Provenance of externally-sourced test material used by `wsl-webauthn-verifier`, and why no
third-party binary vectors are committed.

## What is committed

* `crates/wsl-webauthn-verifier/tests/independent.rs` — a committed, sanitized independent
  vector, produced off-line with `python3`, `cryptography`, and a minimal CBOR encoder. It
  calls none of the in-repo builders, so it is a second implementation of the
  signed-message/certificate construction, and it pins the signed-message definition to an
  off-line SHA-256 literal. It also runs a mutation oracle: every single-byte corruption of
  the known-good object must be rejected. Names are obviously fake; no real machine
  identifier, serial, key, or user is present.
* The synthesized positive/negative suite under `crates/wsl-webauthn-verifier/tests/`:
  every COSE key, `authenticatorData`, `attestationObject`, `attStmt`, X.509 chain, and TPM
  `certInfo`/`pubArea` is generated in-process, so there is no third-party licensing or
  machine-identifier concern. It covers one negative test per invariant.
* `tests/attestation.rs::local_vector_tpm_strict_round_trip` — an `#[ignore]`d, env-gated
  test (`WSL_WEBAUTHN_LOCAL_VECTOR=/path/to/spike-enroll-assert.json`) that runs the
  verifier against a real Windows Hello `tpm` enrollment + assertion. That vector is
  git-ignored (`tests/vectors/local/`) because it contains machine identifiers, and is never
  committed.

## Why no vendored third-party vectors

No copyable static attestation vectors exist in the candidate projects: both
[webauthn4j](https://github.com/webauthn4j/webauthn4j) and
[Yubico java-webauthn-server](https://github.com/Yubico/java-webauthn-server) (Apache-2.0)
generate registration/assertion objects from test code at runtime, and their
`src/test/resources` hold only DER/PEM certificates, keys, and keystores. Vendoring a
fragment of their Java/Scala source as a test vector would be impractical and low-value, so
the synthesized suite is used instead. The projects were consulted for semantics only, and
their licenses are recorded under `LICENSES/`.

## References consulted (semantics, not copied)

| Project | License | Used to validate |
|---|---|---|
| [webauthn4j](https://github.com/webauthn4j/webauthn4j) | Apache-2.0 | TPM §8.3: `pubArea` byte layout, `Name` = `nameAlg ‖ H(pubArea)` over the bare `TPMT_PUBLIC`, `extraData` = H(authData ‖ clientDataHash) using the `alg` hash, RSA exponent 0 → 65537, `nameAlg` support set |
| [Yubico java-webauthn-server](https://github.com/Yubico/java-webauthn-server) | Apache-2.0 | packed/none attestation shapes |
| [W3C WebAuthn Level 2, §8.3 / §8.3.1](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation) | W3C Document License | normative TPM verification procedure and AIK certificate requirements |

No W3C Document License material is copied into this repository.
