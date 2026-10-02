# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 — Unreleased

Initial release: authenticate `sudo`/`su` on WSL via the Windows Hello WebAuthn
platform authenticator, with all cryptographic verification performed on the
Linux side.

### Added

- Assertion verification for ES256, RS256, and EdDSA; `tpm` and `packed`/AttCA
  attestation verification chained to the pinned Microsoft TPM Root CA 2014;
  policy-gated self/`none`.
- `pam_wsl_webauthn.so`: a PAM module with a fully fail-closed result mapping,
  panic containment, a bridge SHA-256 pin, and a `pam_conv` consent pre-prompt.
- `wsl-webauthn-pam` CLI: `enroll` (with double-enroll retry and
  `--allow-unattested`), `unregister`, `probe`, `status`, `verify`, and
  `install`/`uninstall` with legacy WSL-Hello-sudo migration.
- Root-owned credential store and TOML config parsing, with symlink-hardened,
  size-capped reads and atomic writes.
- WSL interop runner with bounded IO, a deadline, `SIGKILL` +
  best-effort `taskkill.exe` escalation, and a fast-fail interop pre-flight.
- `WSLWebAuthnBridge.exe`: the Windows ceremony driver over dynamic
  `webauthn.dll` FFI.
- Packaging and CI: `pam-auth-update` profile (`Default: no`), `install.sh`
  shim, `Makefile`, and a release workflow producing per-architecture tarballs
  plus `SHA256SUMS`.
- Docs: README, `SECURITY.md`, `SPIKE.md`, `CONTRIBUTING.md`.
