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
  panic containment, a bridge SHA-256 pin, and a `pam_conv` action-cue notice
  (emitted under `PAM_SILENT` when a terminal is attached, silenceable with `quiet`).
- `wsl-webauthn-pam` CLI: `enroll` (with double-enroll retry and
  `--allow-unattested`), `unregister`, `probe`, `status`, `verify`, and
  `install`/`uninstall` with legacy WSL-Hello-sudo migration.
- Root-owned credential store and TOML config parsing, with symlink-hardened,
  size-capped reads and atomic writes.
- WSL interop runner with bounded IO, a deadline, `SIGKILL` +
  best-effort `taskkill.exe` escalation, and a fast-fail interop pre-flight.
- `WSLWebAuthnBridge.exe`: the Windows ceremony driver over dynamic
  `webauthn.dll` FFI, carrying a `VERSIONINFO` resource so the WebAuthn prompt can
  name its requester.
- Packaging and CI: `pam-auth-update` profile (`Default: no`), `install.sh`
  shim, `Makefile`, and a release workflow producing per-architecture tarballs
  plus `SHA256SUMS`.
- Docs: README, `SECURITY.md`, `SPIKE.md`, `CONTRIBUTING.md`.

### Changed

- The pinned RP ID is now `wsl-webauthn-pam` (the personal `io.github.kirin-xiao`
  segment is dropped from the `Passkey for …` line the Windows dialog shows).
  The `rpIdHash` therefore changes: **existing users must re-enroll**, and the old
  Windows credential cannot be deleted (it is orphaned).
- `WSLWebAuthnBridge.exe` now carries a `VERSIONINFO` resource, so its bytes (and thus
  the SHA-256 recorded at enrollment) change; upgrading in place without re-enrolling
  fails the bridge pin. Re-enrolling re-pins the new binary.
- The `pam_conv` notice is emitted during `sudo` (which authenticates with
  `PAM_SILENT`) when a controlling terminal is present, and suppressed for scripted
  callers or with the `quiet` module argument.

### Fixed

- `enroll`/auth no longer look hung while the Windows Hello dialog is open: the CLI
  announces the PIN prompt and the module logs ceremony progress, and the bridge
  best-effort tries to foreground the dialog (falling back to a taskbar flash) so a user
  who sees the prompt is less likely to type the PIN into the shell.
