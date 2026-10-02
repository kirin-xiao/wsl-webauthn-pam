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
  `webauthn.dll` FFI, carrying a `VERSIONINFO` resource (file metadata).
- Packaging and CI: `pam-auth-update` profile (`Default: no`), a `bootstrap.sh`
  one-command installer, `Makefile`, and a release workflow producing
  per-architecture tarballs plus `SHA256SUMS`.
- Docs: README, `SECURITY.md`, `SPIKE.md`, `CONTRIBUTING.md`.

### Changed

- Install is now one command:
  `curl -fsSL .../releases/latest/download/bootstrap.sh | sudo bash`.
  `bootstrap.sh` verifies the release tarball against `SHA256SUMS` (and the
  build-provenance attestation when `gh` is present), then provisions, enrolls,
  and enables the profile. The `install.sh` shim is gone; a release tarball's
  CLI is run directly (`sudo ./wsl-webauthn-pam install`).
- `install` and `enroll` now enable the `pam-auth-update` profile **after** a
  credential is verified, instead of offering a separate, default-off enable
  step. `enroll` gains `--no-enable`. A failed or skipped enrollment leaves the
  profile disabled and prints the exact recovery commands.
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
- The PAM module now advances the stored signature counter after a successful assertion
  from a counter-maintaining authenticator, so WebAuthn §7.2 clone detection compares
  against the last seen count instead of the enrollment-time count. The conditional
  write cannot resurrect an `unregister`ed record or clobber a newer enrollment, is
  skipped for constant-zero authenticators (the common case), and can never fail an
  authentication.

### Fixed

- `enroll`/auth no longer look hung while the Windows Hello dialog is open: the CLI
  announces the PIN prompt and the module logs ceremony progress, and the bridge
  best-effort tries to foreground the dialog (falling back to a taskbar flash) so a user
  who sees the prompt is less likely to type the PIN into the shell.
- `bootstrap.sh` runs the installer directly when it is already root, instead of nesting
  `sudo`, so the invoking user (not `root`) is enrolled; it also no longer re-points its
  own stdin, which silently truncated the script under `curl | bash`.
