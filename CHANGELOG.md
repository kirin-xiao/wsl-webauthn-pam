# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 — Unreleased

Initial release: a clean-room rewrite of WSL-Hello-sudo that authenticates
`sudo`/`su` via the Windows Hello **WebAuthn platform authenticator**, with all
verification performed on the Linux side.

### Added

- **`wsl-webauthn-protocol`** — shared OS-agnostic constants (pinned RP ID and
  origin), framed wire types, base64url helpers, and byte-stable
  `clientDataJSON` construction.
- **`wsl-webauthn-verifier`** — the security core: a pure-Rust, `unsafe`-free,
  panic-free WebAuthn verifier. Assertion verification for ES256/RS256/EdDSA;
  attestation verification for `tpm` (§8.3) and `packed`/AttCA to the pinned
  Microsoft TPM Root CA 2014, plus policy-gated self/`none`. Synthesized
  positive/negative tests, `proptest` round-trips, and `cargo-fuzz` targets.
- **`wsl-webauthn-store`** — root-owned credential store (`0700` dir, `0600`
  files) with symlink-hardened, TOCTOU-checked, size-capped reads and atomic
  writes; TOML config parsing.
- **`wsl-webauthn-runner`** — WSL interop spawner with bounded IO, a `poll`-based
  deadline, `SIGKILL` + best-effort `taskkill.exe` escalation, and a fast-fail
  interop pre-flight.
- **`wsl-webauthn-bridge`** (`WSLWebAuthnBridge.exe`) — the Windows ceremony
  driver: dynamic `webauthn.dll` FFI, hidden-window message pump, and a
  self-cancelling watchdog that reclassifies its own cancel as `timeout`.
- **`wsl-webauthn-pam`** (`pam_wsl_webauthn.so`) — the PAM `cdylib` with
  hand-rolled bindings, `catch_unwind` panic containment → `PAM_ABORT`, a fully
  fail-closed mapping table, the bridge SHA-256 pin, and a `pam_conv` consent
  pre-prompt.
- **`wsl-webauthn-cli`** (`wsl-webauthn-pam`) — `enroll` (with D3 double-enroll
  and `--allow-unattested`), `unregister`, `probe`, `status`, `verify`, and the
  installer: `install`/`uninstall` with symlink-hardened atomic writes, the
  `pam-auth-update` profile, and legacy WSL-Hello-sudo migration (D7: rewrite
  `/etc/pam.d` references before removing the old module, never import the PEM).
- **Packaging & CI** — `pam-config` profile (`Default: no`), `install.sh` shim,
  `Makefile`, SHA-pinned `cargo-deny`/actionlint/pam-auth-update-expansion CI,
  and a release workflow producing per-architecture tarballs + `SHA256SUMS`.
- **Docs** — this rewrite's README (security model and limits), `SECURITY.md`
  threat model, `SPIKE.md` empirical findings, `CONTRIBUTING.md`.
