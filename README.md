# wsl-webauthn-pam

Linux PAM module that authenticates `sudo`/`su` via the **Windows WebAuthn platform
authenticator** (Windows Hello) over WSL interop.

Clean-room rewrite of WSL-Hello-sudo as a strong authentication mechanism: the Windows
Hello / FIDO2 ceremony runs in a small Windows bridge (`WSLWebAuthnBridge.exe`), and **all
signature and attestation verification happens on the Linux side** in a pure-Rust verifier.

> **Status: under active development.** Nothing here is ready for production use yet.

## Goals

- Authenticate `sudo`/`su` with the TPM-backed Windows Hello platform authenticator.
- Verify everything (challenge, origin, rpIdHash, UV/UP flags, signature, attestation chain)
  locally; never trust a Windows-side signing oracle.
- Fail closed: every error path maps to a documented PAM result, no silent fallback.

See the binding implementation plan and issue tracker for the full design, frozen decisions,
and acceptance criteria (plan §1–§13).

## Repository layout

| Path | Purpose |
|---|---|
| `crates/wsl-webauthn-protocol` | Shared constants + wire types + framing (no OS deps) |
| `crates/wsl-webauthn-verifier` | Security core: CBOR/COSE parsers + verification (Wave A) |
| `crates/wsl-webauthn-store` | Root-owned credential store (Wave A) |
| `crates/wsl-webauthn-runner` | Spawns the bridge via interop with deadline + bounded IO (Wave A) |
| `crates/wsl-webauthn-bridge` | `WSLWebAuthnBridge.exe` (Windows only) |
| `crates/wsl-webauthn-pam` | `pam_wsl_webauthn.so` (Linux cdylib) |
| `crates/wsl-webauthn-cli` | `wsl-webauthn-pam` (`enroll`/`probe`/`install`/…) |

## Build prerequisites

- Stable Rust (edition 2024; `rust-version = 1.85`). The toolchain is pinned by
  `rust-toolchain.toml`.
- **Linux PAM module**: needs `libpam0g-dev` **only to link the cdylib**. `cargo check` works
  without it.
- **Windows bridge**: build on Windows with `cargo.exe`, or cross-compile on Linux with the
  self-contained `x86_64-pc-windows-gnu` target:

  ```sh
  rustup target add x86_64-pc-windows-gnu
  cargo build --release -p wsl-webauthn-bridge --target x86_64-pc-windows-gnu
  ```

  `make bridge` picks `cargo.exe` when available and otherwise falls back to the gnu target.

## Quick start

```sh
cargo test --workspace      # unit tests (no libpam0g-dev required)
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release --workspace
```

## License

MIT — see [LICENSE](LICENSE).
