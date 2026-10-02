# Contributing

Thanks for your interest in `wsl-webauthn-pam`. This is authentication
infrastructure, so correctness and fail-closed behavior matter more than speed.

- Canonical repository: <https://github.com/kirin-xiao/wsl-webauthn-pam>
- Security issues: report privately, see [SECURITY.md](SECURITY.md).

## Development setup

- **Rust:** stable, pinned by `rust-toolchain.toml` (edition 2024,
  `rust-version = 1.88`). Nothing else is required for `cargo check`.
- **PAM headers**, to link the `cdylib` and run the `pam_start` tests:
  `sudo apt-get install -y libpam0g-dev` (Debian/Ubuntu).
- **The Windows bridge** builds on Windows with `cargo.exe` (native MSVC, what
  CI ships) or cross-compiles on Linux:

  ```sh
  rustup target add x86_64-pc-windows-gnu
  cargo build --release -p wsl-webauthn-bridge --target x86_64-pc-windows-gnu
  ```

- **Fuzzing** (`fuzz/`, a separate cargo-fuzz workspace) needs nightly. Export
  `RUSTUP_TOOLCHAIN` for the whole invocation so cargo-fuzz and its child
  `cargo` use the same nightly despite the stable toolchain file:

  ```sh
  rustup toolchain install nightly-2026-09-30
  export RUSTUP_TOOLCHAIN=nightly-2026-09-30
  cargo install cargo-fuzz --version 0.13.2 --locked
  cd fuzz && cargo fuzz run assertion
  ```

  Reproducibility relies on the committed `fuzz/Cargo.lock` (cargo-fuzz 0.13.2
  has no `--locked` pass-through).

## Gates

Before opening a pull request, make sure all of these are green:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Or, where available, `make check` (adds `cargo-deny`). CI adds `cargo-deny
check`, `actionlint`, the `pam-auth-update` profile-expansion guard, the Windows
bridge build/tests, and a native aarch64 `cargo build --release` (which really
links the PAM `cdylib`). See `.github/workflows/ci.yaml`.

Notes:

- Use `--locked` everywhere. If you change a dependency, commit the updated
  `Cargo.lock`.
- Keep the code `unsafe`-free where practical; new `unsafe` needs a
  `// SAFETY:` justification.
- The verifier must never panic on attacker-controlled input and must return an
  error for every malformed path.
- Never commit real-machine attestation material or machine identifiers. Local
  vectors belong in the git-ignored `tests/vectors/local/`.

## Pull requests

- Use **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
  `ci:`, `chore:`).
- Keep changes focused and explain the *why* in the description; call out any
  change to the security model or the PAM mapping table.
- Update documentation (`README.md`, `SECURITY.md`, `CHANGELOG.md`) when user
  behavior or the threat model changes.
- By contributing you agree your contributions are licensed under the
  [MIT License](LICENSE).
