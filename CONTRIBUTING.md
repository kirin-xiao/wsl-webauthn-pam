# Contributing

Thanks for your interest in `wsl-webauthn-pam`. This is authentication
infrastructure, so correctness and fail-closed behavior matter more than speed.

- Canonical repository: <https://github.com/kirin-xiao/wsl-webauthn-pam>
- Security issues: report privately, see [SECURITY.md](SECURITY.md).

## Development setup

- **Rust:** stable, pinned by `rust-toolchain.toml` (edition 2024,
  `rust-version = 1.88`). Nothing else is required for `cargo check`.
- **PAM headers** (to link the `cdylib` and run the `pam_start` tests):

  ```sh
  sudo apt-get install -y libpam0g-dev        # Debian/Ubuntu
  ```

- **Cross-compiling the Windows bridge** (optional; CI also builds it):

  ```sh
  rustup target add x86_64-pc-windows-gnu
  cargo build --release -p wsl-webauthn-bridge --target x86_64-pc-windows-gnu
  ```

  `cmd`/`powershell` users can instead build natively with `cargo.exe` (MSVC).

## Gates

Before opening a pull request, make sure all of these are green:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Or, where available, `make check` (adds `cargo-deny`). CI additionally runs
`cargo-deny check`, `actionlint`, the `pam-auth-update` profile-expansion guard,
the Windows bridge build/tests, and a native aarch64 `cargo build --release`
(which really links the PAM `cdylib`, not just `cargo check`). See
`.github/workflows/ci.yaml`.

Notes:

- Use `--locked` everywhere. If you change a dependency, commit the updated
  `Cargo.lock`.
- Keep the code `unsafe`-free where practical. The only sanctioned `unsafe` is
  in the small, documented FFI/syscall modules (`wsl-webauthn-pam` bindings and
  `wsl-webauthn-store::sys`, `wsl-webauthn-runner::proc`); new `unsafe` needs a
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
