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

Or, where available, `make check` (adds `cargo-deny`, `shellcheck`, and the
hermetic `bootstrap.sh` tests). CI adds `cargo-deny check`, `actionlint`, the
`pam-auth-update` profile-expansion guard, the Windows bridge build/tests, a
native aarch64 `cargo build --release` (which really links the PAM `cdylib`), and
a `package` job that builds the Linux artifacts in the glibc-floor container,
asserts the floor, builds the `.deb`, and installs it in Debian 12 / Ubuntu 22.04
containers. See `.github/workflows/ci.yaml`.

`bootstrap.sh` is gated by `shellcheck` and by `scripts/test-bootstrap.sh` — a
hermetic harness (no network, no privileges) that runs the script under a
whole-`PATH` command shim against a synthetic release tree. Run it directly with
`sh scripts/test-bootstrap.sh` or `make bootstrap`.

Notes:

- Use `--locked` everywhere. If you change a dependency, commit the updated
  `Cargo.lock`.
- Keep the code `unsafe`-free where practical; new `unsafe` needs a
  `// SAFETY:` justification.
- The verifier must never panic on attacker-controlled input and must return an
  error for every malformed path.
- Never commit real-machine attestation material or machine identifiers. Local
  vectors belong in the git-ignored `tests/vectors/local/`.

## Packaging and releases

Releases are cut by pushing a `vX.Y.Z` tag; `.github/workflows/release.yaml` then
builds the tarballs, the `.deb`s, and the signed apt repository.

- **glibc floor.** The released Linux module and CLI are compiled inside
  `ubuntu:20.04` (glibc 2.31) by `.github/scripts/build-glibc-floor.sh`, and the
  ELF is asserted against that floor by `.github/scripts/check-glibc-floor.sh`.
  Do not "simplify" the build back onto `ubuntu-latest`: that silently raises the
  floor to the runner's glibc and makes the result unloadable on Debian 12 /
  Ubuntu 22.04. The floor is also what the `.deb`'s `libc6 (>= 2.31)` reflects.
- **`.deb` packaging.** `packaging/nfpm.yaml` is the whole spec; nfpm is pinned
  (version + per-arch SHA-256) in `.github/scripts/install-nfpm.sh`, and
  `.github/scripts/build-deb.sh` maps the release arch labels to the deb
  architecture and the multiarch security-directory triplet. `make deb` builds
  the package locally from the host-built binaries (host glibc, not the floor)
  and runs `.github/scripts/check-deb-layout.sh`, which asserts the module/CLI
  paths and modes and — importantly — that the installer's `--artifact-dir`
  module is a *regular file*. The CLI reads that module with a no-follow read and
  refuses a symlink, so a symlinked artifact would break every packaged
  `install`. The maintainer scripts live in `packaging/debian/`; they must stay
  non-interactive and must never enroll, and the profile must be deregistered in
  `prerm` (while the module is still on disk), not only in `postrm`.
- **apt repository.** `.github/scripts/build-apt-repo.sh` re-indexes every
  released `.deb`, signs `Release`/`InRelease`, exports the public keyring, and
  fails closed if the signature does not verify. Publishing needs two secrets —
  `APT_GPG_PRIVATE_KEY` (an ASCII-armored ed25519 private key) and, for a
  passphrase-protected key, `APT_GPG_PASSPHRASE`. Declare them on the
  `github-pages` environment so only the `apt-repo` job can read them, and add
  required reviewers there to gate a release behind an approval. The signing
  key's fingerprint is published in the README. GitHub Pages must be set to
  deploy **from GitHub Actions**. Pre-release tags are excluded from the
  repository, which only ever serves the stable suite.
- **Version bumps.** Bump `version` in `Cargo.toml`, refresh `Cargo.lock`
  (`cargo metadata` rewrites only the workspace members' versions), and add a
  `CHANGELOG.md` entry. The release workflow refuses a tag whose base version
  does not match `Cargo.toml`. Pre-release tags (`v0.2.0-rc1`) map to a Debian
  `0.2.0~rc1` automatically.

## Pull requests

- Use **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
  `ci:`, `chore:`).
- Keep changes focused and explain the *why* in the description; call out any
  change to the security model or the PAM mapping table.
- Update documentation (`README.md`, `SECURITY.md`, `CHANGELOG.md`) when user
  behavior or the threat model changes.
- By contributing you agree your contributions are licensed under the
  [MIT License](LICENSE).
