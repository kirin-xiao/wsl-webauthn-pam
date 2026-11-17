# wsl-webauthn-pam

[![CI](https://github.com/kirin-xiao/wsl-webauthn-pam/actions/workflows/ci.yaml/badge.svg)](https://github.com/kirin-xiao/wsl-webauthn-pam/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange?logo=rust&logoColor=white)](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/install/)
[![Windows 10 1903+ · WSL2](https://img.shields.io/badge/Windows-10%20build%201903%2B%20%C2%B7%20WSL2-0078D6?logo=windows&logoColor=white)](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/install/#requirements)

**Passwordless `sudo` and `su` inside WSL2, authenticated with the Windows
Hello passkey you already use.** A Linux PAM module plus a small Windows bridge:
it does not replace `sudo`, does not touch `sudoers`, and every security decision
is made on the Linux side.

> **Status.** 0.2.0 is the current release. Windows Hello credentials from
> WSL-Hello-sudo are **not** migrated: the legacy key is never imported and
> every user re-enrolls from scratch.

## Install

Debian 11+ / Ubuntu 20.04+ (amd64 or arm64), from the signed apt repository:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://kirin-xiao.github.io/wsl-webauthn-pam/wsl-webauthn-pam-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/wsl-webauthn-pam.gpg >/dev/null
sudo tee /etc/apt/sources.list.d/wsl-webauthn-pam.sources >/dev/null <<'EOF'
Types: deb
URIs: https://kirin-xiao.github.io/wsl-webauthn-pam
Suites: stable
Components: main
Architectures: amd64 arm64
Signed-By: /etc/apt/keyrings/wsl-webauthn-pam.gpg
EOF
sudo apt update && sudo apt install wsl-webauthn-pam
sudo wsl-webauthn-pam install --skip-enroll --artifact-dir /usr/lib/wsl-webauthn-pam
sudo wsl-webauthn-pam enroll
```

The repository is signed by the ed25519 key
`AE1D A898 2786 7B0D 7415 BBEE 5834 B868 04A5 D3AF` (expires 2028-10-16); check
the fetched keyring against it before trusting it. Two Windows dialogs appear
during enrollment: first a *save your passkey* confirmation, then your PIN or
biometric — **type the PIN into the Windows dialog, never the terminal.**

The [install page](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/install/)
covers the rest: the bootstrap one-liner, the `.deb`, building from source, the
manual path, `--allow-unattested`, per-distro installs, uninstall, and the
upgrade caveat (a new `.exe` changes the pin, so upgrades re-enroll).

> [!WARNING]
> Keep a second WSL shell open while you test, and confirm `sudo` still falls
> back to your password before you close it. If you are stuck:
> `wsl.exe -d <distro> -u root` (a Windows-side root shell that bypasses PAM),
> then `pam-auth-update --remove wsl-webauthn`.

## Documentation

The site is the manual: <https://kirin-xiao.github.io/wsl-webauthn-pam/>

- [Install](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/install/) — requirements, every install path, uninstall
- [How it works](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/how-it-works/) — the sudo → PAM → Hello sequence
- [Security](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/security/) — threat model, trust anchors, verified invariants
- [Usage](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/usage/) — CLI, PAM arguments, config keys, error tokens
- [Troubleshooting](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/troubleshooting/) — symptom, cause, fix
- [FAQ](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/faq/) — shared accounts, multiple distros, no TPM
- [Prior art](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/prior-art/) — WSL-Hello-sudo and what changed

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Build and PR gates, fuzzing, and the cross-compiled Windows bridge are covered in
[CONTRIBUTING.md](CONTRIBUTING.md). Releases are on the
[releases page](https://github.com/kirin-xiao/wsl-webauthn-pam/releases).
Security issues: report privately, see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
