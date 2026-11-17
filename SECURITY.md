# Security Policy

`wsl-webauthn-pam` is authentication infrastructure: a Linux PAM module plus a
Windows bridge that authenticates `sudo`/`su` via the Windows Hello WebAuthn
platform authenticator.

**Canonical repository:** <https://github.com/kirin-xiao/wsl-webauthn-pam>

**Full threat model:** <https://kirin-xiao.github.io/wsl-webauthn-pam/docs/security/>
— design principle, attacker capabilities, trust anchors, the verified-invariant
list, the fail-closed PAM mapping, accepted residual risk, and distribution
integrity. This file is the reporting policy, not the threat model.

## Supported versions

Security fixes land on the latest release. At the time of writing that is
**0.2.0**; `wsl-webauthn-pam --version` prints what is installed.

| Version | Supported |
|---|---|
| 0.2.x (latest release) | yes |
| 0.1.x and earlier | no — upgrade first |

Upgrading in place changes the bridge `.exe` bytes, so the recorded bridge pin
no longer matches: re-enroll with `sudo wsl-webauthn-pam enroll --replace` after
an upgrade (see [the install page](https://kirin-xiao.github.io/wsl-webauthn-pam/docs/install/)).

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting on this repository:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub Security Advisories).
3. Include: affected version/commit, the component (verifier / PAM module / bridge / store / installer), a description, and a minimal reproduction.

## Disclosure process

We will acknowledge the report and coordinate a fix and disclosure. Please allow
reasonable time before public disclosure. There is no bug-bounty program.

- We confirm the report against a supported version, then coordinate a fix and
  a disclosure.
- The fix ships in a release; the advisory names the affected versions and any
  workaround.
- If the report is out of scope — a compromised Windows session, a compromised
  Linux root, a compromised TPM, or a stolen release/signing key — we say so and
  point at the relevant section of the threat model instead of treating it as a
  vulnerability. Those cases are documented, not overlooked.

## Release signing key

The apt repository is signed by the ed25519 key
`AE1D A898 2786 7B0D 7415 BBEE 5834 B868 04A5 D3AF`, which expires 2028-10-16.
Verify a fetched keyring before trusting it:

```sh
gpg --show-keys --with-fingerprint /etc/apt/keyrings/wsl-webauthn-pam.gpg
```

The keyring is served from the same origin as the repository, so a first
install is trust-on-first-use; comparing it against this fingerprint closes
that gap.
