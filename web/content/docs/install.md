+++
title = "Install"
description = "Install from the signed apt repository, enroll Windows Hello, upgrade, and uninstall."
weight = 1
+++

Install on the Linux side, then put the bridge on the Windows side. Both halves
are needed: the module cannot reach Windows Hello without the bridge.

## Requirements

| Requirement | Detail |
|---|---|
| Windows 10 1903+ | For the `webauthn.dll` API the bridge loads. |
| WSL2 with interop | WSL1 is untested; systemd services may not reach the interop session leader. |
| Windows Hello set up | PIN, fingerprint, or face; TPM-backed for the default enrollment policy. |
| A distro with PAM | The profile uses `pam-auth-update` (Debian/Ubuntu); other distros get manual `/etc/pam.d` instructions. |
| Building from source | Stable Rust 1.88+ and `libpam0g-dev` on Debian/Ubuntu. |

Released binaries target glibc 2.31 (Debian 11+, Ubuntu 20.04+,
RHEL/Rocky/Alma 9) on `amd64` and `arm64`.

## Install from the signed apt repository

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
```

The repository is signed by the ed25519 key
`AE1D A898 2786 7B0D 7415 BBEE 5834 B868 04A5 D3AF` (expires 2028-10-16).
The keyring comes from the same origin as the repository, so confirm it:

```sh
gpg --show-keys --with-fingerprint /etc/apt/keyrings/wsl-webauthn-pam.gpg
```

`apt` installs the Linux side only — module, CLI, and a disabled
`pam-auth-update` profile. Copy the bridge and enroll:

{% <term label="root shell" copy={true} glyph=">" aria="Finish an apt install: copy the bridge, then enroll"> %}
sudo wsl-webauthn-pam install --skip-enroll --artifact-dir /usr/lib/wsl-webauthn-pam
sudo wsl-webauthn-pam enroll
{% </term> %}

`install` copies the bundled bridge to Windows and writes
`/etc/wsl_webauthn/config`. `--skip-enroll` keeps it from enrolling in the same
step, which would make the following `enroll` fail with `already-exists`;
`enroll` enables the profile once a credential is verified.

## Enrollment {#enrollment}

Enrollment binds one Windows Hello credential to one Linux user, then enables
the profile. For another user, run `sudo wsl-webauthn-pam enroll --user <NAME>`;
for scripted provisioning, `install` also takes `--dry-run`, `--yes`, and
`--non-interactive`.

### The two Windows dialogs

First a *save your passkey* confirmation appears, then a PIN or biometric prompt.

> [!WARNING]
> The dialog can open behind the terminal. **Type your PIN into the Windows
> dialog, never the terminal.** Check the taskbar for the Windows Security icon
> if nothing appears.

### Upgrading

A new release ships a new `WSLWebAuthnBridge.exe`, and its bytes are part of the
hash pinned at enrollment, so an in-place upgrade fails with
`error[bridge-integrity]`. That is the pin doing its job. Re-enroll against the
new binary:

```sh
sudo wsl-webauthn-pam enroll --replace
```

There is no module argument that disables the pin.

## Don't lock yourself out

> [!WARNING]
> Keep a second WSL shell (or the Windows-side root shell) open while you test,
> and confirm `sudo` still falls back to your password before closing it.

The shipped profile uses `[success=end default=ignore]`, so a failed, cancelled,
or timed-out Hello attempt is ignored and PAM falls through to your password.
The exception is an account with no password, or a hand-edited
`required`/`requisite` line the installer refuses to produce.

While you test, rely on the account's local password. WSL has no virtual
console, but from a Windows terminal a root shell bypasses PAM entirely:

```powershell
wsl.exe -d <distro> -u root
```

```sh
pam-auth-update --remove wsl-webauthn   # or: edit /etc/pam.d/* by hand
```

## Bootstrap one-liner

The script downloads the release, checks it against `SHA256SUMS` (and the
provenance attestation when `gh` is present), then provisions, enrolls, and
enables the profile.

{% <term label="bootstrap" copy={true} glyph=">" aria="One-command bootstrap install"> %}
curl -fsSL https://github.com/kirin-xiao/wsl-webauthn-pam/releases/latest/download/bootstrap.sh | sudo bash
{% </term> %}

Pass options through with `bash -s --`, or pin a release with
`--version v0.2.0`.

<details>
<summary>Read the script before running it</summary>

```sh
curl -fsSLO https://github.com/kirin-xiao/wsl-webauthn-pam/releases/latest/download/bootstrap.sh
gh attestation verify bootstrap.sh -R kirin-xiao/wsl-webauthn-pam   # optional
less bootstrap.sh
sudo bash bootstrap.sh
```

</details>

## `--allow-unattested` {#allow-unattested}

Attested enrollment is the default, and a software key is refused.
`--allow-unattested` admits one on a machine you control, and `status` shows that
no attestation was verified; the flag is needed again for a `--replace`
re-enrollment (see the [security summary](@/docs/security.md)).

## Uninstall and rollback

Remove one user's credential:

```sh
sudo wsl-webauthn-pam uninstall --user <NAME>   # or: unregister --user <NAME>
```

Remove everything the installer owns:

```sh
sudo wsl-webauthn-pam uninstall --all
```

If `sudo` is misbehaving, use the Windows-side root shell and remove the profile:

```powershell
wsl.exe -d <distro> -u root
```

```sh
pam-auth-update --remove wsl-webauthn   # or: edit /etc/pam.d/* by hand
```

`uninstall` never blind-edits `/etc/pam.d`; it warns about leftover references.
If you installed from apt, also run `sudo apt remove wsl-webauthn-pam`. The
`/usr/local/bin/wsl-webauthn-pam` copy that `install` wrote is not owned by the
package, shadows `/usr/bin` on `PATH`, and has to be removed by hand. A legacy
`/etc/pam_wsl_hello` directory is never removed (see
[Prior art](@/docs/prior-art.md)).

## From source

<details>
<summary>Build and install from source</summary>

```sh
git clone https://github.com/kirin-xiao/wsl-webauthn-pam
cd wsl-webauthn-pam
make release                            # builds the Linux module + CLI and the Windows bridge
tar xzf build/wsl-webauthn-pam-<version>-<arch>.tar.gz -C build
sudo build/wsl-webauthn-pam-<version>-<arch>/wsl-webauthn-pam install
```

The bridge builds natively with `cargo.exe` on Windows (what CI ships) or
cross-compiles on Linux with `rustup target add x86_64-pc-windows-gnu`. A
tarball install is not tracked by apt, so remove it with
`sudo wsl-webauthn-pam uninstall --all`.

</details>

## Manual installation (no installer) {#manual-installation-no-installer}

<details>
<summary>Install the files by hand</summary>

1. Copy `pam_wsl_webauthn.so` to the PAM security directory, e.g.
   `/usr/lib/x86_64-linux-gnu/security/` (Debian/Ubuntu) or
   `/usr/lib64/security/` (RHEL/Fedora).
2. Copy `WSLWebAuthnBridge.exe` anywhere onto the Windows side; the config
   pins its path.
3. Create the credential store:
   `sudo install -d -m 0700 -o root -g root /etc/wsl_webauthn/credentials`
4. Write `/etc/wsl_webauthn/config` as root, mode `0600`:

   ```toml
   bridge_path = "/mnt/c/Users/<you>/AppData/Local/Programs/wsl-webauthn-pam/WSLWebAuthnBridge.exe"
   win_mnt     = "/mnt/c"
   # timeout_secs = 60        # optional override
   ```

5. Enroll: `sudo wsl-webauthn-pam enroll --no-enable`
6. Add the module to the relevant service (e.g. `/etc/pam.d/sudo`):

   ```text
   auth sufficient pam_wsl_webauthn.so
   ```

   Or copy `pam-config` to `/usr/share/pam-configs/wsl-webauthn` and use
   `pam-auth-update --enable wsl-webauthn`. The profile's
   `[success=end default=ignore]` control is the `pam-auth-update` idiom;
   `pam-auth-update` expands it to a computed jump (`end` is not a literal
   PAM action, so do not paste it raw into `/etc/pam.d`).

</details>
