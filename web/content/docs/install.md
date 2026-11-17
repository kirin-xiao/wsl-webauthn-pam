+++
title = "Install"
description = "The signed apt repository, the .deb, the bootstrap script, the two-command path, and what each step leaves on disk."
weight = 1
+++

`wsl-webauthn-pam` installs on the Linux side and puts one executable on the
Windows side. Both halves are needed: the PAM module cannot reach Windows Hello
without the bridge, and the bridge is useless without a credential enrolled from
inside the distro.

The signed apt repository is the primary path. Everything else on this page
installs the same files.

## Requirements

| Requirement | Detail |
|---|---|
| Windows 10 1903+ (build 18362) | The minimum for the WebAuthn API the bridge loads (`webauthn.dll`). |
| WSL2 with interop enabled | WSL1 is untested. systemd services may not see the interop session leader, so Hello can work from an interactive shell but not from a service. |
| Windows Hello set up | PIN, fingerprint, or face. TPM-backed for the default enrollment policy. |
| A Linux distro with PAM | The packaged profile uses `pam-auth-update` (Debian/Ubuntu family); on other distros the installer prints the exact manual `/etc/pam.d` instructions instead. |
| Building from source only | Stable Rust (1.88+, edition 2024) and `libpam0g-dev` on Debian/Ubuntu. |

The released Linux binaries are built against glibc 2.31 and load on Debian 11+,
Ubuntu 20.04+, and RHEL/Rocky/Alma 9. The apt repository serves `amd64` and
`arm64`.

## Install from the signed apt repository

Debian 11+ and Ubuntu 20.04+ are supported.

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

The repository is signed by the ed25519 key `AE1D A898 2786 7B0D 7415 BBEE 5834 B868 04A5 D3AF`
(expires 2028-10-16). The keyring is fetched from the same origin as the
repository, so confirm you got the right key before trusting it:

```sh
gpg --show-keys --with-fingerprint /etc/apt/keyrings/wsl-webauthn-pam.gpg
```

`apt` installs the Linux side only — the PAM module, the CLI, and the
`pam-auth-update` profile (left disabled). The Windows bridge still has to reach
the Windows side, and enrollment is still interactive, so run:

{% <term label="root shell" copy={true} glyph=">" aria="Finish an apt install: copy the bridge, then enroll"> %}
sudo wsl-webauthn-pam install --skip-enroll --artifact-dir /usr/lib/wsl-webauthn-pam
sudo wsl-webauthn-pam enroll
{% </term> %}

`install` copies the bundled bridge onto the Windows side and writes
`/etc/wsl_webauthn/config`; `--skip-enroll` keeps it from offering to enroll in
the same step (which would make the following `enroll` fail with
`already-exists`). `enroll` enables the profile once a credential is verified.

`install` also copies the CLI to `/usr/local/bin`, which shadows the packaged
`/usr/bin` copy on `PATH` — harmless for operation, but a later `apt remove`
does not remove that copy.

## Enrollment {#enrollment}

An enrollment binds one Windows Hello credential to one Linux user: it runs the
WebAuthn ceremony on the Windows side, verifies the attestation and the assertion
signature on the Linux side, and only then writes the credential record and
enables the profile.

### The two Windows dialogs

Two Windows dialogs appear during enrollment: first a *save your passkey*
confirmation, then your PIN or biometric.

> [!WARNING]
> The dialog can open behind the terminal. **Type your PIN into the Windows
> dialog, never the terminal.** Check the taskbar for the Windows Security icon
> if nothing appears.

### Upgrading

A new release ships a new `WSLWebAuthnBridge.exe`. Its bytes are part of the
pinned hash recorded at enrollment, so an in-place upgrade makes the pin fail:

```text
error[bridge-integrity]
```

That is the pin doing its job. Re-enroll against the new binary:

```sh
sudo wsl-webauthn-pam enroll --replace
```

The same applies after replacing the `.exe` by hand. There is no module argument
that disables the pin.

## Don't lock yourself out

> [!WARNING]
> Keep a second WSL shell (or the Windows-side root shell below) open while you
> test, and confirm `sudo` still falls back to your password before closing it.

The shipped profile carries the `pam-auth-update` fail-through control

```text
[success=end default=ignore]  pam_wsl_webauthn.so
```

so a Hello attempt that fails, times out, or never gets a prompt (no credential,
broken bridge, unavailable interop) is **ignored** and PAM falls through to the
next method — normally your password. Under the shipped configuration the module
adds no new way to lose password access; an account with no password or a
hand-edited `required`/`requisite` line (which the installer refuses to produce)
is the exception.

Rely on the account's **local password** while you test. WSL has no virtual
console (`Ctrl-Alt-F2`), but from a Windows terminal a root shell for the distro
**bypasses PAM entirely**:

```powershell
wsl.exe -d <distro> -u root
```

```sh
pam-auth-update --remove wsl-webauthn   # or: edit /etc/pam.d/* by hand
```

## Bootstrap one-liner

The script downloads the release tarball, checks it against `SHA256SUMS` (and the
build-provenance attestation when `gh` is present), then provisions, enrolls, and
enables the profile.

{% <term label="bootstrap" copy={true} glyph=">" aria="One-command bootstrap install"> %}
curl -fsSL https://github.com/kirin-xiao/wsl-webauthn-pam/releases/latest/download/bootstrap.sh | sudo bash
{% </term> %}

```text
Done. `sudo` now uses Windows Hello.
  If you decline the Hello prompt, sudo falls back to your password.
  Test it:  sudo -k; sudo true
  Add another user later:  sudo /usr/local/bin/wsl-webauthn-pam enroll
```

Pass options through to the installer, or pin a release:

```sh
curl -fsSL .../bootstrap.sh | sudo bash -s -- --allow-unattested
curl -fsSL .../bootstrap.sh | sudo bash -s -- --version v0.2.0
```

To read the script before running it:

```sh
curl -fsSLO https://github.com/kirin-xiao/wsl-webauthn-pam/releases/latest/download/bootstrap.sh
gh attestation verify bootstrap.sh -R kirin-xiao/wsl-webauthn-pam   # optional
less bootstrap.sh
sudo bash bootstrap.sh
```

## The `.deb` from the release page

```sh
curl -fsSLO https://github.com/kirin-xiao/wsl-webauthn-pam/releases/download/v0.2.0/wsl-webauthn-pam_0.2.0_amd64.deb
gh attestation verify wsl-webauthn-pam_0.2.0_amd64.deb -R kirin-xiao/wsl-webauthn-pam  # optional
sudo apt install ./wsl-webauthn-pam_0.2.0_amd64.deb
```

A `.deb` install has the same two halves to finish as the apt path: copy the
bridge and enroll, with the commands in
[Install from the signed apt repository](#install-from-the-signed-apt-repository).

## Two commands (pre-provision)

```sh
sudo wsl-webauthn-pam install --skip-enroll   # provision; profile left disabled
sudo wsl-webauthn-pam enroll                  # enroll; enables the profile on success
```

`install` also supports `--dry-run`, `--yes`/`-y`, and `--non-interactive` for
scripted provisioning, and `enroll --user <NAME>` for another user. A skipped,
declined, or failed enrollment leaves the profile disabled and prints the exact
recovery commands.

`enroll` and `install` print only actionable status by default. Add `-v`/`--verbose`
to see the resolved config and each provisioning step, or `--quiet`/`-q` to
suppress all non-error status in scripts. The two are mutually exclusive and are
accepted only by `enroll`/`install`; `probe`/`status`/`verify`/`unregister`/`uninstall`
and `--dry-run` always print their full output.

## From source

```sh
git clone https://github.com/kirin-xiao/wsl-webauthn-pam
cd wsl-webauthn-pam
make release                            # builds the Linux module + CLI and the Windows bridge
tar xzf build/wsl-webauthn-pam-<version>-<arch>.tar.gz -C build
sudo build/wsl-webauthn-pam-<version>-<arch>/wsl-webauthn-pam install
```

`install` copies the CLI to `/usr/local/bin/wsl-webauthn-pam`, so the short
command works from any directory afterwards. The bridge builds natively with
`cargo.exe` on Windows (what CI ships) or cross-compiles on Linux with
`rustup target add x86_64-pc-windows-gnu`. A tarball install is not tracked by
apt, so remove it with `sudo wsl-webauthn-pam uninstall --all`.

## Manual installation (no installer)

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

## Other distros

The packaged `pam-auth-update` profile is Debian/Ubuntu-specific. On other
distros the installer prints the exact manual `/etc/pam.d` instructions instead
of running `pam-auth-update`, so step 6 above is the whole integration. The
module binary is the same one that ships in the `.deb`.

## One install per distro

Each distro is a separate Linux system with its own `/etc/pam.d`, so install and
enroll once per distro. The Windows side is shared: several distros, and several
Linux users, can enroll against the same Windows account.

## What `--allow-unattested` records

Attested enrollment (`tpm`/`packed`) must chain to the pinned Microsoft TPM Root
CA 2014 with a Windows Hello AAGUID. A software key (attestation `self`/`none`)
is refused by default.

`--allow-unattested` admits it once, for a machine you control. The resulting
credential record is stamped `attestation.mode: "unattested-opt-in"` and is
visible in `status`. The label is enrollment-time audit metadata, not an
authentication-time policy: it tells an operator that no attestation was
verified, and it is never a silent fallback — the flag has to be passed
explicitly, again for a `--replace` re-enrollment.

## Uninstall and rollback

Remove one user's credential, keeping the module installed:

```sh
sudo wsl-webauthn-pam uninstall --user <NAME>   # or: unregister --user <NAME>
```

Remove everything the installer owns — profile, module, config, Windows bridge,
and the CLI:

```sh
sudo wsl-webauthn-pam uninstall --all
```

If `sudo` is misbehaving and you need out of the PAM stack immediately, the
recovery path is the Windows-side root shell plus the profile removal:

```powershell
wsl.exe -d <distro> -u root
```

```sh
pam-auth-update --remove wsl-webauthn   # or: edit /etc/pam.d/* by hand
```

`uninstall` never blind-edits `/etc/pam.d`: it warns about leftover references it
finds. If you installed from apt, also run `sudo apt remove wsl-webauthn-pam` to
remove the packaged files; the `/usr/local/bin/wsl-webauthn-pam` copy that
`install` left behind is not owned by the package. A legacy `/etc/pam_wsl_hello`
directory from WSL-Hello-sudo is never removed — it is not this project's (see
[Prior art](@/docs/prior-art.md)).
