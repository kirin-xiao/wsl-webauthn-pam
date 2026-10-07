# wsl-webauthn-pam

[![CI](https://github.com/kirin-xiao/wsl-webauthn-pam/actions/workflows/ci.yaml/badge.svg)](https://github.com/kirin-xiao/wsl-webauthn-pam/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange?logo=rust&logoColor=white)](#other-ways-to-install)
[![Windows 10 1903+ · WSL2](https://img.shields.io/badge/Windows-10%20build%201903%2B%20%C2%B7%20WSL2-0078D6?logo=windows&logoColor=white)](#requirements)

**Passwordless `sudo` and `su` inside WSL2, authenticated with the Windows
Hello passkey you already use.**

`wsl-webauthn-pam` is a Linux PAM module plus a tiny Windows helper.

It is a pure PAM module — it does not fork or replace `sudo`, does not touch
`sudoers`, and works for anything that authenticates through PAM. It is an
independent rewrite of
[WSL-Hello-sudo](https://github.com/nullpo-head/WSL-Hello-sudo) (see
[Prior art](#prior-art)).

> **Status.** 0.1.0 is the initial release. Windows Hello credentials from
> WSL-Hello-sudo are **not** migrated: the legacy key is never imported and
> every user re-enrolls from scratch.

## Quick start

```sh
curl -fsSL https://github.com/kirin-xiao/wsl-webauthn-pam/releases/latest/download/bootstrap.sh | sudo bash
```

```text
Done. `sudo` now uses Windows Hello.
  If you decline the Hello prompt, sudo falls back to your password.
  Test it:  sudo -k; sudo true
  Add another user later:  sudo /usr/local/bin/wsl-webauthn-pam enroll
```

Two Windows dialogs appear during enrollment: first a *save your passkey*
confirmation, then your PIN or biometric. The dialog can open behind the
terminal — **type your PIN into the Windows dialog, never the terminal.**

Pass options through to the installer, or pin a release:

```sh
curl -fsSL .../bootstrap.sh | sudo bash -s -- --allow-unattested
curl -fsSL .../bootstrap.sh | sudo bash -s -- --version v0.1.0
```

To read the script before running it:

```sh
curl -fsSLO https://github.com/kirin-xiao/wsl-webauthn-pam/releases/latest/download/bootstrap.sh
gh attestation verify bootstrap.sh -R kirin-xiao/wsl-webauthn-pam   # optional
less bootstrap.sh
sudo bash bootstrap.sh
```

## Don't lock yourself out

> [!WARNING]
> Keep a second WSL shell (or the Windows-side root shell below) open while you
> test, and confirm `sudo` still falls back to your password before closing it.

The shipped profile carries the `pam-auth-update` fail-through control

```text
[success=end default=ignore]  pam_wsl_webauthn.so
```

so a Hello attempt that fails, times out, or never gets a prompt (no
credential, broken bridge, unavailable interop) is **ignored** and PAM falls
through to the next method — normally your password. Under the shipped
configuration the module adds no new way to lose password access; an account
with no password or a hand-edited `required`/`requisite` line (which the
installer refuses to produce) is the exception.

Rely on the account's **local password** while you test. WSL has no virtual
console (`Ctrl-Alt-F2`), but from a Windows terminal a root shell for the
distro **bypasses PAM entirely**:

```powershell
wsl.exe -d <distro> -u root
```

```sh
pam-auth-update --remove wsl-webauthn   # or: edit /etc/pam.d/* by hand
```

## Requirements

- **Windows 10 1903+** (build 18362) — the minimum for the WebAuthn API the
  bridge loads (`webauthn.dll`).
- **WSL2 with interop enabled** (WSL1 untested). systemd services may not see
  the interop session leader, so Hello can work from an interactive shell but
  not from a service.
- **Windows Hello set up** — PIN, fingerprint, or face. TPM-backed for the
  default enrollment policy.
- **A Linux distro with PAM.** The packaged profile uses `pam-auth-update`
  (Debian/Ubuntu family); on other distros the installer prints the exact
  manual `/etc/pam.d` instructions instead.
- **To build from source:** stable Rust (1.88+, edition 2024) and
  `libpam0g-dev` on Debian/Ubuntu.

## Other ways to install

### Two commands (pre-provision)

```sh
sudo wsl-webauthn-pam install --skip-enroll   # provision; profile left disabled
sudo wsl-webauthn-pam enroll                  # enroll; enables the profile on success
```

`install` also supports `--dry-run`, `--yes`/`-y`, and `--non-interactive` for
scripted provisioning, and `enroll --user <NAME>` for another user. A skipped,
declined, or failed enrollment leaves the profile disabled and prints the exact
recovery commands.

`enroll` and `install` print only actionable status by default. Add
`-v`/`--verbose` to see the resolved config and each provisioning step, or
`--quiet`/`-q` to suppress all non-error status in scripts. The two are
mutually exclusive and are accepted only by `enroll`/`install`;
`probe`/`status`/`verify`/`unregister`/`uninstall` and `--dry-run` always print
their full output.

### From source

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
`rustup target add x86_64-pc-windows-gnu`.

<details>
<summary><strong>Manual installation (no installer)</strong></summary>

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

## How it works

```mermaid
sequenceDiagram
    autonumber
    participant U as You
    participant P as sudo/PAM stack
    participant M as pam_wsl_webauthn.so
    participant B as WSLWebAuthnBridge.exe
    participant H as Windows Hello

    U->>P: sudo whoami
    P->>M: authenticate "alice"
    M->>M: load the credential record, mint a fresh 32-byte challenge
    M->>B: spawn over WSL interop — framed stdio, no shell, no temp challenge file
    B->>H: WebAuthNAuthenticatorGetAssertion, user verification required
    H->>U: passkey prompt — PIN, fingerprint, or face
    U-->>H: gesture
    H-->>B: assertion
    B-->>M: relay authenticatorData, signature, credentialId
    M->>M: verify rpIdHash, UP/UV flags, credential binding, signature
    M-->>P: PAM_SUCCESS — every other path is fail-closed
    P-->>U: done
```

**What you see.** On `sudo`, the module prints a one-line cue naming the
service and the Linux user being elevated (for example: *Windows Hello:
authenticating 'sudo' for Linux user alice — a Windows passkey prompt is
waiting; check the taskbar and do not type here*). The Windows dialog is
titled *Sign in with a passkey* and shows **Passkey for wsl-webauthn-pam** —
the pinned relying-party ID, not a configurable display name.

**Decline and cancel.** Cancelling the prompt is an ordinary failure: `sudo`
falls through to the password prompt (with a short delay).

## Security

- **Attested enrollment.** `tpm`/`packed` attestation must chain to the pinned
  **Microsoft TPM Root CA 2014** with a Windows Hello AAGUID. A software key
  (attestation `self`/`none`) is refused by default; `--allow-unattested`
  exists for TPM-less machines you control, is recorded in the credential
  record, and is never a silent fallback.
- **Pinned RP ID and origin.** Compile-time constants, asserted byte-for-byte
  on the Linux side.
- **Pinned bridge.** The `.exe` is hash-checked on every launch, using the same
  file descriptor it executes.
- **Hardened store.** One root-owned credential record per Linux user
  (`0700`/`0600`), symlink-refusing, swap-detecting, atomic-write, and
  bounded-read.
- **No surprises.** No telemetry, no accounts, and no network at
  authentication time. The only network use is the release download you run
  yourself.

The full threat model — attacker capabilities, the verified-invariant list,
and how each error path is fail-closed — lives in [SECURITY.md](SECURITY.md).

## Using the CLI

`wsl-webauthn-pam <COMMAND> [OPTIONS]` (installed at
`/usr/local/bin/wsl-webauthn-pam`; `-h` prints the full usage). Operational
failures print stable tokens you can script against — `error[not-found]`,
`error[interop-unavailable]`, `error[bridge-integrity]`, … — and the exit code
is `0` on success, `1` on operational failure, `2` on usage error.

| Command | What it does | Root? | Key options |
|---|---|---|---|
| `install` | Provision the bridge, config, module, profile, and CLI | yes | `--skip-enroll`, `--dry-run`, `--yes`/`-y`, `--non-interactive`, `--allow-unattested`, `--artifact-dir`, `--module-dir`, `--win-mnt`, `-v`/`--verbose`, `--quiet`/`-q` |
| `enroll` | Run the Windows Hello ceremony for one Linux user, then enable the profile | yes | `--replace`, `--allow-unattested`, `--no-enable`, `--user <NAME>`, `--bridge`, `--win-mnt`, `-v`/`--verbose`, `--quiet`/`-q` |
| `unregister` | Remove one user's credential record | yes | `--user <NAME>`, `--yes`/`-y` |
| `uninstall` | Remove a credential or all components | yes | `--user <NAME>` or `--all` (also removes the CLI), `--module-dir`, `--win-mnt`, `--yes`/`-y`, `--non-interactive` |
| `probe` | Report interop and Hello availability, check the bridge pin | no (root for the pin) | `--bridge`, `--win-mnt` |
| `status` | List enrolled users and the config summary | no (root for the records) | `--user <NAME>` for one full record |
| `verify` | Self-test the crypto stack against a synthetic ceremony | no | — |

Example output:

```console
$ wsl-webauthn-pam verify
verify: PASS
  attestation: packed / SelfAttested
  assertion:   verified (ES256)
  negative control: tampered signature rejected
  negative control: disallowed AAGUID rejected

$ sudo wsl-webauthn-pam probe
Bridge:  /mnt/c/Users/<you>/AppData/Local/Programs/wsl-webauthn-pam/WSLWebAuthnBridge.exe
win_mnt: /mnt/c
interop: OK
api_version: 9
Windows Hello: available
pin:     OK (matches the enrolled bridge)
```

### PAM module arguments

| Argument | Effect |
|---|---|
| `quiet` | Never emit the terminal action cue |
| `debug` | Verbose logging (never secrets) |
| `timeout=<secs>` | Whole-ceremony deadline; a value outside `1..=600` or non-numeric is logged and ignored |

```text
auth sufficient pam_wsl_webauthn.so quiet timeout=120
```

The same timeout can be set globally with `timeout_secs` in
`/etc/wsl_webauthn/config` — a plain TOML file `install` writes; add the key
by hand.

## Troubleshooting

**`sudo` just asks for a password — the module never seems to trigger.**
Check `sudo wsl-webauthn-pam status` first (is a credential enrolled for this
user?), then the auth log: `journalctl -t pam_wsl_webauthn` or your distro's
`auth.log` (facility `authpriv`); the `debug` module argument adds detail. The
module writes nothing to stdout.

**`install` finished but `sudo` still asks for a password.**
Either the invoking user has no credential — visible in `status` — or the
profile is not enabled. Enable with
`sudo pam-auth-update --enable wsl-webauthn` and enroll with
`sudo wsl-webauthn-pam enroll`. Install and enroll enable the profile
automatically **only after enrollment succeeds**.

**The Windows prompt appears behind other windows.**
Watch the taskbar for the Windows Security icon. Type the PIN into the
**dialog**, never the terminal.

**`interop-unavailable` — the bridge never starts.**
WSL interop needs the `WSLInterop` `binfmt_misc` registration enabled; systemd
services often cannot reach the session leader (see
[Requirements](#requirements)). The runner fails fast rather than hanging.

**The prompt times out.**
Default deadline is 60 s (55 s advisory in the dialog plus a hard Linux-side
deadline, with up to ~5 s of cleanup). Override with the `timeout=<secs>`
module argument or `timeout_secs` in the config. A watchdog expiry is reported
as `timeout`; pressing *cancel* in the dialog is `user_cancelled` and falls
through to the password.

**`error[bridge-integrity]` — the bridge pin fails after I replaced the `.exe`.**
That is the pin doing its job. Re-enroll (`sudo wsl-webauthn-pam enroll
--replace`) to trust the new binary. The pin is always enforced; there is no
module argument to disable it. Upgrading in place also changes the `.exe`
bytes (it carries version metadata), so upgrades re-enroll.

## FAQ

**Several Linux users share one Windows account — does that work?**
Yes, and that is the normal WSL case. Each Linux user enrolls once and has
exactly one credential record of their own, bound for audit to the Windows
account that enrolled it.

**I installed it in one distro; what about my other distros?**
Each distro is a separate Linux system with its own `/etc/pam.d`, so install
and enroll once per distro.

**Can I use this on a machine without a TPM?**
Only with `--allow-unattested`, and only on a machine you control: without a
TPM there is no attestation, so the software key is accepted on trust and the
record says so.

## Prior art

This project would not exist without
[WSL-Hello-sudo](https://github.com/nullpo-head/WSL-Hello-sudo). `wsl-webauthn-pam` is an
independent rewrite, not a drop-in upgrade: the trust model, protocol,
installer, and credential store are all new.
The legacy project's structural weaknesses — unauthenticated enrollment of an
attacker-influenceable public key, a blind consent dialog, and a shell-based
installer — are what the WebAuthn ceremony, Linux-side verification, and the
pinned-bridge design fix.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Build and PR gates, fuzzing, the cross-compiled Windows bridge, and the
repository layout are covered in [CONTRIBUTING.md](CONTRIBUTING.md). Security
issues: [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
