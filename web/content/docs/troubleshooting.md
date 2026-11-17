+++
title = "Troubleshooting"
description = "When sudo asks for a password, the prompt hides behind the terminal, interop is unavailable, or the bridge pin fails."
weight = 5
+++

Most reports are one of six cases. Each entry below is symptom, cause, fix.

Before anything else: `sudo` falling back to your password is the designed
behaviour, not a failure. The module adds no new way to lose password access
under the shipped profile.

## `sudo` just asks for a password — the module never seems to trigger

**Symptom.** No Windows Hello prompt, no terminal cue, just the password.

**Cause.** Either there is no credential for this Linux user, or the profile is
not enabled for the service.

**Fix.** Check the credential first, then the log:

```sh
sudo wsl-webauthn-pam status
journalctl -t pam_wsl_webauthn
```

or your distro's `auth.log` (facility `authpriv`). The `debug` module argument
adds detail. The module writes nothing to stdout.

## `install` finished but `sudo` still asks for a password

**Symptom.** Provisioning reported success; authentication still falls through.

**Cause.** Either the invoking user has no credential — visible in `status` — or
the profile is not enabled.

**Fix.** Enable the profile and enroll:

```sh
sudo pam-auth-update --enable wsl-webauthn
sudo wsl-webauthn-pam enroll
```

`install` and `enroll` enable the profile automatically **only after enrollment
succeeds**. A skipped, declined, or failed enrollment deliberately leaves it
disabled.

## The Windows prompt appears behind other windows

**Symptom.** `sudo` seems to hang, then falls back to the password. Later you
notice a Hello prompt.

**Cause.** The dialog is a Windows window; it can open behind the terminal.

**Fix.** Watch the taskbar for the Windows Security icon, and type the PIN into
the **dialog**, never the terminal. The terminal cue on the Linux side names the
service and the user so you know a prompt is waiting.

## `interop-unavailable` — the bridge never starts

**Symptom.** `error[interop-unavailable]`, immediately, without a Hello prompt.

**Cause.** WSL interop needs the `WSLInterop` `binfmt_misc` registration
enabled. systemd services often cannot reach the interop session leader, so
Hello can work from an interactive shell but not from a service.

**Fix.** Check that interop works at all from the same shell (for example
`cmd.exe /c echo ok`), and run the authentication from an interactive session.
The runner fails fast rather than hanging.

## The prompt times out

**Symptom.** About a minute passes, then the password prompt.

**Cause.** The default deadline is 60 s: a 55 s advisory in the dialog plus a
hard Linux-side deadline, with up to ~5 s of cleanup.

**Fix.** Override it with the `timeout=<secs>` module argument or `timeout_secs`
in `/etc/wsl_webauthn/config`. A watchdog expiry is reported as `timeout`;
pressing *cancel* in the dialog is `user_cancelled`. Both fall through to the
password.

## `error[bridge-integrity]` — the bridge pin fails after I replaced the `.exe`

**Symptom.** Authentication worked, then stopped after an upgrade or a manual
file replacement.

**Cause.** That is the pin doing its job. The bridge `.exe` is SHA-256 checked on
every launch, against the hash recorded at enrollment.

**Fix.** Re-enroll to trust the new binary:

```sh
sudo wsl-webauthn-pam enroll --replace
```

The pin is always enforced; there is no module argument to disable it. Upgrading
in place also changes the `.exe` bytes (it carries version metadata), so upgrades
re-enroll.

## Locked out, or about to be

Keep a second shell open while testing. WSL has no virtual console, but a
Windows-side root shell bypasses PAM entirely:

```powershell
wsl.exe -d <distro> -u root
```

```sh
pam-auth-update --remove wsl-webauthn   # or: edit /etc/pam.d/* by hand
```

The full warning and the fail-through profile are on the
[install page](@/docs/install.md#don-t-lock-yourself-out).

## Where the logs are

| Source | Where |
|---|---|
| PAM module | `journalctl -t pam_wsl_webauthn`, facility `authpriv`; the distro's `auth.log` on a non-systemd host |
| Installer / CLI | stderr of the command you ran; `-v` adds the resolved config and each step for `install`/`enroll` |
| Bridge | nothing on the Linux side; the runner reports the failure as a stable token |

The module never logs a secret and never writes to stdout as part of an
authentication.

## Error tokens

Operational failures print `error[<token>]: <message>`. The token is stable;
the message is not.

| Token | Meaning |
|---|---|
| `config-missing` | `/etc/wsl_webauthn/config` is absent — provision with `install` |
| `config-invalid` | The config exists but cannot be parsed or is over its size cap |
| `not-found` | No credential record for the user |
| `already-exists` | A record already exists — re-enroll with `--replace` |
| `record-corrupt` | A record fails validation (unknown mode, bad digest, malformed TOML) |
| `invalid-username` | The username cannot name a record |
| `symlink` | A path component is a symlink, which the store refuses |
| `not-regular-file` | A path that must be a regular file is not |
| `insecure-store` | Wrong owner or mode on the store, a record, or the config |
| `too-large` | A record, config, or wire frame exceeds its cap |
| `path-changed` | A file was swapped between the `lstat` and the `open` |
| `record-changed` | A conditional write found the record changed since load |
| `record-user-mismatch` | The record belongs to a different user |
| `encode` | Serializing a record failed |
| `io` | An operating-system error |
| `bridge-missing` | The `.exe` is not at the configured `bridge_path` |
| `interop-unavailable` | WSL interop is not available to this process |
| `spawn` | Interop failed to start the bridge |
| `bridge-failed` | The bridge returned `ok:false` |
| `bridge-integrity` | The `.exe` hash differs from the pin recorded at enrollment — re-enroll with `--replace` |
| `transport` | Framing, length, truncation, or trailing bytes |
| `timeout` | The ceremony deadline expired |
| `verify-rejected` | The verifier rejected the assertion |
| `error` | A failure with no more specific token |

Usage errors print a bare `error:` and exit `2`. Exit codes and the full token
list are on the [usage page](@/docs/usage.md#exit-codes).
