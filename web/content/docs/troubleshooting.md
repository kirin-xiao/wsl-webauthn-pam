+++
title = "Troubleshooting"
description = "When sudo asks for a password, the prompt hides behind the terminal, interop is unavailable, or the bridge pin fails."
weight = 5
+++

Falling back to your password is designed behaviour.

## `sudo` just asks for a password — the module never seems to trigger

**Symptom.** No Windows Hello prompt, no terminal cue, just the password.

**Cause.** No credential for this user, or the profile is not enabled.

**Fix.** Check the credential, then the log:

```sh
sudo wsl-webauthn-pam status
journalctl -t pam_wsl_webauthn
```

or the distro's `auth.log`. The `debug` argument adds detail.

## `install` finished but `sudo` still asks for a password

**Symptom.** Provisioning succeeded; authentication still falls through.

**Cause.** No credential, or the profile is not enabled.

**Fix.** Enable the profile and enroll:

```sh
sudo pam-auth-update --enable wsl-webauthn
sudo wsl-webauthn-pam enroll
```

`install` and `enroll` enable the profile only after enrollment succeeds.

## The Windows prompt appears behind other windows

**Symptom.** `sudo` hangs, then falls back to the password; a Hello prompt
appears later.

**Cause.** The dialog is a Windows window and can open behind the terminal.

**Fix.** Watch the taskbar for the Windows Security icon, and type the PIN into
the **dialog**, never the terminal. The cue names the service and user.

## `interop-unavailable` — the bridge never starts

**Symptom.** `error[interop-unavailable]`, immediately, without a Hello prompt.

**Cause.** WSL interop is unavailable to this process; systemd services often
cannot reach the session leader.

**Fix.** Check interop from the same shell (`cmd.exe /c echo ok`) and
authenticate interactively; the runner fails fast.

## The prompt times out

**Symptom.** About a minute passes, then the password prompt.

**Cause.** The default deadline is 60 s.

**Fix.** Override it with the `timeout=<secs>` module argument or `timeout_secs`
in `/etc/wsl_webauthn/config`. An expiry is `timeout`; *cancel* is
`user_cancelled`; both fall through to the password.

## `error[bridge-integrity]` — the bridge pin fails after I replaced the `.exe`

**Symptom.** Worked, then stopped after an upgrade or manual replacement.

**Cause.** The pin is working: the `.exe` is checked against the enrollment hash.

**Fix.** Re-enroll to trust the new binary:

```sh
sudo wsl-webauthn-pam enroll --replace
```

The pin is always enforced; upgrades change the `.exe` bytes, so re-enroll.

## Locked out, or about to be

Keep a second shell open while testing. WSL has no virtual console; a
Windows-side root shell bypasses PAM:

```powershell
wsl.exe -d <distro> -u root
```

```sh
pam-auth-update --remove wsl-webauthn   # or: edit /etc/pam.d/* by hand
```

The full warning is on the
[install page](@/docs/install.md#don-t-lock-yourself-out).

## Where the logs are

| Source | Where |
|---|---|
| PAM module | `journalctl -t pam_wsl_webauthn`, facility `authpriv`; the distro's `auth.log` on a non-systemd host |
| Installer / CLI | stderr of the command you ran; `-v` adds the config and each step |
| Bridge | nothing; the runner reports a stable error token |

It never logs a secret or writes to stdout during authentication.

## Error tokens

Operational failures print `error[<token>]: <message>`; the token is stable, the
message is not.

| Token | Meaning |
|---|---|
| `config-missing` | `/etc/wsl_webauthn/config` is absent — run `install` |
| `config-invalid` | The config is unparsable or over its size cap |
| `not-found` | No credential record for the user |
| `already-exists` | A record exists — re-enroll with `--replace` |
| `record-corrupt` | A record fails validation |
| `invalid-username` | The username cannot name a record |
| `symlink` | A path component is a symlink; refused |
| `not-regular-file` | A required path is not a regular file |
| `insecure-store` | Wrong owner or mode on the store, record, or config |
| `too-large` | A record, config, or frame exceeds its cap |
| `path-changed` | A file was swapped between `lstat` and `open` |
| `record-changed` | A conditional write found the record changed |
| `record-user-mismatch` | The record belongs to a different user |
| `encode` | Serializing a record failed |
| `io` | An operating-system error |
| `bridge-missing` | The `.exe` is not at the configured `bridge_path` |
| `interop-unavailable` | WSL interop is not available to this process |
| `spawn` | Interop failed to start the bridge |
| `bridge-failed` | The bridge returned `ok:false` |
| `bridge-integrity` | The `.exe` hash differs from the pin — re-enroll with `--replace` |
| `transport` | Framing, length, truncation, or trailing bytes |
| `timeout` | The ceremony deadline expired |
| `verify-rejected` | The verifier rejected the assertion |
| `error` | A failure with no more specific token |

Usage errors print a bare `error:` and exit `2`.
