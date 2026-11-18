+++
title = "Usage"
description = "The CLI commands, PAM module arguments, config file, and the stable error tokens scripts can check."
weight = 4
+++

`wsl-webauthn-pam <COMMAND> [OPTIONS]`. The installer puts the CLI at
`/usr/local/bin/wsl-webauthn-pam`; a package install also has `/usr/bin`, which
the `/usr/local/bin` copy shadows on `PATH`. `-h` prints the full usage, and
`-V`/`--version` prints the version.

## Commands

| Command | What it does | Root? | Key options |
|---|---|---|---|
| `install` | Provision the bridge, config, module, profile, and CLI | yes | `--skip-enroll`, `--dry-run`, `--yes`/`-y`, `--non-interactive`, `--allow-unattested`, `--artifact-dir`, `--module-dir`, `--win-mnt`, `-v`/`--verbose`, `--quiet`/`-q` |
| `enroll` | Run the Windows Hello ceremony for one Linux user, then enable the profile | yes | `--replace`, `--allow-unattested`, `--no-enable`, `--user <NAME>`, `--bridge`, `--win-mnt`, `-v`/`--verbose`, `--quiet`/`-q` |
| `unregister` | Remove one user's credential record | yes | `--user <NAME>`, `--yes`/`-y` |
| `uninstall` | Remove a credential or all components | yes | `--user <NAME>` or `--all` (also removes the CLI), `--module-dir`, `--win-mnt`, `--yes`/`-y`, `--non-interactive` |
| `probe` | Report interop and Hello availability, check the bridge pin | no (root for the pin) | `--bridge`, `--win-mnt` |
| `status` | List enrolled users and the config summary | no (root for the records) | `--user <NAME>` for one full record |
| `verify` | Self-test the crypto stack against a synthetic ceremony | no | — |

The default target user for `enroll`, `unregister`, and `uninstall --user` is
`SUDO_USER`, falling back to the current user. `--artifact-dir` tells `install`
where to find `pam_wsl_webauthn.so` and `WSLWebAuthnBridge.exe`; `--module-dir`
overrides the detected PAM security directory.

A value that begins with `-` must use the `--flag=value` form; in the
`--flag value` form a `-`-prefixed token is read as the next flag.

## Output control

`enroll` and `install` print only actionable status by default.

| Flag | Effect |
|---|---|
| `-v`, `--verbose` | Adds the resolved config and each provisioning step |
| `--quiet`, `-q` | Suppresses all non-error status output |
| (neither) | Default, actionable status only |

The two flags are mutually exclusive and are accepted only by `enroll` and
`install`. `probe`, `status`, `verify`, `unregister`, `uninstall`, and
`--dry-run` always print their full output. None of these flags changes a stable
error token or an exit code.

## Self-test output

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

`probe` is read-only.

## PAM module arguments

| Argument | Effect |
|---|---|
| `quiet` | Never emit the terminal action cue |
| `debug` | Verbose logging (never secrets) |
| `timeout=<secs>` | Whole-ceremony deadline; a value outside `1..=600` or non-numeric is logged and ignored |

```text
auth sufficient pam_wsl_webauthn.so quiet timeout=120
```

## Config file

`/etc/wsl_webauthn/config` is a plain TOML file, root-owned and mode `0600`,
written by `install`:

| Key | Meaning | Default when absent |
|---|---|---|
| `bridge_path` | Absolute path to `WSLWebAuthnBridge.exe` | none — required |
| `win_mnt` | Windows mount root the runner spawns in | `/mnt/c` |
| `timeout_secs` | Global ceremony deadline, overridden by the `timeout=` module argument | 60 |

`install` writes `bridge_path` and `win_mnt`; `timeout_secs` is added by hand.
The same timeout can be set per service with the module argument instead. The
`win_mnt` value is also honoured from the `/etc/wsl.conf` `[automount] root=`
setting when the installer resolves a default.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Operational failure. In `status` list mode this includes one or more unreadable or corrupt credential records; re-run as root to read them. |
| `2` | Usage error: missing values, unknown or empty flags, misplaced flags |

## Stable error tokens

Operational failures print `error[<token>]: <message>` on stderr. Usage errors
print a bare `error:`. Scripts can branch on the bracketed token instead of
parsing prose; the tokens do not change when messages are reworded.

```text
config-missing, config-invalid, not-found, already-exists, record-corrupt,
invalid-username, symlink, not-regular-file, insecure-store, too-large,
path-changed, record-changed, record-user-mismatch, encode, io,
bridge-missing, interop-unavailable, spawn, bridge-failed, bridge-integrity,
transport, timeout, verify-rejected, error
```

What each token means, and what to do about it, is on the
[troubleshooting page](@/docs/troubleshooting.md#error-tokens).

## Manual provisioning flags

`install --skip-enroll` leaves the profile disabled and prints the recovery
commands; `--dry-run` resolves and prints the plan without writing anything;
`--yes` answers every prompt; `--non-interactive` never reads stdin and takes
the question defaults. A skipped, declined, or failed enrollment always leaves
the profile disabled — the profile is enabled only after a credential is
verified.

`enroll --no-enable` enrolls without touching `pam-auth-update`, which is what
the manual installation path uses; `enroll --replace` overwrites an existing
record and re-pins the bridge, and is required after an upgrade changes the
`.exe` bytes.

## Logs and verbosity at authentication time

The PAM module writes nothing to stdout as part of an authentication. Its audit
trail goes to `authpriv` — `journalctl -t pam_wsl_webauthn` on a systemd distro,
or the distro's `auth.log`. The `debug` module argument adds detail without ever
logging a secret.
