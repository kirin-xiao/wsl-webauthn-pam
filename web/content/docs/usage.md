+++
title = "Usage"
description = "The CLI commands, PAM module arguments, config file, and logs."
weight = 4
+++

`wsl-webauthn-pam <COMMAND> [OPTIONS]`. `-h` prints the full usage, and
`-V`/`--version` prints the version. Values beginning with `-` need
`--flag=value`.

## Commands

| Command | What it does | Root? |
|---|---|---|
| `install` | Provision the bridge, config, module, profile, and CLI | yes |
| `enroll` | Enroll a user, then enable the profile (`--user <NAME>`, `--replace`) | yes |
| `unregister` | Remove one user's credential (`--user <NAME>`) | yes |
| `uninstall` | Remove a credential or everything (`--all`) | yes |
| `probe` | Report interop and Hello availability; check the bridge pin | root for the pin |
| `status` | List users and the config summary | root for records |
| `verify` | Self-test the crypto stack | no |

The default target is `SUDO_USER`, falling back to the current user. `enroll
--replace` overwrites an existing record and re-pins the bridge after an upgrade;
`--no-enable` enrolls without changing `pam-auth-update`.

## Output control

`enroll` and `install` print actionable status by default; `-v` adds each step
and the resolved config, while `--quiet` suppresses non-error output. They are
mutually exclusive.

<details>
<summary>Self-test output</summary>

```console
$ wsl-webauthn-pam verify
verify: PASS
  attestation: packed / SelfAttested
  assertion:   verified (ES256)
  negative control: tampered signature rejected
  negative control: disallowed AAGUID rejected
```

</details>

## PAM module arguments

| Argument | Effect |
|---|---|
| `quiet` | Never emit the terminal action cue |
| `debug` | Verbose logging (never secrets) |
| `timeout=<secs>` | Whole-ceremony deadline; a value outside `1..=600` is logged and ignored |

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
| `timeout_secs` | Global ceremony deadline, overridden by `timeout=` | 60 |

`install` writes `bridge_path` and `win_mnt`; add `timeout_secs` by hand, or set
it per service with the module argument.

## Logs

The module writes nothing to stdout during authentication. Its audit trail goes
to `authpriv`: `journalctl -t pam_wsl_webauthn` on systemd, or the distro's
`auth.log`. `debug` adds detail without logging secrets.

Operational failures print `error[<token>]: <message>` on stderr; the
[troubleshooting table](@/docs/troubleshooting.md#error-tokens) lists every
token.
