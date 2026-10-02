# wsl-webauthn-pam

Authenticate `sudo`/`su` on WSL with the **Windows Hello WebAuthn platform
authenticator** (`webauthn.dll`, TPM-backed) — with **all cryptographic
verification performed on the Linux side**.

An independent rewrite of
[WSL-Hello-sudo](https://github.com/nullpo-head/WSL-Hello-sudo) that keeps the
reusable-Hello-gesture idea but replaces its `KeyCredentialManager` RSA-signing
oracle with a real WebAuthn / FIDO2 ceremony. The legacy PEM is never imported;
every user re-enrolls from scratch.

- Repository: **https://github.com/kirin-xiao/wsl-webauthn-pam**
- Releases (binaries + `SHA256SUMS`): <https://github.com/kirin-xiao/wsl-webauthn-pam/releases>
- License: [MIT](LICENSE)

---

## What it does

When a user runs `sudo` (or `su`), PAM calls `pam_wsl_webauthn.so`, which mints
a fresh 32-byte challenge, builds `clientDataJSON` with the pinned origin, and
loads the enrolled credential record. It spawns `WSLWebAuthnBridge.exe` as the
Windows user over WSL interop (framed stdio; no shell, no temp files); the bridge
runs `WebAuthNAuthenticatorGetAssertion` (`UV=REQUIRED`, platform) — the Windows
Hello prompt — and relays `{authenticatorData, signature, credentialId,
clientDataJSON echo}`, deciding nothing.

Linux-side root code then verifies the client data, `rpIdHash`, UP/UV,
credential-id binding, COSE key structure, and the signature over
`authenticatorData ‖ SHA-256(clientDataJSON)`, returning `PAM_SUCCESS` only if
every check passes; every other path is fail-closed.

Enrollment uses `WebAuthNAuthenticatorMakeCredential` (`attestation = DIRECT`,
`UV = REQUIRED`, platform attachment, non-resident credential) and verifies the
**attestation chain to a pinned Microsoft TPM root CA** before writing the trust
anchor.

---

## Security model

[SECURITY.md](SECURITY.md) is the canonical threat model and citations. In
short: enrollment verifies `tpm`/`packed` attestation to the pinned Microsoft
TPM Root CA 2014 with a Windows Hello AAGUID (unattested keys require
`--allow-unattested`); the RP ID and origin are compile-time constants
(`wsl-webauthn-pam`), asserted byte-for-byte on the Linux
side and never carried on the wire; and the module refuses to launch a bridge
whose SHA-256 differs from the digest pinned at enrollment. One root-owned
credential record is kept per Linux user; the signature counter is compared
(advisory on Windows Hello, which reports a constant counter), with challenge
freshness as the main gate. Windows shows `Passkey for
wsl-webauthn-pam` (the RP ID, not a friendly name); the
Linux-side `pam_conv` notice names the service and user — emitted even under
`PAM_SILENT` when a terminal is attached, silenceable with the `quiet` argument.

### Limits and accepted residual risk

- **Scoped to a pinned RP ID, not a browser-grade origin.** The guarantee is
  "bound to this pinned RP ID"; a native Win32 client is not origin-enforced the
  way a browser is.
- **A compromised Windows session can consent-phish.** It can initiate
  ceremonies (subject to user verification) and replace the bridge `.exe`, but
  cannot achieve silent root or forge an assertion for an enrolled credential.
- **Consent blinding is mitigated, not eliminated.** The OS cannot prove which
  process raised the ceremony.
- **Not a roaming authenticator.** Machine loss or reset means re-enrollment.
  Replaced or superseded Windows keys are orphaned but not removable (Windows
  exposes no API to enumerate or delete non-resident credentials).
- **No hardware side-channel defense.** TPM/platform behavior is trusted as-is;
  compromised Linux root is out of scope by definition.

### Enrollment and unattested keys

A first-ever enrollment for an RP ID can return an unattested (`fmt: "none"`)
credential. Under Strict the CLI discards it and re-runs one ceremony with a
fresh challenge; only a strictly verified credential is persisted, and if the
retry is still unattested, enrollment fails.

`--allow-unattested` admits `self` and `none` for TPM-less machines (recorded
`mode: "unattested-opt-in"`, `verified: false`); a `tpm`/`packed` attestation is
still recorded as `strict`. It is never a silent fallback — only use it on
machines you control.

---

## Requirements

- **Windows 10 1903+** (build 18362) with `webauthn.dll`. The client-data echo
  field is used when `ASSERTION.dwVersion >= 6` and absent otherwise.
- **WSL2 with interop enabled** (WSL1 untested), reachable from the process that
  runs PAM — systemd services may not see the session leader.
- **A Windows Hello gesture** (PIN, fingerprint, or face), TPM-backed for the
  default policy.
- **A Linux distro with PAM**, plus `pam-auth-update` for the packaged profile.
  `libpam0g-dev` is needed to build the module and run the `pam_start` tests
  (which require **libpam ≥ 1.4**).
- **Stable Rust** to build from source (pinned by `rust-toolchain.toml`;
  `rust-version = 1.88`, edition 2024 — 1.88 is required for let-chains).

---

## Installation

### Guided install

From a **release tarball**, `install.sh` sits next to the CLI:

```sh
tar xzf wsl-webauthn-pam-<version>-<arch>.tar.gz && cd wsl-webauthn-pam-<version>-<arch>
sudo ./install.sh                      # thin shim: exec sudo ./wsl-webauthn-pam install
```

From a **source checkout**, build first:

```sh
git clone https://github.com/kirin-xiao/wsl-webauthn-pam
cd wsl-webauthn-pam
make release                            # or: cargo build --release --locked
tar xzf build/wsl-webauthn-pam-<version>-<arch>.tar.gz -C build
sudo ./build/wsl-webauthn-pam-<version>-<arch>/install.sh
```

The shim runs the CLI from its own directory, so invoke it from inside the
unpacked/staged directory. `install` copies the CLI to
`/usr/local/bin/wsl-webauthn-pam`, so afterwards the short command works from any
directory and survives deleting the unpacked tree. If `/usr/local/bin` is not on
your `PATH`, use the absolute path or add it.

`install` (running as root) will:

1. Locate the Windows mount root from `/etc/wsl.conf` (`/mnt/c` by default;
   override with `--win-mnt`), resolve `%LOCALAPPDATA%` via `cmd.exe`, copy the
   bridge there, and record its SHA-256 pin.
2. Install `pam_wsl_webauthn.so` into the module directory (detected via
   `pam_unix.so`, or set with `--module-dir`; the `.so` and bridge are found in
   the release layout, `target/`, or the current directory, overridable with
   `--artifact-dir <DIR>` or `$WSL_WEBAUTHN_ARTIFACTS`).
3. Write `/etc/wsl_webauthn/config` (`0600` root), create
   `/etc/wsl_webauthn/credentials/` (`0700` root), and install the
   `pam-auth-update` profile to `/usr/share/pam-configs/wsl-webauthn`
   (`Default: no` — never silently enabled).
4. Install the CLI itself to `/usr/local/bin/wsl-webauthn-pam` (`0755` root).
5. Offer to remove the legacy `wsl-hello` profile and rewrite stale
   `pam_wsl_hello` references in `/etc/pam.d/*` (with confirmation and backup),
   never importing the legacy PEM.
6. Offer to enable the profile now (default no), print the lockout warning, and
   offer to enroll the invoking user. `--skip-enroll` stops before enrollment;
   `--yes` answers yes to every prompt; `--dry-run` previews without writing;
   `--non-interactive` never reads stdin.

If `pam-auth-update` is missing (non-Debian), `install` prints manual
`/etc/pam.d` instructions. Then enroll once and enable the profile:

```sh
sudo wsl-webauthn-pam enroll          # run as the user you want to enroll
sudo pam-auth-update                  # select "WSL WebAuthn authentication"
# or non-interactively:
sudo pam-auth-update --enable wsl-webauthn
```

`enroll` prints a short notice before the ceremony and a line when the second dialog
appears. The Windows Hello dialog can open behind the terminal, and the save dialog may
be followed by a PIN prompt; the bridge makes a best-effort attempt to raise it (or
flash its taskbar button). See Troubleshooting.

### Manual installation (no installer)

1. Copy `pam_wsl_webauthn.so` to the PAM security directory: e.g.
   `/usr/lib/x86_64-linux-gnu/security/` (Debian/Ubuntu) or
   `/usr/lib64/security/` (RHEL/Fedora).
2. Copy the bridge onto the Windows side (any path; the config pins it).
3. Write `/etc/wsl_webauthn/config` as root, mode `0600`:

   ```toml
   bridge_path = "/mnt/c/Users/<you>/AppData/Local/Programs/wsl-webauthn-pam/WSLWebAuthnBridge.exe"
   win_mnt     = "/mnt/c"
   # timeout_secs = 60        # optional override
   ```

4. `sudo install -d -m 0700 -o root -g root /etc/wsl_webauthn/credentials`
5. Enroll: `sudo wsl-webauthn-pam enroll`
6. Add a line to the relevant service (e.g. `/etc/pam.d/sudo`):

   ```
   auth sufficient pam_wsl_webauthn.so
   ```

   Or use the profile as shown above. `[success=end default=ignore]` is the
   `pam-auth-update` idiom (expanded to a computed jump); `end` is not a literal
   PAM action.

### The lockout warning

**Keep at least one working `sudo`/`su` path that does not go through this
module.** The module is **fail-closed**: any provisioning error (missing config,
unreadable store, bridge transport failure, interop unavailable, pin mismatch,
timeout) denies Hello for that PAM service and only falls through to the *next*
method when the stack says so (under `sufficient`, or under
`[success=end default=ignore]`). Keep a root shell or the local password
available, and test with a non-critical service first.

**If you do get locked out**, WSL has no virtual console (`Ctrl-Alt-F2`) to fall
back to, so open a root shell from the Windows side:

```powershell
wsl.exe -d <distro> -u root
```

```sh
# then, inside that root shell:
pam-auth-update --remove wsl-webauthn     # or: edit /etc/pam.d/* by hand
```

On a non-WSL Linux host, switch to another TTY/console (`Ctrl-Alt-F2`, or
serial/SSH) and remove the module line.

---

## Using the CLI

`wsl-webauthn-pam <COMMAND> [OPTIONS]`

| Command | Purpose | Options |
|---|---|---|
| `enroll` | Enroll a Windows Hello credential (root) | `--replace`; `--allow-unattested`; `--user <NAME>` (default `SUDO_USER` or current); `--bridge <PATH>`; `--win-mnt <PATH>` |
| `unregister` | Remove one user's credential record (root, per-user only) | `--user <NAME>`; `--yes`, `-y` |
| `probe` | Report interop / Hello availability and the bridge pin | `--bridge <PATH>`; `--win-mnt <PATH>` |
| `status` | List enrolled users and the config summary | `--user <NAME>` for one full record; config and records need root |
| `verify` | Self-test the crypto stack against a synthetic ceremony | — |
| `install` | Provision the bridge, config, PAM module, profile and CLI (root) | `--artifact-dir <DIR>`; `--module-dir <DIR>`; `--win-mnt <PATH>`; `--allow-unattested`; `--skip-enroll`; `--dry-run`; `--yes`, `-y`; `--non-interactive` |
| `uninstall` | Remove a credential or all components (root) | `--user <NAME>`; `--all` (also removes the CLI at `/usr/local/bin`); `--module-dir <DIR>`; `--win-mnt <PATH>`; `--yes`, `-y`; `--non-interactive` |

`--bridge` and `--win-mnt` fall back to the config, then (`--win-mnt`) to
`/mnt/c`. `--bridge` only supplies the bridge path; it does not initialize the
store, so `install` must have run first (otherwise `enroll` fails with
`error[not-found]` and guidance to run `install`). `--artifact-dir` falls back to
`$WSL_WEBAUTHN_ARTIFACTS` or the current directory. A value beginning with `-`
must use the `--flag=value` form; in the `--flag value` form a `-`-prefixed token
is read as the next flag.

Exit codes: `0` success; `1` operational failure (in `status` list mode this
includes unreadable/corrupt credential records — re-run as root); `2` usage
error. `enroll`, `unregister`, `install`, and `uninstall` require root; `probe`
and `verify` run unprivileged; `status` runs unprivileged but prints
`Config: unavailable (…); re-run as root` for the root-owned config and store.

---

## Building from source

```sh
cargo build --release --workspace --locked
```

Linking the `cdylib` PAM module against `libpam0g-dev` is the only build step
that needs PAM development headers (Debian/Ubuntu:
`sudo apt-get install -y libpam0g-dev`).

### The Windows bridge

Build it on Windows with **`cargo.exe`** (native MSVC — what CI ships), or
cross-compile on Linux with the `x86_64-pc-windows-gnu` target (no admin
needed):

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release -p wsl-webauthn-bridge --target x86_64-pc-windows-gnu
```

`make bridge` picks `cargo.exe` when it is on `PATH` and otherwise falls back to
the GNU cross target.

### Make targets

| Target | What it does |
|---|---|
| `make` / `make all` | Linux module + CLI (release) and the Windows bridge |
| `make bridge` | Bridge only (`cargo.exe`, else the host-matched GNU target) |
| `make test` | `cargo test --workspace --locked` |
| `make check` | `fmt` + `clippy` + `test` + `deny` + `machete` |
| `make machete` | `cargo-machete`: fail on manifest dependencies no source uses |
| `make pam-profile` | Validate the `pam-config` profile and its `pam-auth-update` expansion |
| `make release` | Assemble `build/wsl-webauthn-pam-<version>-<arch>.tar.gz` + `build/SHA256SUMS` |

### Release artifact layout

Tagging `v*` triggers the release workflow: one tarball per architecture
containing `pam_wsl_webauthn.so`, the `wsl-webauthn-pam` CLI,
`WSLWebAuthnBridge.exe`, `install.sh`, `pam-config`, and `README.md`, plus a
top-level `SHA256SUMS` covering all tarballs. `make release` reproduces the
layout locally under `build/` (build-host arch only).

Published on the [releases page](https://github.com/kirin-xiao/wsl-webauthn-pam/releases);
verify downloads against `SHA256SUMS`. CI releases also carry a signed
build-provenance attestation: verify with
`gh attestation verify <file> -R kirin-xiao/wsl-webauthn-pam`.

---

## Troubleshooting

**The module never seems to trigger, and `sudo` just asks for a password.**
The module writes nothing to stdout; its only user-visible output is a one-line action
cue sent through the PAM conversation. Under `PAM_SILENT` (as `sudo` sets) the cue
requires a controlling terminal, and the `quiet` module argument suppresses it
everywhere. Check the authentication log: `journalctl -t pam_wsl_webauthn` or your
distro's `auth.log` (syslog facility `authpriv`). Add the `debug` module argument for
`LOG_DEBUG` detail (never secrets).

**The Windows Hello prompt appears in the background.**
The bridge passes the current foreground window as the prompt's owner and makes a
best-effort attempt to raise the dialog when it appears (falling back to flashing its
taskbar button). WSL focus handling can still leave it behind, especially when another
app (e.g. a browser) is actively in front; watch the taskbar for the Windows Security
icon and click it.
The CLI announces the second (PIN) dialog and the module names the service, so you know
a prompt is expected; type the PIN into the **dialog**, never the terminal. Because
`sudo` authenticates in silent mode, the module emits its cue only when a terminal is
attached; add the `quiet` module argument to silence it entirely.

**Interop is unavailable.**
WSL interop needs the `binfmt_misc` `WSLInterop` registration to be `enabled`.
Systemd services often cannot reach the session leader, so Hello may work from an
interactive shell but not from a service. The runner fails fast (no hang) when
the registration is missing or disabled.

**The prompt timed out.**
The bridge passes an advisory 55 s timeout to `webauthn.dll` *and* runs its own
watchdog that calls `WebAuthNCancelCurrentOperation` at 55 s. The Linux runner
enforces a hard 60 s deadline for the whole child, then `SIGKILL`s the shim and
best-effort `taskkill.exe`s the reported Windows PID within a 5 s budget, so
total wall time can reach about `deadline + 5 s`. Override with the
`timeout=<secs>` module argument or `timeout_secs` in the config. The module
argument is clamped to `1..=600` seconds; a non-numeric or out-of-range value is
logged at `LOG_ERR` and ignored. A watchdog fire is reported as `timeout`; a
genuine user cancel remains `user_cancelled`.

**The bridge pin fails after I replaced the `.exe`.**
That is the pin doing its job. The pin is always enforced and there is no module
argument to disable it: re-enroll, or, if you intend to trust the new binary,
re-run `enroll --replace`.

---

## FAQ

**Why WebAuthn instead of the old `KeyCredentialManager`?**
`KeyCredentialManager` gives an RSA signing oracle with an unattested,
attacker-influenceable public key and a blind, fixed prompt. WebAuthn gives
attestation to a pinned TPM root, RP-scoping, a focused consent-bearing prompt,
and no signing oracle — the key signs a WebAuthn assertion whose contents are
fully verified.

**Is my old WSL-Hello-sudo configuration migrated?**
**No.** Fresh enrollment is required and the legacy PEM is **never imported**.
The installer detects a legacy install, warns, and offers to rewrite
`/etc/pam.d/*` references from `pam_wsl_hello` to `pam_wsl_webauthn.so` **with
confirmation and a backup** before removing the old module.

**Multi-user semantics: can several Linux users share one Windows account?**
Yes, and that is the normal WSL case. Each Linux user has exactly **one
credential record** of their own, bound for audit to the Windows account/SID
that enrolled it. There is no runtime SID check: interop always runs as the
distro-session owner, so the "wrong" Windows account simply yields no usable
credential.

**Can I use this on a machine without a TPM?**
Only with `--allow-unattested`, and only on a machine you control. Without a TPM
there is no attestation, so the software key is accepted on trust (see
[Enrollment and unattested keys](#enrollment-and-unattested-keys)).

**Does it modify `sudoers`?**
No. It works through the PAM stack; enabling it means adding the module (or the
`pam-auth-update` profile) to the relevant PAM service such as
`/etc/pam.d/sudo`.

---

## Repository layout

| Path | Purpose |
|---|---|
| `crates/wsl-webauthn-protocol` | Shared constants + wire types + framing (no OS deps) |
| `crates/wsl-webauthn-verifier` | Security core: pure-Rust CBOR/COSE + assertion/attestation verification |
| `crates/wsl-webauthn-store` | Root-owned, symlink-hardened credential store and config parsing |
| `crates/wsl-webauthn-runner` | Spawns the bridge over WSL interop with bounded IO + deadlines |
| `crates/wsl-webauthn-bridge` | `WSLWebAuthnBridge.exe` (Windows) |
| `crates/wsl-webauthn-pam` | `pam_wsl_webauthn.so` (Linux `cdylib`) |
| `crates/wsl-webauthn-cli` | `wsl-webauthn-pam` (`enroll`/`probe`/`install`/…) |
| `pam-config` | The `pam-auth-update` profile (`Default: no`) |
| `SPIKE.md` | Empirical findings from the real Windows host |
| `tests/vectors` | Vector provenance (no binary third-party vectors committed) |

---

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check           # requires: cargo install cargo-deny
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
