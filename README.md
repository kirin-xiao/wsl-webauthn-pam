# wsl-webauthn-pam

Authenticate `sudo`/`su` on WSL with the **Windows Hello WebAuthn platform
authenticator** (`webauthn.dll`, TPM-backed) — with **all cryptographic
verification performed on the Linux side**.

`wsl-webauthn-pam` is a clean-room rewrite of the classic
[WSL-Hello-sudo](https://github.com/nullpo-head/WSL-Hello-sudo) that replaces its
`KeyCredentialManager` RSA-signing oracle with a real WebAuthn / FIDO2 ceremony.

- Repository: **https://github.com/kirin-xiao/wsl-webauthn-pam**
- Releases (binaries + `SHA256SUMS`): <https://github.com/kirin-xiao/wsl-webauthn-pam/releases>
- License: [MIT](LICENSE)

> **Relationship to WSL-Hello-sudo.** This is an independent modern rewrite, not
> a fork. It keeps the same *idea* (reuse the Windows Hello gesture for Linux
> privilege escalation) but **not** the legacy trust model. The legacy PEM public
> key is never read, imported, or migrated — every user re-enrolls from scratch.
> The original project lives at <https://github.com/nullpo-head/WSL-Hello-sudo>.

---

## What it does

When a user runs `sudo` (or `su`), the Linux PAM stack calls
`pam_wsl_webauthn.so`. That module mints a fresh challenge, asks a small Windows
executable (`WSLWebAuthnBridge.exe`) to run a Windows Hello WebAuthn ceremony
over WSL interop, and then verifies the returned assertion **entirely on the
Linux side** before returning `PAM_SUCCESS`. The bridge never decides anything:
it triggers the platform prompt and relays bytes.

This moves the mechanism from *"a Hello gesture happened at time T"*
(convenience authentication) toward *strong, scope-bound authentication*: the
credential is attested, RP-scoped, and every signature is checked by root-owned
Linux code.

---

## How it works

```
  sudo / su
      │  PAM stack
      ▼
  pam_wsl_webauthn.so            (runs as root)
      │  1. mint a fresh 32-byte challenge (OsRng)
      │  2. build clientDataJSON{type, challenge, origin}  (origin = pinned ORIGIN)
      │  3. load the enrolled credential record (credential id + COSE public key)
      │  4. optional pam_conv pre-prompt: names the service + Linux user
      │
      │  WSL interop (framed stdio: 4-byte LE length + JSON, no shell, no temp files)
      ▼
  WSLWebAuthnBridge.exe          (runs as the Windows user, holds NO trust)
      │  5. WebAuthNAuthenticatorGetAssertion(UV=REQUIRED, platform, allow-list)
      │       → Windows Hello "Sign in with a passkey" prompt
      │  6. relay {authenticatorData, signature, credentialId, clientDataJSON echo}
      │
      ▼  bytes back over the pipe
  pam_wsl_webauthn.so            (root) — the ONLY place a trust decision is made:
      │  • clientDataJSON: type == "webauthn.get", challenge == ours, origin == pinned
      │  • rpIdHash == SHA-256(RP_ID)         (authenticatorData)
      │  • UP = 1 and UV = 1                  (user *verification*, not presence)
      │  • credential id returned == enrolled credential id
      │  • COSE alg ∈ {-7, -257, -8}; key structure + point-on-curve validated
      │  • signature over authenticatorData ‖ SHA-256(clientDataJSON)
      │      verified with the enrolled public key (ES256 / RS256 / EdDSA)
      │  • signature-counter clone signal checked (§7.2 step 22)
      └─ PAM_SUCCESS only if every check passes; every other path is fail-closed
```

**Enrollment** uses the same pair with `WebAuthNAuthenticatorMakeCredential`
(`attestation = DIRECT`, `UV = REQUIRED`, platform attachment, non-resident
credential) and additionally verifies the **attestation chain to a pinned
Microsoft TPM root CA** on the Linux side before writing the trust anchor.

Everything security-relevant happens in `wsl-webauthn-verifier` (pure Rust, no
OS dependencies, no `unsafe`, no panic on any input) and in the PAM module.
`wsl-webauthn-protocol` pins the constants that both sides share and that are
never carried on the wire.

---

## Security model

This is the honest version. Read it before you enable the module.

### What is attested (proven at enrollment)

Under the default **Strict** policy, enrollment verifies that the public key
really belongs to a genuine, TPM-backed Windows Hello credential:

- Attestation format `tpm` (W3C WebAuthn §8.3 — what Windows Hello actually
  emits) is fully verified: `ver == "2.0"`, the `certInfo`/`pubArea` structures
  are parsed, `extraData == H(authData ‖ clientDataHash)`, the attested `name`
  is recomputed from the `pubArea`, and the AIK signature over `certInfo` is
  checked with the leaf key.
- The certificate chain (`x5c`) is checked to the pinned
  **Microsoft TPM Root Certificate Authority 2014**, SHA-256
  `87:0C:7A:35:CE:AB:3D:59:97:9F:2C:6A:52:40:42:D4:04:CB:71:51:80:04:35:09:25:FB:2C:ED:79:A9:99:DA`.
  The bundled public root is trusted **only** after its bytes hash to that pin.
- The AAGUID in `authenticatorData` must be one of the two Windows Hello
  AAGUIDs (`08987058-cadc-4b81-b6e1-30de50dcbe96` software TPM,
  `9ddd1817-af5a-4672-a2b9-3e3dd95000a9` hardware TPM).
- `packed`/AttCA attestation chains are also accepted (same root + leaf rules:
  v3, `CA=false`, `OU="Authenticator Attestation"`, `id-fido-gen-ce-aaguid`
  matching the authData AAGUID).

If **both** default-policy ceremonies produce an unattested credential, the key
is refused. There is **no silent fallback to an unattested key, ever**.

### What is bound

- **RP ID / origin.** Both are compile-time constants:
  `io.github.kirin-xiao.wsl-webauthn-pam`. The origin is pinned *equal to* the RP
  ID because this is a native client with no browser origin. The wire format
  never carries them, and both are asserted byte-for-byte on the Linux side.
  Changing either requires a rebuild **and** re-enrollment.
- **Linux user.** One credential record per Linux user
  (`/etc/wsl_webauthn/credentials/<user>.json`), written by the enrollment CLI
  as root. The record's `linux_user` must match the account being authenticated.
- **Bridge binary.** The PAM module refuses to launch the bridge unless its
  SHA-256 matches the digest pinned at enrollment (plan D11, fail-closed). A
  tampered or replaced `.exe` is not executed; `noverifypin` disables this check
  and is logged loudly.
- **Clone signal.** The signature counter is recorded at enrollment and
  compared on each authentication per WebAuthn §7.2 step 22 whenever either
  count is non-zero. Windows Hello is a zero/constant-counter authenticator, so
  this is an advisory signal, not the main gate — challenge freshness is. (The
  PAM module logs the observed count but does not write it back to the store.)

### What the prompt shows (and what it does not)

Empirically (see `SPIKE.md` §8), the Windows Security dialog shows:

- the **`user_name`** passed in the request (e.g. `alice`), and
- **"Passkey for `io.github.kirin-xiao.wsl-webauthn-pam`"** — the **RP ID**,
  *not* the friendly RP name (`sudo on WSL (wsl-webauthn-pam)`), and
- **not** `user_display_name`, the challenge, or the origin.

Because Windows does not surface a friendly service name, the Linux-side
`pam_conv` pre-prompt is the primary consent-naming mechanism. It reads
`Windows Hello: authenticating '<service>' for Linux user <user> — check the
Windows prompt` and is suppressed under `PAM_SILENT`.

### Limits and accepted residual risk

- **Strong authentication bound to a pinned RP ID — not a browser-grade origin
  guarantee.** A native Win32 client is not origin-enforced the way a browser
  is, so the RP ID is a scoping and display mechanism. The guarantee is
  "bound to this pinned RP ID", not "bound to an `https://` origin".
- **Compromised Windows session (accepted).** If the Windows account is already
  compromised, an attacker can initiate ceremonies (still subject to user
  verification) and can replace the bridge `.exe`. Attestation, UV, and the
  Linux-side verifier mean this does **not** yield silent root and **cannot
  forge an assertion for an enrolled credential** — but it does make **consent
  phishing** possible. This is the hard ceiling of delegating authentication to
  the local Windows session.
- **Compromised Linux root (out of scope).** Root can rewrite the credential
  store and sudoers; out of scope by definition.
- **Consent blinding is mitigated, not eliminated.** WebAuthn improves the
  prompt and requires user verification, but the OS cannot prove *which process*
  raised the ceremony.
- **Not a roaming authenticator.** A machine-local platform credential is not a
  portable FIDO2 key; machine loss or reset means re-enrollment by design.
- **No hardware side-channel defense.** TPM/platform behavior is trusted as-is.

See [SECURITY.md](SECURITY.md) for the full threat model and citations.

### The double-enroll behavior (read this before first enrollment)

The **first-ever** enrollment for a given RP ID on a machine returns
`fmt: "none"` from Windows (spike-confirmed across two RP IDs); subsequent
enrollments return `tpm`. Under the default Strict policy the CLI handles this
automatically:

1. Run the enrollment ceremony.
2. If the attestation is `none`/self and the policy is Strict, **discard that
   credential** and run exactly one more ceremony with a **fresh challenge**.
3. The persisted credential is always the second one — the first (unattested)
   Windows credential is orphaned and never trusted.
4. If the second is *still* unattested, the CLI fails and points at
   `--allow-unattested`.

**`--allow-unattested`** exists for TPM-less machines. It admits `self` and
`none` attestations (recorded as `mode: "unattested-opt-in"`, `verified: false`,
logged loudly). It is *permissive, not prescriptive*: if the platform still
returns a fully verified `tpm` (or `packed`/AttCA) attestation, that is recorded
as `mode: "strict"`, `verified: true` — the flag only widens what is admitted.
**What accepting it means:** you are asserting "I trust that
this machine is not lying about not having a TPM." A software key that simply
*declines* to attest is then accepted. **Only use it on machines you control.**
It is never a silent fallback.

> **Note on orphaned Windows credentials.** Windows exposes no API to enumerate
> or delete non-resident platform credentials, so re-enrolling (`--replace`) or
> changing the RP ID leaves the old Windows-side key in place. It cannot be
> selected without its credential ID, which only the Linux store holds — but it
> is not removable. This is an accepted consequence (`SPIKE.md` §7).

---

## Requirements

- **Windows 10 1903+** (build 18362) with `webauthn.dll`. The development
  machine observed API version 9 (Windows 11); the client-data echo field is used
  opportunistically when `ASSERTION.dwVersion >= 6` and absent otherwise.
- **WSL2 with interop enabled.** WSL1 is untested. Interop must be reachable
  from the process that runs PAM (systemd services may not see the session
  leader — see Troubleshooting).
- **A Windows Hello gesture configured** (PIN, fingerprint, or face) with a
  TPM-backed credential for the strongest (default) policy.
- **A Linux distro with PAM**, plus `pam-auth-update` for the packaged profile
  path. `libpam0g-dev` is needed to *build* the module and to run the
  `pam_start` integration tests (not for `cargo check`); those tests use
  `pam_start_confdir`, which requires **libpam ≥ 1.4** (test-only).
- **Stable Rust** to build from source (pinned by `rust-toolchain.toml`;
  `rust-version = 1.85`, edition 2024).

---

## Installation

> The Rust installer (`install` / `uninstall` in the CLI) implements plan §10.
> The guided flow below is what `sudo wsl-webauthn-pam install` does; the
> **manual installation** section is the fallback if you prefer to place the
> files yourself.

### Guided install

From a **release tarball**, `install.sh` sits next to the CLI and can be run
directly:

```sh
tar xzf wsl-webauthn-pam-<version>-<arch>.tar.gz && cd wsl-webauthn-pam-<version>-<arch>
sudo ./install.sh                      # thin shim: exec sudo ./wsl-webauthn-pam install
```

From a **source checkout**, build first (the shim runs the CLI from its own
directory):

```sh
git clone https://github.com/kirin-xiao/wsl-webauthn-pam
cd wsl-webauthn-pam
make                                    # or: cargo build --release --locked
sudo ./build/release/install.sh         # after `make release`, or:
sudo wsl-webauthn-pam install           # if the CLI is on PATH
```

`install` (running as root) will:

1. Read `/etc/wsl.conf` (`[automount]`-scoped, CRLF-tolerant) to find the
   Windows mount root (`/mnt/c` by default; override with `--win-mnt`), then
   resolve `%LOCALAPPDATA%` via `cmd.exe` and copy the bridge to
   `%LOCALAPPDATA%\Programs\wsl-webauthn-pam\WSLWebAuthnBridge.exe`, recording
   its SHA-256 pin.
2. Install `pam_wsl_webauthn.so` into the module directory (detected via
   `pam_unix.so`, or pinned with `--module-dir`). The `.so` and bridge are found
   in the release layout, `target/`, or the current directory; override with
   `--artifact-dir <DIR>` (or `$WSL_WEBAUTHN_ARTIFACTS`).
3. Write `/etc/wsl_webauthn/config` (`0600` root) and create
   `/etc/wsl_webauthn/credentials/` (`0700` root).
4. Install the `pam-auth-update` profile to
   `/usr/share/pam-configs/wsl-webauthn`. The profile ships with
   **`Default: no`** — it is **never silently enabled**.
5. Offer to remove the legacy `wsl-hello` profile and rewrite stale
   `pam_wsl_hello` references in `/etc/pam.d/*` (with confirmation + backup)
   **before** removing the old module, then require fresh enrollment. It never
   imports the legacy PEM. Our module and profile are installed and verified
   *before* any legacy cleanup, so a failure cannot leave a stale reference.
6. Offer to enable the profile now (**default no**, matching `Default: no`),
   print the lockout warning, and **last** offer to enroll the invoking user.
   Use `--skip-enroll` to stop before the enrollment offer, `--yes` to answer
   yes to every prompt, and `--non-interactive` to never read stdin.

Then, once:

```sh
sudo wsl-webauthn-pam enroll          # run as the user you want to enroll
```

Finally enable the PAM profile (this is the step that turns it on):

```sh
sudo pam-auth-update                  # select "WSL WebAuthn authentication"
# or non-interactively:
sudo pam-auth-update --enable wsl-webauthn
```

### Manual installation (no installer)

1. Copy `pam_wsl_webauthn.so` to e.g. `/usr/lib/x86_64-linux-gnu/security/`.
2. Copy the bridge onto the Windows side (any path works; the config pins it).
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
   `pam-auth-update` idiom (it is expanded to a computed jump); `end` is not a
   literal PAM action.

### ⚠️ The lockout warning

**Keep at least one working `sudo`/`su` path that does not go through this
module.** The module is **fail-closed**: any provisioning error (missing
config, unreadable store, bridge transport failure, interop unavailable, pin
mismatch, timeout) denies Hello for that PAM service and only falls through to
the *next* method when the stack says so (under `sufficient`, or under
`[success=end default=ignore]`). Keep a second TTY, a root shell, or the local
password available, and test with a non-critical service first. The installer
prints the same warning.

---

## Using the CLI

```
wsl-webauthn-pam <COMMAND> [OPTIONS]

  enroll       Enroll a Windows Hello credential for a Linux user (root)
                 --replace             overwrite an existing credential
                 --allow-unattested    admit self/none attestations (opt-in, loud)
                 --user <NAME>         target user (default: SUDO_USER or current)
                 --bridge <PATH>       bridge exe path (else config, else required)
                 --win-mnt <PATH>      Windows mount root (else config, else /mnt/c)
  unregister   Remove one user's credential record (root, per-user only)
                 --user <NAME>         target user (default: SUDO_USER or current)
                 --yes                 skip the confirmation prompt
  probe        Report interop / Hello availability and the bridge pin
                 --bridge <PATH>       bridge exe path (else config, else required)
                 --win-mnt <PATH>      Windows mount root (else config, else /mnt/c)
  status       List enrolled users and the config summary (root for records)
                 --user <NAME>         show one user's full record
  verify       Self-test the crypto stack against a synthetic ceremony
  install      Provision the bridge, config, PAM module and profile (root)
                 --artifact-dir <DIR>  where to find the .so/.exe (else env/cwd)
                 --module-dir <DIR>    override the PAM security directory
                 --win-mnt <PATH>      override the Windows mount root
                 --allow-unattested    admit self/none attestation at enroll
                 --skip-enroll         do not offer enrollment at the end
                 --yes                 answer yes to every prompt
                 --non-interactive     never read stdin; use question defaults
  uninstall    Remove a credential or all components (root)
                 --user <NAME>         remove one user's record (default)
                 --all                 remove profile, module, config, bridge
                 --module-dir <DIR>    override the PAM security directory
                 --win-mnt <PATH>      override the Windows mount root
                 --yes                 skip confirmations
                 --non-interactive     never read stdin; use question defaults
```

`enroll`, `unregister`, `install`, and `uninstall` require root. `probe` and
`verify` run unprivileged; `status` works unprivileged for the config summary
but needs root to read credential records. Exit codes: `0` success, `1`
operational failure, `2` usage error.

---

## Building from source

```sh
cargo build --release --workspace --locked
```

The Linux PAM module is a `cdylib`; linking it against `libpam0g-dev` is the
only thing that needs the PAM development headers:

```sh
sudo apt-get install -y libpam0g-dev     # Debian/Ubuntu
```

### The Windows bridge

Either build it on Windows with **`cargo.exe`** (native MSVC — what CI ships),
or cross-compile on Linux with the self-contained
`x86_64-pc-windows-gnu` target (no admin needed; `rust-lld` + `rust-mingw` link
standalone):

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release -p wsl-webauthn-bridge --target x86_64-pc-windows-gnu
```

`make bridge` picks `cargo.exe` when it is on `PATH` and otherwise falls back to
the GNU cross target. (WSL interop is what lets you run the resulting `.exe`
directly, which is required for enrollment and authentication.)

### Make targets

| Target | What it does |
|---|---|
| `make` / `make all` | Linux module + CLI (release) and the Windows bridge |
| `make bridge` | Bridge only (`cargo.exe`, else `x86_64-pc-windows-gnu`) |
| `make test` | `cargo test --workspace --locked` |
| `make check` | `fmt` + `clippy` + `test` + `deny` |
| `make pam-profile` | Validate the `pam-config` profile and its `pam-auth-update` expansion |
| `make release` | Assemble `build/release/` + a per-arch tarball + `SHA256SUMS` |

### Release artifact layout

Tagging `v*` triggers the release workflow. Each architecture produces one
tarball, alongside a top-level `SHA256SUMS` covering every tarball:

```
wsl-webauthn-pam-<version>-<arch>.tar.gz      # arch ∈ {x86_64, aarch64}
├── pam_wsl_webauthn.so        # Linux PAM module
├── wsl-webauthn-pam           # CLI
├── WSLWebAuthnBridge.exe      # matching-arch Windows bridge
├── install.sh
├── pam-config
└── README.md

SHA256SUMS                     # separate release asset: checksums for all tarballs
```

Published on the [releases page](https://github.com/kirin-xiao/wsl-webauthn-pam/releases).
Verify downloads against `SHA256SUMS`. (`make release` assembles the same
contents under `build/` and additionally writes a `SHA256SUMS` file next to the
tarball.)

---

## Troubleshooting

**The module never seems to trigger, and `sudo` just asks for a password.**
The module honours `PAM_SILENT` and never writes to stdout, so it is quiet by
design. Check the authentication log:
`journalctl -t pam_wsl_webauthn` or your distro's `auth.log` (syslog facility
`authpriv`). Add the `debug` module argument for `LOG_DEBUG` detail (never
secrets).

**The Windows Hello prompt appears in the background.**
The bridge owns a hidden top-level window and the dialog is parented to it, but
WSL focus handling means the dialog is not forced to the foreground — the legacy
"appears behind other windows" symptom is structurally fixed but foreground
acquisition is not guaranteed (`SPIKE.md` §9). Mitigation: watch the taskbar
for the Windows Security icon and click it. This is worst when another app (e.g.
a browser) is actively in front.

**Interop is unavailable.**
WSL interop needs the `binfmt_misc` `WSLInterop` registration to be `enabled`.
Systemd services often cannot reach the session leader, so Hello may work from
an interactive shell but not from a service. The runner fails fast (no hang)
when the registration is missing or disabled.

**The prompt timed out.**
The bridge passes an advisory 55 s timeout to `webauthn.dll` *and* runs its own
watchdog that calls `WebAuthNCancelCurrentOperation` at 55 s. The Linux runner
enforces a hard 60 s deadline for the whole child, then `SIGKILL`s the shim and
best-effort `taskkill.exe`s the reported Windows PID within a 5 s budget. So
total wall time can reach about `deadline + 5 s`. Override with the
`timeout=<secs>` module argument or `timeout_secs` in the config.

> Because `WebAuthNCancelCurrentOperation` makes the platform return the same
> `NTE_USER_CANCELLED` HRESULT as a manual cancel, the bridge reclassifies its
> **own** watchdog fire to `timeout` while a genuine user cancel remains
> `user_cancelled` (`SPIKE.md` §5; `ceremony.rs`).

**The bridge pin fails after I replaced the `.exe`.**
That is the pin doing its job. Re-enroll, or (if you intend to trust the new
binary) re-run `enroll --replace`, or launch with the `noverifypin` module
argument — which is logged loudly at `LOG_ERR` on every authentication and
removes a defence-in-depth control.

---

## FAQ

**Why WebAuthn instead of the old `KeyCredentialManager`?**
`KeyCredentialManager` gives an RSA signing oracle with an unattested,
attacker-influenceable public key and a blind, fixed prompt. WebAuthn gives us
(a) **attestation** to a pinned TPM root, (b) **RP-scoping**, (c) a **focused,
consent-bearing prompt**, and (d) **no signing oracle** — the key signs a
WebAuthn assertion whose contents we fully verify, not an arbitrary blob. See
`ISSUES.md` §1 in the rewrite requirements.

**Is my old WSL-Hello-sudo configuration migrated?**
**No.** Fresh enrollment is required and the legacy PEM is **never imported** —
it is exactly the attacker-influenceable artifact this rewrite rejects. The
installer detects a legacy install, warns, and offers to rewrite
`/etc/pam.d/*` references from `pam_wsl_hello` to `pam_wsl_webauthn.so` **with
confirmation and a backup** before removing the old module (a stale reference
would be a load failure and a lockout).

**Multi-user semantics: can several Linux users share one Windows account?**
Yes, and that is the normal WSL case. Each Linux user has exactly **one
credential record** of their own, bound (for audit) to the Windows account/SID
that enrolled it. There is no runtime SID check: interop always runs as the
distro-session owner, so the "wrong" Windows account simply yields no usable
credential. The Windows account binding is **audit-only**.

**Can I use this for real authentication on a machine without a TPM?**
Only with `--allow-unattested`, and only on a machine you control. Without a TPM
there is no attestation, so the software key is accepted on trust (see
[the double-enroll section](#the-double-enroll-behavior-read-this-before-first-enrollment)).

**Does it modify `sudoers`?**
No. It never edits `sudoers`. It works through the PAM stack; enabling it means
adding the module (or the `pam-auth-update` profile) to the relevant PAM service
such as `/etc/pam.d/sudo`.

> The `ISSUES.md` requirement set referenced in the FAQ above is the plan this
> project was built against; it is not part of this repository.

---

## Demo / UX

Enrollment and every authentication raise the standard Windows Security dialog:

```
┌─ Windows Security ────────────────────────────────────────┐
│  Sign in with a passkey                                    │
│                                                            │
│  ●─  alice                                    ○───○         │
│      Passkey for io.github.kirin-xiao.wsl-webauthn-pam     │
│                                                            │
│              ⋮⋮⋮ ⋮⋮⋮ ⋮⋮⋮                                   │
│              Enter your PIN                                │
│              [ PIN __________________ ]                    │
│              I forgot my PIN                               │
│                          [ Cancel ]                        │
└────────────────────────────────────────────────────────────┘
```

The primary line is the `user_name`; the secondary line is
`Passkey for <RP_ID>`. On the Linux side, `sudo` also prints the `pam_conv`
pre-prompt naming the service and user (unless `PAM_SILENT`). The dialog is
parented to the bridge's hidden window (`owner = WSLWebAuthnBridge`) and appears
about one second into the ceremony. Screenshots from the real machine are not
committed because they can contain user-identifying data; the description above
is taken from `SPIKE.md` §8.

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
