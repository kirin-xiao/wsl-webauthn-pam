# Security Policy

`wsl-webauthn-pam` is authentication infrastructure: a Linux PAM module plus a
Windows bridge that authenticates `sudo`/`su` via the Windows Hello WebAuthn
platform authenticator. This document states the threat model, the trust
anchors, the enrollment and enforcement properties, and the residual risks we
accept. The condensed, user-facing version is in
[README → Security model](README.md#security-model).

**Canonical repository:** <https://github.com/kirin-xiao/wsl-webauthn-pam>

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability. Use
GitHub's private vulnerability reporting on this repository:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub Security Advisories).
3. Include: affected version/commit, the component (verifier / PAM module /
   bridge / store / installer), a description, and a minimal reproduction.

We will acknowledge the report and coordinate a fix and disclosure. Please
allow reasonable time before public disclosure. There is no bug-bounty program.

## Design principle: all trust is Linux-side

The Windows bridge (`WSLWebAuthnBridge.exe`) is a **thin relay**: it loads
`webauthn.dll`, runs the ceremony, and relays bytes. It performs no security
decision and holds no trust. Every cryptographic and policy decision is made by
the root-owned Linux side, in the pure-Rust verifier and the PAM module
(`crates/wsl-webauthn-verifier/src/lib.rs`, `crates/wsl-webauthn-pam/src/logic.rs`).
A compromised bridge therefore cannot forge an accepted assertion — it can only
fail, stall, or attempt consent phishing.

---

## Threat model

### Attacker capabilities

#### 1. Local Linux user (unprivileged)

*CAN:*

- Attempt `sudo`/`su` and try to satisfy the Hello ceremony.
- Supply a malformed or hostile credential record if it could write one — but
  the store is root-owned (`0700` dir, `0600` files) and any ownership/mode
  mismatch, symlink, or file swap makes `Store::load` fail closed
  (`crates/wsl-webauthn-store/src/lib.rs`, `StoreError::{BadOwnership,
  SymlinkedPath, PathChanged}`).
- Craft arbitrary bytes as an assertion if it can replace the bridge — the
  pinned SHA-256 rejects a replaced `.exe` before launch
  (`crates/wsl-webauthn-pam/src/logic.rs`, bridge pin step).

*CANNOT:*

- Authenticate without a valid signature from the enrolled credential over the
  fresh challenge (`verify_assertion`).
- Reach any code path that returns `PAM_SUCCESS` without a fully verified
  assertion — there is exactly one success return.

#### 2. Attacker with a compromised Windows session

*CAN:*

- Initiate ceremonies (subject to Windows user verification) and thus attempt
  **consent phishing**.
- Replace the bridge executable on DrvFs.

*CANNOT:*

- **Forge an assertion for an enrolled credential.** The signature is verified
  on the Linux side against the enrolled public key over a challenge the Linux
  side minted; a replaced bridge has no private key. The bridge pin also refuses
  to launch a changed `.exe` unless the operator disabled it with `noverifypin`.
- **Silently raise privilege.** Even a successful ceremony is checked against
  `rpIdHash`, UP/UV, the enrolled credential id, and the signature.
- **Enroll a software key under the default policy.** Strict attestation chains
  to the pinned Microsoft TPM root and requires a Windows Hello AAGUID; an
  unattested key is refused after the double-enroll retry.

This residual capability — making the user approve a ceremony they did not
intend — is accepted and documented as SR-OUT-1/3 (see
[residual risk](#accepted-residual-risk)).

#### 3. Malicious bridge executable

*CAN:*

- Return `ok:false`, malformed framing, an oversized/truncated frame, or wrong
  bytes for `authenticatorData`/`signature`/`credential_id`.
- Stall, or report a fabricated `not_available`/`busy`/etc. to deny service.

*CANNOT:*

- Produce a response the verifier accepts without a genuine signature from the
  enrolled credential. Echo mismatch, credential-id mismatch, malformed base64,
  any `VerifyError`, and out-of-range/oversized values all fail closed to
  `PAM_AUTH_ERR` or `PAM_AUTHINFO_UNAVAIL` (`crates/wsl-webauthn-pam/src/lib.rs`
  mapping table; `crates/wsl-webauthn-runner/src/lib.rs` bounded read loop).
- Be launched unchanged by the module if its hash differs from the one pinned at
  enrollment (unless `noverifypin`). The pin is fail-closed.

Because the bridge holds no trust, an attacker who fully controls it gains only
the ability to deny authentication or to relay a genuine ceremony — not to
authenticate.

### Out of scope

- **Compromised Linux root.** Root can rewrite the trust store, the module, and
  sudoers; this is out of scope by definition.
- **A compromised TPM / platform.** Platform behavior is trusted as-is.
- **Physical/OS-level attacks on Windows** below the WebAuthn boundary.

---

## Trust anchors

| Anchor | Value / rule | Where |
|---|---|---|
| RP ID | `io.github.kirin-xiao.wsl-webauthn-pam` (compile-time constant) | `crates/wsl-webauthn-protocol/src/lib.rs` (`RP_ID`) |
| Origin | pinned equal to the RP ID (native client, no browser origin) | `crates/wsl-webauthn-protocol/src/lib.rs` (`ORIGIN`) |
| Attestation root | **Microsoft TPM Root Certificate Authority 2014**, SHA-256 `87:0C:7A:35:CE:AB:3D:59:97:9F:2C:6A:52:40:42:D4:04:CB:71:51:80:04:35:09:25:FB:2C:ED:79:A9:99:DA` | `crates/wsl-webauthn-verifier/src/lib.rs` (`MS_TPM_ROOT_2014_SHA256`) |
| AAGUID allow-list | `08987058-cadc-4b81-b6e1-30de50dcbe96` (software TPM), `9ddd1817-af5a-4672-a2b9-3e3dd95000a9` (hardware TPM) | `STRICT_AAGUIDS` |
| Bridge binary | SHA-256 recorded at enrollment, re-checked on every authentication | credential record `bridge_sha256`; `logic.rs` pin step |
| COSE algorithms | `{-7 ES256, -257 RS256, -8 EdDSA}` | `crates/wsl-webauthn-verifier/src/cose.rs` |

Overriding the root is impossible in production: `verify_attestation` always
uses the pinned fingerprint, and the bundled root certificate is trusted **only**
after its bytes hash to that pin (`crates/wsl-webauthn-verifier/src/ms_root.rs`).
A `#[doc(hidden)]` test-only seam (`verify_attestation_with_anchor`) lets the test
suite substitute a synthetic root; it cannot weaken the production path.

### Verified invariants (assertion)

- `clientDataJSON`: exact `type` (`webauthn.get`), `challenge` compared on
  **decoded** bytes, `origin` byte-equal to the pinned constant, valid UTF-8.
- `authenticatorData`: `rpIdHash == SHA-256(RP_ID)`; **UP = 1**; **UV = 1**;
  length bounds.
- Credential id returned == enrolled id.
- COSE key: allow-listed `alg`, P-256 uncompressed point-on-curve, RSA
  `n` in 2048..=4096, Ed25519 `x` 32 bytes.
- Signature: ES256 (DER), RS256 (PKCS#1 v1.5), EdDSA (`verify_strict`) over
  `authenticatorData ‖ SHA-256(clientDataJSON)`.
- Signature-counter clone signal per WebAuthn §7.2 step 22 (advisory; Windows
  Hello reports a constant counter and the store is not written back).

### Verified invariants (attestation)

- `tpm` (§8.3): `ver == "2.0"`, `certInfo` magic/type, `extraData ==
  H(authData ‖ clientDataHash)`, `name` recomputed from `pubArea`, AIK `sig`
  over `certInfo`, chain to the pinned root; AIK leaf v3, empty Subject,
  `CA=false`, TCG AIK Extended Key Usage (`2.23.133.8.3`) and a KeyUsage, when
  present, permitting `digitalSignature`. The TCG SubjectAltName content is not
  validated (documented gap; Windows Hello's AIK SAN uses a non-standard
  critical `directoryName` encoding).
- `packed`/AttCA: chain to the pinned root, leaf v3, `CA=false`,
  `OU="Authenticator Attestation"`, `id-fido-gen-ce-aaguid` matching the
  authData AAGUID, `attStmt.alg` == leaf key alg.
- AAGUID allow-list: the authData AAGUID must be one of `STRICT_AAGUIDS` on
  **every** attestation path. It is checked once, before the format/policy
  dispatch, so self and `none` (admitted under `AllowUnattested`) cannot bypass
  it. Assertions do not enforce an AAGUID allow-list; the assertion path does not
  trust or compare an AAGUID.
- Self/`none` attestation: admitted **only** under explicit
  `AttestationPolicy::AllowUnattested` — never a silent fallback. The policy is
  permissive, not prescriptive: a fully verified `tpm`/`packed` attestation is
  still recorded `mode: "strict"`, `verified: true` even when
  `--allow-unattested` was passed.

The verifier is `#![forbid(unsafe_code)]` and non-panicking on every parse path;
it is exercised by synthesized positive/negative tests (one negative per
invariant), `proptest` round-trips, and `cargo-fuzz` targets
(`crates/wsl-webauthn-verifier/`, `fuzz/`).

---

## Enrollment security properties

- **Attestation verified before the anchor is written.** The CLI builds the
  enrollment `clientDataJSON`, runs the ceremony, and only writes a record after
  `verify_attestation` succeeds under the selected policy. A failed verification
  never persists anything (`crates/wsl-webauthn-cli/src/main.rs`).
- **Double-enroll discards the first credential.** When the first-ever ceremony
  for an RP ID returns `none`, the CLI discards that outcome and re-runs exactly
  one ceremony with a fresh challenge; only the second credential can be
  persisted (`enroll_with_double_enroll`, unit-tested to prove ceremony #1 never
  reaches the record).
- **Root-only store.** `/etc/wsl_webauthn/credentials/` is `0700`, records are
  `0600`, config is `0600`, all root-owned. The PAM hot path verifies ownership
  and **exact** modes (an equality test, so any extra group/other or
  setuid/setgid/sticky bit is rejected).
- **Symlink-hardened.** Every path component is `lstat`ed; a symlink is refused.
  Reads use `open(2)` with `O_NOFOLLOW|O_NOCTTY|O_CLOEXEC`, then `fstat` the
  descriptor and compare `(dev, ino)` with the earlier `lstat` — a file swapped
  between the two calls is rejected (`StoreError::PathChanged`).
- **Atomic writes.** `mkstemp` in the destination directory → `fchmod 0600` →
  `write` → `fsync(file)` → `rename`/`link` → `fsync(dir)`. Failure paths remove
  the temp file.
- **Bounded reads.** Records are capped at 256 KiB, config at 64 KiB, wire
  responses at 64 KiB, requests at 8 KiB; caps are enforced *while reading*.
- **No shell, no temp challenge file.** The challenge and `clientDataJSON` travel
  over stdin via a length-prefixed frame. The runner spawns with an argument
  array and `current_dir = win_mnt`; there is no shell and no on-disk challenge.

---

## PAM fail-closed mapping (summary)

From `crates/wsl-webauthn-pam/src/lib.rs`:

| Situation | PAM code |
|---|---|
| Verified assertion | `PAM_SUCCESS` |
| No credential record / null, empty, or invalid username | `PAM_USER_UNKNOWN` |
| Config missing/invalid; store error (ownership, symlink, corrupt, I/O); bridge pin mismatch or missing; runner failure (interop unavailable, bridge missing, spawn, transport, timeout); `not_available`/`not_supported`/`timeout`/`busy`/`invalid_parameter`/`internal` | `PAM_AUTHINFO_UNAVAIL` |
| `user_cancelled`; any `VerifyError`; echo/credential-id mismatch; malformed response | `PAM_AUTH_ERR` |
| Panic in module code | `PAM_ABORT` |
| `pam_sm_setcred` | `PAM_SUCCESS` |
| Any other non-authentication `pam_sm_*` | `PAM_IGNORE` |

There is exactly one path to `PAM_SUCCESS`: a fully verified assertion. Every
failure path also requests `pam_fail_delay(pamh, 2_000_000)` (2 s) to blunt
consent spam. No attempt counter is persisted across processes; the PAM stack
owns retry policy.

> **Fall-through caveat.** `PAM_USER_UNKNOWN`/`PAM_AUTHINFO_UNAVAIL` fall
> through to the next method only when the PAM stack is configured to allow it
> (`sufficient`, or `[success=end default=ignore]`). Under a required-only stack
> the denial is final. Keep a working fallback (see the README lockout warning).

---

## Accepted residual risk

These are documented, not addressed. The user-facing wording is in the
[README](README.md#limits-and-accepted-residual-risk); the source requirements
are SR-OUT-1..5 in the rewrite requirements.

- **SR-OUT-1 — Compromised Windows session.** Ceremony initiation is possible
  (subject to user verification) and the bridge can be replaced, but attestation
  + UV + Linux-side verification mean this does **not** yield silent root and
  does **not** let a replaced bridge forge an assertion. It does allow **consent
  phishing**. Hard ceiling of delegating to the local Windows session.
- **SR-OUT-2 — Compromised Linux root.** Out of scope by definition.
- **SR-OUT-3 — Consent blinding is mitigated, not eliminated.** Neither WebAuthn
  nor a custom pre-prompt can make the OS prove *which process* raised the
  ceremony.
- **SR-OUT-4 — Not a roaming authenticator.** Machine loss/reset ⇒ re-enrollment
  by design. Windows also cannot enumerate/delete non-resident platform
  credentials, so old Windows keys from `--replace`/re-enrollment are orphaned
  (inert without their credential ID, which only the Linux store holds).
- **SR-OUT-5 — No hardware side-channel defense.** TPM/platform behavior is
  trusted as-is.

Additionally: because this is a native client, the RP ID is a **scoping/display**
mechanism, not a browser-grade origin guarantee. The guarantee is "bound to this
pinned RP ID."

---

## Cryptography and dependencies

- No OpenSSL. The verifier is hand-rolled pure Rust over `ciborium`, `p256`,
  `ecdsa`, `sha2`, `rsa`, `ed25519-dalek`, `x509-cert`, `der`, `const-oid`
  (plan D4).
- Builds use `--locked`; third-party CI actions are pinned to commit SHAs;
  `cargo-deny` checks advisories, licenses, and sources (`deny.toml`).
- One advisory is knowingly accepted: **RUSTSEC-2023-0071** (non-constant-time
  RSA private-key operations in `rsa`). It reaches us through public-key-only
  RS256 / attestation verification; no RSA private key exists anywhere in the
  project and the PAM path is local and never network-reachable. Rationale is
  recorded in `deny.toml`.
- Real-machine attestation vectors are **never committed**; they contain
  machine-linked key material and live only in the git-ignored
  `tests/vectors/local/`.
