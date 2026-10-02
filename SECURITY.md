# Security Policy

`wsl-webauthn-pam` is authentication infrastructure: a Linux PAM module plus a Windows bridge that authenticates `sudo`/`su` via the Windows Hello WebAuthn platform authenticator.

**Canonical repository:** <https://github.com/kirin-xiao/wsl-webauthn-pam>

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting on this repository:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability** (GitHub Security Advisories).
3. Include: affected version/commit, the component (verifier / PAM module / bridge / store / installer), a description, and a minimal reproduction.

We will acknowledge the report and coordinate a fix and disclosure. Please allow reasonable time before public disclosure. There is no bug-bounty program.

## Design principle: all trust is Linux-side

The Windows bridge (`WSLWebAuthnBridge.exe`) loads `webauthn.dll`, runs the ceremony, and relays bytes; it makes no security decision and holds no trust. Every cryptographic and policy decision is made by the root-owned Linux side in the pure-Rust verifier and the PAM module (`crates/wsl-webauthn-verifier/src/lib.rs`, `crates/wsl-webauthn-pam/src/logic.rs`). A compromised bridge can only fail, stall, or attempt consent phishing — it cannot forge an accepted assertion.

---

## Threat model

### Attacker capabilities

#### 1. Local Linux user (unprivileged)

*CAN:* attempt `sudo`/`su` and try to satisfy the Hello ceremony; supply a malformed or hostile credential record if it could write one — but the store is root-owned (`0700` dir, `0600` files) and any ownership/mode mismatch, symlink, or file swap makes `Store::load` fail closed (`StoreError::{BadOwnership, SymlinkedPath, PathChanged}`); craft assertion bytes if it can replace the bridge — the pinned SHA-256 rejects a replaced `.exe` before launch.

*CANNOT:* authenticate without a valid signature from the enrolled credential over a fresh challenge (`verify_assertion`); reach any path returning `PAM_SUCCESS` without a fully verified assertion — there is exactly one success return.

#### 2. Attacker with a compromised Windows session

*CAN:* initiate ceremonies (subject to Windows user verification) and thus attempt **consent phishing**; replace the bridge executable on DrvFs.

*CANNOT:*

- **Forge an assertion for an enrolled credential.** The signature is verified on the Linux side against the enrolled public key over a Linux-minted challenge; a replaced bridge has no private key. The bridge pin also refuses to launch a changed `.exe`; there is no module argument that disables it.
  <!-- INVARIANT: PAM-BRIDGE-PIN-FAIL-CLOSED -->
- **Silently raise privilege.** A successful ceremony is checked against `rpIdHash`, UP/UV, the enrolled credential id, and the signature.
- **Enroll a software key under the default policy.** Strict attestation chains to the pinned Microsoft TPM root and requires a Windows Hello AAGUID; an unattested key is refused after the double-enroll retry.

Consent phishing — making the user approve a ceremony they did not intend — is accepted residual risk (see [residual risk](#accepted-residual-risk)).

#### 3. Malicious bridge executable

*CAN:* return `ok:false`, malformed framing, an oversized/truncated frame, or wrong bytes for `authenticatorData`/`signature`/`credential_id`; stall or report a fabricated `not_available`/`busy`/etc. to deny service.

*CANNOT:* produce a response the verifier accepts without a genuine signature from the enrolled credential — echo mismatch, credential-id mismatch, malformed base64, any `VerifyError`, and out-of-range/oversized values all fail closed to `PAM_AUTH_ERR` or `PAM_AUTHINFO_UNAVAIL` (`crates/wsl-webauthn-pam/src/lib.rs` mapping table; `crates/wsl-webauthn-runner/src/lib.rs` bounded read loop); be launched unchanged by the module if its hash differs from the one pinned at enrollment — the pin is fail-closed and cannot be disabled from the module arguments.
<!-- INVARIANT: RUNNER-BOUNDED-READ -->
<!-- INVARIANT: RUNNER-EXACTLY-ONE-FRAME, RUNNER-TIMEOUT-REAP, RUNNER-SIGPIPE-SAFE, RUNNER-NO-SHELL -->

### Out of scope

- **Compromised Linux root.** Root can rewrite the trust store, the module, and sudoers.
- **Compromised TPM / platform.** Platform behavior is trusted as-is.
- **Physical/OS-level attacks on Windows** below the WebAuthn boundary.

---

## Trust anchors

| Anchor | Value / rule | Where |
|---|---|---|
| RP ID | `wsl-webauthn-pam` (compile-time constant) | `crates/wsl-webauthn-protocol/src/lib.rs` (`RP_ID`) |
| Origin | pinned equal to the RP ID (native client, no browser origin) | `crates/wsl-webauthn-protocol/src/lib.rs` (`ORIGIN`) |
| Attestation root | **Microsoft TPM Root Certificate Authority 2014**, SHA-256 `87:0C:7A:35:CE:AB:3D:59:97:9F:2C:6A:52:40:42:D4:04:CB:71:51:80:04:35:09:25:FB:2C:ED:79:A9:99:DA` | `crates/wsl-webauthn-verifier/src/lib.rs` (`MS_TPM_ROOT_2014_SHA256`) |
<!-- INVARIANT: CHAIN-PINNED-ROOT -->
<!-- INVARIANT: CHAIN-PATHLEN -->
| AAGUID allow-list | `08987058-cadc-4b81-b6e1-30de50dcbe96` (software TPM), `9ddd1817-af5a-4672-a2b9-3e3dd95000a9` (hardware TPM) | `STRICT_AAGUIDS` |
| Bridge binary | SHA-256 recorded at enrollment, re-checked on every authentication | credential record `bridge_sha256`; runner checks the held descriptor it executes (`Runner::expected_sha256`, `proc::TrustedFile::sha256`) |
| COSE algorithms | `{-7 ES256, -257 RS256, -8 EdDSA}` | `crates/wsl-webauthn-verifier/src/cose.rs` |

`verify_attestation` always uses the pinned fingerprint; the bundled root certificate is trusted **only** after its bytes hash to that pin (`crates/wsl-webauthn-verifier/src/ms_root.rs`). A test-only seam (`verify_attestation_with_anchor`, under the `test-anchor` feature) substitutes a synthetic root for tests; downstream crates never enable it.

### Verified invariants (assertion)

- `clientDataJSON`: exact `type` (`webauthn.get`), `challenge` compared on **decoded** bytes, `origin` byte-equal to the pinned constant, valid UTF-8.
  <!-- INVARIANT: ASSERTION-CLIENTDATA-TYPE-EXACT, ASSERTION-CLIENTDATA-CHALLENGE-DECODED, ASSERTION-CLIENTDATA-ORIGIN-PINNED -->
- `authenticatorData`: `rpIdHash == SHA-256(RP_ID)`, **UP = 1**, **UV = 1**, length bounds.
  <!-- INVARIANT: ASSERTION-RPIDHASH, ASSERTION-UP-UV, AUTHDATA-ED-GATES-TRAILING, AUTHDATA-CANONICAL-COSE-FIRST, CBOR-EXACT-NO-TRAILING, CBOR-NO-DUPLICATE-KEYS -->
- Credential id returned == enrolled id.
  <!-- INVARIANT: ASSERTION-CREDENTIAL-ID-BINDING -->
- COSE key: allow-listed `alg`, P-256 uncompressed point-on-curve, RSA `n` in 2048..=4096, Ed25519 `x` 32 bytes.
  <!-- INVARIANT: COSE-ALG-ALLOWLIST, COSE-P256-UNCOMPRESSED-ON-CURVE, COSE-RSA-MODULUS-SIZE, COSE-RSA-EXPONENT, COSE-ED25519-X-LENGTH, COSE-KTY-ALG-CONSISTENCY -->
- Signature: ES256 (DER), RS256 (PKCS#1 v1.5), EdDSA (`verify_strict`) over `authenticatorData ‖ SHA-256(clientDataJSON)`.
  <!-- INVARIANT: ASSERTION-SIGNED-MESSAGE-DEFINITION -->
- Signature-counter clone signal per WebAuthn §7.2 step 22 (advisory; Windows Hello reports a constant counter). After a verified assertion, when the authenticator reported a strictly higher counter than the record holds, the module conditionally advances the stored value to the last seen count. The write is conditional on the record being unchanged since load (it can neither resurrect an `unregister`ed record nor clobber a newer enrollment) and is non-fatal: a persistence failure is logged and the authentication still succeeds.
  <!-- INVARIANT: ASSERTION-COUNTER-POLICY -->

### Verified invariants (attestation)

<!-- INVARIANT: ATTESTATION-ALLOW-UNATTESTED-OPT-IN, TPM-CERTINFO-BINDING, TPM-PUBAREA-KEYBITS, TPM-AIK-EKU-REQUIRED, TPM-AIK-KEYUSAGE-DIGITALSIGNATURE, CHAIN-LEAF-V3-AND-CA-FALSE, CHAIN-PACKED-OU, CHAIN-AAGUID-EXT-MATCH, CHAIN-ATTSTMT-ALG-MATCH, CHAIN-ISSUER-SUBJECT-LINK, CHAIN-VALIDITY-WINDOW -->

- `tpm` (§8.3): `ver == "2.0"`, `certInfo` magic/type, `extraData == H(authData ‖ clientDataHash)`, `name` recomputed from `pubArea`, AIK `sig` over `certInfo`, chain to the pinned root; AIK leaf v3, empty Subject, `CA=false`, TCG AIK Extended Key Usage (`2.23.133.8.3`) and a KeyUsage, when present, permitting `digitalSignature`. The TCG SubjectAltName content is not validated (documented gap; Windows Hello's AIK SAN uses a non-standard critical `directoryName` encoding).
- `packed`/AttCA: chain to the pinned root, leaf v3, `CA=false`, `OU="Authenticator Attestation"`, `id-fido-gen-ce-aaguid` matching the authData AAGUID, `attStmt.alg` == leaf key alg.
- AAGUID allow-list: the authData AAGUID must be one of `STRICT_AAGUIDS` on **every** attestation path, checked once before the format/policy dispatch, so self and `none` (admitted under `AllowUnattested`) cannot bypass it. Assertions neither enforce an AAGUID allow-list nor compare an AAGUID.
  <!-- INVARIANT: AAGUID-ALLOWLIST-EVERY-ATTESTATION-PATH -->
- Self/`none` attestation: admitted **only** under explicit `AttestationPolicy::AllowUnattested`, never a silent fallback. The policy is permissive, not prescriptive: a fully verified `tpm`/`packed` attestation is still recorded `mode: "strict"`, `verified: true` when `--allow-unattested` was passed.

**`attestation.mode` is enrollment-time audit metadata, not an authentication-time policy.** The record's `attestation.mode` (`"strict"` or `"unattested-opt-in"`) and `attestation.verified` are written by root through the verified enrollment path and are read only for operator reporting. At authentication time the module does **not** re-apply an attestation policy from these fields: the gate is the signature over a fresh challenge under the enrolled public key, together with the RP-ID/origin and bridge-hash pins and root ownership of the record. A record stamped `mode: "unattested-opt-in"` reflects a conscious `--allow-unattested` enrollment; an attacker who could write a record could equally stamp it `"strict"`, so re-checking the label would add no security. There is no `strict-only` module argument: uniform strictness is chosen at the enrollment path (`--allow-unattested` is the only relaxation), not through PAM arguments.

The verifier is `#![forbid(unsafe_code)]` and non-panicking on every parse path.

**Build requirement — unwinding panics.** The PAM module wraps every exported entry point in `catch_unwind`, returning `PAM_ABORT` instead of unwinding across the C ABI; the Windows bridge must fail in-band. Both crates require `panic = "unwind"` and carry a `#[cfg(not(panic = "unwind"))] compile_error!` guard, so a `panic = "abort"` profile fails the build.
<!-- INVARIANT: PAM-BUILD-PANIC-UNWIND, MSRV-1.88 -->

**No test seam in shipped artifacts.** `Deps::panic_probe` is a no-op trait default that no production implementation overrides, so no shipped module can panic through it. The audit sink is chosen at **runtime**: the `syslog` path is always compiled (present as an undefined `nm` symbol in both the release and `--all-targets` `.so`), so no build profile produces a module that silently loses its `authpriv` path. A process switches to an in-process recorder only if code calls `logger::enable_capture` (test harnesses) or sets the hidden `WSL_WEBAUTHN_TEST_CAPTURE` marker, and the marker is ignored under an `AT_SECURE` privilege transition; no production code path enables either.

---

## Enrollment security properties

<!-- INVARIANT: ENROLL-VERIFY-BEFORE-PERSIST, ENROLL-DOUBLE-ENROLL-DISCARDS-FIRST, ENROLL-REPLACE-ORPHAN-GUARD, ENROLL-STORAGE-ERROR-FAILS-CLOSED, STORE-ROOT-ONLY-OWNERSHIP-MODE, STORE-SYMLINK-HARDENED, STORE-ATOMIC-NO-TEMP-LEFTOVER, STORE-BOUNDED-READS, STORE-MODE-VALIDATED-ON-LOAD -->

- **Verify before persist.** The CLI builds the enrollment `clientDataJSON`, runs the ceremony, and only writes a record after `verify_attestation` succeeds under the selected policy; a failed verification never persists anything (`crates/wsl-webauthn-cli/src/main.rs`).
- **Double-enroll discards the first credential.** When the first-ever ceremony for an RP ID returns `none`, the CLI discards that outcome and re-runs exactly one ceremony with a fresh challenge; only the second credential can persist.
- **Root-only store.** `/etc/wsl_webauthn/credentials/` is `0700`, records and config are `0600`, all root-owned. The PAM hot path verifies ownership and **exact** modes, rejecting any extra group/other or setuid/setgid/sticky bit.
- **Symlink-hardened.** Every path component is `lstat`ed; a symlink is refused. Reads `open(2)` with `O_NOFOLLOW|O_NOCTTY|O_CLOEXEC`, then `fstat` the descriptor and compare `(dev, ino)` with the earlier `lstat`, rejecting a file swapped between the two calls (`StoreError::PathChanged`).
- **Atomic writes.** `mkstemp` → `fchmod 0600` → `write` → `fsync(file)` → `rename`/`link` → `fsync(dir)`. Failure paths remove the temp file.
- **Bounded reads.** Records are capped at 256 KiB, config at 64 KiB, wire responses at 64 KiB, requests at 8 KiB; caps are enforced *while reading*.
- **No shell, no temp challenge file.** The challenge and `clientDataJSON` travel over stdin via a length-prefixed frame; the runner spawns with an argument array and `current_dir = win_mnt`, so there is no shell and no on-disk challenge.

---

## PAM fail-closed mapping (summary)

From `crates/wsl-webauthn-pam/src/lib.rs`:

<!-- INVARIANT: PAM-ONE-SUCCESS-PATH, PAM-PANIC-ABORT, PAM-NON-AUTH-EXPORTS, PAM-FAIL-DELAY -->

| Situation | PAM code |
|---|---|
| Verified assertion | `PAM_SUCCESS` |
| No credential record / null, empty, or invalid username | `PAM_USER_UNKNOWN` |
| Config missing/invalid; store error (ownership, symlink, corrupt, I/O); bridge pin mismatch or missing; runner failure (interop unavailable, bridge missing, spawn, transport, timeout); `not_available`/`not_supported`/`timeout`/`busy`/`invalid_parameter`/`internal` | `PAM_AUTHINFO_UNAVAIL` |
| `user_cancelled`; any `VerifyError`; echo/credential-id mismatch; malformed response | `PAM_AUTH_ERR` |
| Panic in module code | `PAM_ABORT` |
| `pam_sm_setcred` | `PAM_SUCCESS` |
| Any other non-authentication `pam_sm_*` | `PAM_IGNORE` |

There is exactly one path to `PAM_SUCCESS`: a fully verified assertion. Every failure path also requests `pam_fail_delay(pamh, 2_000_000)` (2 s) to blunt consent spam. No attempt counter is persisted across processes; the PAM stack owns retry policy.

> **Fall-through caveat.** `PAM_USER_UNKNOWN`/`PAM_AUTHINFO_UNAVAIL` fall through to the next method only when the PAM stack is configured to allow it (`sufficient`, or `[success=end default=ignore]`). Under a required-only stack the denial is final. Keep a working fallback (see the README lockout warning).

---

## Accepted residual risk

The user-facing wording is in the [README](README.md#limits-and-accepted-residual-risk).

- **Compromised Windows session.** Ceremony initiation is possible (subject to user verification) and the bridge can be replaced, but attestation + UV + Linux-side verification mean this does **not** yield silent root and does **not** let a replaced bridge forge an assertion; it does allow **consent phishing**.
- **Compromised Linux root.** Out of scope by definition.
- **Consent blinding is mitigated, not eliminated.** Neither WebAuthn nor a custom PAM notice can make the OS prove *which process* raised the ceremony.
- **Not a roaming authenticator.** Machine loss/reset ⇒ re-enrollment by design. Windows cannot enumerate/delete non-resident platform credentials, so old keys from `--replace`/re-enrollment are orphaned (inert without their credential ID, which only the Linux store holds).
- **No hardware side-channel defense.** TPM/platform behavior is trusted as-is.

The RP ID is a **scoping/display** mechanism, not a browser-grade origin guarantee; the guarantee is "bound to this pinned RP ID."

---

## Cryptography and dependencies

- No OpenSSL. The verifier is hand-rolled pure Rust over `ciborium`, `p256`, `ecdsa`, `sha2`, `rsa`, `ed25519-dalek`, `x509-cert`, `der`, `const-oid`.
- Builds use `--locked`; third-party CI actions are pinned to commit SHAs; `cargo-deny` checks advisories, licenses, and sources (`deny.toml`).
- **RUSTSEC-2023-0071** (non-constant-time RSA private-key operations in `rsa`) is knowingly accepted: it reaches us only through public-key-only RS256 / attestation verification, no RSA private key exists in the project, and the PAM path is local and never network-reachable (rationale in `deny.toml`).
- Real-machine attestation vectors are **never committed** — they contain machine-linked key material and live only in the git-ignored `tests/vectors/local/`.
