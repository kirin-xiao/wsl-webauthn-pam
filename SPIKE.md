# Stage-1 Windows WebAuthn spike — empirical findings

**Scope:** validate plan decisions **D2** (RP ID shape / acceptance), **D3**
(attestation format + chain), **D5** (API floor / echo field) against a real
Windows host, and capture golden vectors for the verifier (plan §11, §13 wave B3).

**Host (redacted):** WSL2 on Windows 11, local Windows user present at the
keyboard, TPM ready, Windows Hello enrolled. Account SID / username / machine
identifiers are intentionally omitted. Captured vectors (which contain
machine-linked key material) live only in the git-ignored
`tests/vectors/local/`.

**Status: two plan-level findings need a decision (D3).** Details in
[§4](#4-attestation-format--chain-d3--plan-critical) and
[§7](#7-second-rp-id-experiment-d2-robustness). D2 and D5 are **confirmed**.

---

## 0. Verdict summary

| Plan item | Verdict | Evidence |
|---|---|---|
| **D2** RP ID `io.github.kirin-xiao.wsl-webauthn-pam` accepted, origin == RP ID | ✅ confirmed | enroll returned `ok:true`; `rpIdHash == SHA-256(RP_ID)` byte-exact |
| **D2** second RP-ID shape `…-pam-test` also accepted | ✅ confirmed | enroll + assert end-to-end on the `-test` RP |
| **D5** clientData pass-through via `client_data_json_echo` | ✅ confirmed (api 9) | echo b64url == sent b64url; decoded bytes identical |
| **D5** API floor 1903; echo null when `ASSERTION < v6` | ✅ code path verified | bridge emits `null`; unit-tested |
| **D3** Strict = `packed`/AttCA | ❌ **not what this host returns** | real format is **`tpm`**, plus **`none` on the first-ever enrollment per RP ID** |

---

## 1. Environment & probe

```
$ python3 spike/harness.py --deadline 30 probe
{"op":"probe","ok":true,"uv_platform_available":true,"api_version":9}
```

* `uv_platform_available = true` (Windows Hello + TPM present).
* `api_version = 9` — matches the plan's expectation of v9 on this machine.
  `WebAuthNGetApiVersionNumber()` is present and returns 9.

The bridge's declared struct versions worked unchanged on api 9:
`MAKE_CREDENTIAL_OPTIONS` declared at v9 size / filled `dwVersion = 3`,
`GET_ASSERTION_OPTIONS` at v9 size / filled `dwVersion = 4`,
`WEBAUTHN_ASSERTION` declared at v6 size. No `invalid_parameter`, no
over/under-allocation fault.

---

## 2. RP ID acceptance (D2)

Enrollment with the pinned constants:

```
rp_id   = io.github.kirin-xiao.wsl-webauthn-pam
origin  = io.github.kirin-xiao.wsl-webauthn-pam   (D2: origin pinned equal to RP ID)
```

result: `ok:true`, and in `authenticatorData`:

```
rpIdHash = 7c76942798253f3dacc9920309f0b87735aa5de21ddae615cef26255a7b0e4fc
SHA-256("io.github.kirin-xiao.wsl-webauthn-pam") =
           7c76942798253f3dacc9920309f0b87735aa5de21ddae615cef26255a7b0e4fc   ✅ equal
```

**Verdict:** the pinned RP ID is accepted with no `invalid_parameter`/NTE error,
and the platform hashes exactly the pinned string. D2 is confirmed for this host.

---

## 3. clientDataJSON pass-through (D5 / §3)

The Linux side builds `clientDataJSON` (challenge owner) and sends it verbatim;
the bridge never inspects it. On assertion (api 9 ⇒ `ASSERTION.dwVersion >= 6`)
the response carried `client_data_json_echo`.

| Check | Result |
|---|---|
| `echo == sent` (base64url string) | ✅ `True` |
| decoded echo bytes == sent bytes | ✅ `True` |
| decoded echo (UTF-8) | exactly `{"type":"webauthn.get","challenge":"…","origin":"io.github.kirin-xiao.wsl-webauthn-pam"}` |
| signature over `authData ‖ SHA-256(clientData)` verifies with the enrolled COSE key | ✅ `True` |

So `WEBAUTHN_ASSERTION.pbClientDataJSON` **is the raw `clientDataJSON` bytes**
the bridge passed in (not a re-encoded form), and the round-trip is byte-exact.
This gives the PAM module a real consistency bonus: it can compare the echoed
bytes to the bytes it minted without any normalization.

**Verdict:** D5/§3 clientData pass-through is confirmed on this host.

> Note for the verifier: the assertion's `authenticatorData` has `AT = 0`, so no
> COSE key is embedded in an assertion; verification must use the enrolled key
> (as planned).

---

## 4. Attestation format & chain (D3) — PLAN-CRITICAL

### 4.1 Observed format is `tpm`, not `packed`

With `attestation = DIRECT`, `UV = REQUIRED`, `attachment = PLATFORM`, Windows
Hello returned:

```
fmt        = "tpm"
attStmt    = { ver: "2.0", alg: -65535, x5c: [ … 2 certs … ],
               sig: <256 B>, certInfo: <161 B>, pubArea: <118 B> }
authData   = 164 bytes, flags 0x45 (UP|UV|AT), signCount 0
AAGUID     = 9ddd1817-af5a-4672-a2b9-3e3dd95000a9   ← in the D3 Strict set
COSE       = ES256 (-7), EC2 P-256, uncompressed point
credential_id = 32 bytes; reported id == id inside authData  ✅
```

`alg = -65535` = `TPM_ALG_NULL` (the spec's value for "key type/attestation not
specified"). `x5c` holds the **AIK leaf + its intermediate**; `certInfo`/`pubArea`
are TPMT_PUBLIC / TPMS_ATTEST structures.

**Plan impact.** D3 (`Strict = packed/AttCA only`) and D4 (`Scope: packed … none`)
do **not** include `tpm`. On this machine a Default install under Strict would
therefore **refuse the platform's own TPM attestation**. Options:

1. add a verified **`tpm` attestation path** to the verifier (attStmt parse,
   `pubArea`/`certInfo` consistency, AIK chain-to-pinned-root) and admit it under
   Strict — most faithful to "TPM-backed Windows Hello";
2. keep D4's scope, but then Strict cannot be the default on real Windows
   hardware and the plan must say so explicitly (accept self/none, or fail);
3. document `tpm` as unsupported for now and require `--allow-unattested`
   (rejected under Strict) — i.e. no verified attestation on this class of host.

Recommendation: **1**. The observed `x5c` chain already verifies to the pinned
root (below) and the AAGUID is in the Strict set, so a `tpm` verifier is
tractable.

### 4.2 The chain-to-pinned-root assumption *does* hold

D3 pins `Microsoft TPM Root Certificate Authority 2014`
(`SHA-256 = 87:0C:7A:35:CE:AB:3D:59:97:9F:2C:6A:52:40:42:D4:04:CB:71:51:80:04:35:09:25:FB:2C:ED:79:A9:99:DA`).

* The **pinned fingerprint is exact**: exporting the same-named certificate from
  the Windows `ROOT` store yields precisely that fingerprint. Verified with
  `openssl x509 -fingerprint -sha256`.
* The certificate delivered in `x5c[1]` is an **intermediate** whose subject is
  a per-TPM-vendor key-id string (redacted here as it is machine-linked;
  RSA-4096, `CA:TRUE, pathlen:0`, EKU
  `1.3.6.1.4.1.311.21.36` + Attestation Identity Key Certificate),
  **issued by** the pinned root. It is **not** the pinned root itself (different
  fingerprint).
* `x5c[0]` is the AIK leaf, **issued by** the intermediate. It has an **empty
  subject**, EKU `Attestation Identity Key Certificate`, RSA-2048. (The leaf DER
  length and a fingerprint are recorded only in the git-ignored local vector,
  not here.)
* `openssl verify -CAfile <pinned root> -untrusted <x5c[1]> <x5c[0]>` → **OK**.

So the 2-link model in D3 ("build the 2–3 link chain to the pinned root") is
right, and the pin is correct. ✅

### 4.3 Two leaf assumptions in D3/§4 are wrong for `tpm` material

§4 requires of the attestation leaf: `OU = "Authenticator Attestation"` and an
AAGUID extension (`1.3.6.1.4.1.45724.1.1.4`). The observed **`tpm` leaf has
neither** — its subject is *empty* and there is no FIDO AAGUID extension. Those
rules are `packed`-specific. For `tpm`, authenticity comes from `certInfo`/
`pubArea` signed by the AIK plus the AIK chain to the pinned root; the AAGUID is
still carried in `authenticatorData` and was in the Strict set here. A `tpm`
verifier must not reuse the `packed` leaf rules. ⚠️ verifier agent note.

### 4.4 First-ever enrollment per RP ID returns `none` — re-enrollment hazard

Across four enrollment ceremonies:

| # | RP ID | fmt |
|---|---|---|
| 1 | `io.github.kirin-xiao.wsl-webauthn-pam` | **`tpm`** |
| 2 | `io.github.kirin-xiao.wsl-webauthn-pam-test` (first ever for this RP) | **`none`** (empty attStmt) |
| 3 | `io.github.kirin-xiao.wsl-webauthn-pam` | `tpm` |
| 4 | `io.github.kirin-xiao.wsl-webauthn-pam-test` | `tpm` |

Pattern: the **first credential ever created for an RP ID yields `none`** (empty
`attStmt`, 194-byte attestation object); **subsequent** credentials for the same
RP ID yield `tpm`. (The RP is not yet known/trusted to the platform on the very
first create.)

**Plan impact.** With D3 Strict, the **very first enrollment for RP_ID would be
rejected** (`none` is only admitted under `AllowUnattested`). This is a
hard blocker for a clean first `wsl-webauthn-pam enroll` on a fresh machine.
Options: pre-warm the RP (undesirable), admit `none` only for the first
enrollment, or ship with `--allow-unattested` guidance for first enroll. Needs a
plan decision alongside §4.1.

---

## 5. Timeout enforcement & self-cancel

`assert` with `timeout_ms = 5000`, prompt deliberately not touched:

```
linux deadline (harness) = 30 s
observed elapsed         = 5.13 s
linux deadline hit       = False
response                 = {"op":"*","ok":false,"error":"user_cancelled"}
stderr                   = PID <n>
                           WebAuthNAuthenticatorGetAssertion: hr=0x80090036 NotAllowedError
stray processes          = none (tasklist.exe shows no WSLWebAuthnBridge)
```

* The bridge's own watchdog fired at ~5 s and the ceremony self-cancelled
  **before** the Linux-side deadline — the Linux deadline never had to fire. ✅
* No stray Windows process remained after exit. ✅
* **Deviation:** the taxonomy is **`user_cancelled`, not `timeout`**.
  `WebAuthNCancelCurrentOperation` makes the platform return
  `NTE_USER_CANCELLED` (`0x80090036`, `NotAllowedError`) — the *same* HRESULT a
  manual cancel produces. The bridge maps that to `user_cancelled`.
  Consequently the PAM module cannot distinguish "timed out" from "user hit
  cancel" from the wire error alone.

  This is harmless for the §8 PAM mapping (both map to `PAM_AUTH_ERR`), but it
  contradicts the §3 taxonomy's intent that `timeout` be distinguishable. If
  distinguishable timeout logging is wanted, the bridge should decide it
  locally: when its watchdog fired, report `timeout` regardless of the HRESULT.
  **Recommend a small bridge/plan tweak.**

---

## 6. User-cancel mapping

`assert`, user pressed Cancel: elapsed 13.1 s, response
`{"op":"*","ok":false,"error":"user_cancelled"}`, `hr = 0x80090036`
(`NTE_USER_CANCELLED` / `NotAllowedError`), exit 0, no stray process. ✅ maps to
`user_cancelled` exactly as planned (§3, §8 → `PAM_AUTH_ERR`).

---

## 7. Second-RP-ID experiment (D2 robustness)

Built a spike-only exe pinning `io.github.kirin-xiao.wsl-webauthn-pam-test`
(`spike/build_testrp.sh`; the protocol constant is patched, built, then restored
— never committed).

* Enrollment on the `-test` RP: **accepted** (`ok:true`, `rpIdHash == SHA-256`
  of the test string). The prompt showed the test string.
* Assertion against that credential: **succeeds end-to-end** (UP/UV, signature
  verifies, echo byte-exact).
* Re-enroll on the same `-test` RP: `tpm` (see §4.4).

**Verdict:** RP IDs of the pinned shape are flexible — the platform does not
restrict the suffix. D2's RP-ID form is safe.

**Cleanup note (SR-OUT-4 / CR-6 adjacent):** Windows exposes **no API to
enumerate or delete non-resident platform credentials** — they are keyed by a
credential-ID hash and invisible in Settings. The `-test` credentials (and the
second pinned-RP test credential) created during the spike therefore **cannot be
removed from the Windows side**; they are simply orphaned (never selectable
without their credential ID, which only the Linux store would hold). This is an
accepted consequence but should be documented for users (re-enroll under a new
RP ID/`--replace` leaves the old Windows key in place).

---

## 8. Prompt UX (SR-11 consent clarity)

Screenshot of the Windows Security dialog during `assert` (not committed):

```
┌─ Windows Security ────────────────────────────────────────┐
│  Sign in with a passkey                                    │
│                                                            │
│  ●─  spike                                    ○───○         │
│      Passkey for io.github.kirin-xiao.wsl-webauthn-pam     │
│                                                            │
│              ⋮⋮⋮ ⋮⋮⋮ ⋮⋮⋮                                   │
│              Enter your PIN                                │
│              [ PIN __________________ ]                    │
│              I forgot my PIN                               │
│                          [ Cancel ]                        │
└────────────────────────────────────────────────────────────┘
```

* Heading: **"Sign in with a passkey"**.
* Primary line: the **`user_name`** passed in the request (`spike`).
* Secondary line: **"Passkey for `<RP_ID>`"** — it shows the **RP ID**, *not*
  `RP_NAME` (`sudo on WSL (wsl-webauthn-pam)`).
* **`user_display_name` is not shown.**
* No `challenge`/`origin` is shown.
* Enrollment uses the same dialog ("Sign in with a passkey" / create flow).

**SR-11 implication:** the dialog shows the RP ID string; `RP_NAME` (the
human-readable "sudo on WSL (wsl-webauthn-pam)") is **not** displayed by this
Windows build, and neither is `user_display_name`. If consent clarity depends on
showing a friendly service name, either fold the desired text into `RP_ID`
(compile-time constant, D2) or surface it through the PAM `pam_conv` info
message (§8 already plans a "Windows Hello: authenticating sudo for `<user>`"
prompt on the Linux side) — the Windows-side dialog will not do it. Also note
"passkey" wording (not "Windows Hello") is what the user sees.

---

## 9. HWND / focus behavior

Enumerated top-level windows throughout a self-cancelling (`timeout_ms=15000`)
assertion via a `user32!EnumWindows` probe:

```
t≈1.0s..14.3s  visible  iconic=N  rect=0,0,456,502  owner='WSLWebAuthnBridge'  title='Windows Security'
t<1.0s, t>14.9s  (no such window)
```

* The dialog is a **normal, visible top-level window**, appears **~1 s** into the
  ceremony and disappears on cancel/timeout. It is a **direct child/owned window
  of the bridge's hidden window** (`owner = WSLWebAuthnBridge`). This is strong
  evidence the §5 hidden-window model works: Windows Hello is parented to the
  bridge's HWND, not to whatever happened to be foreground.
* The dialog is **not initially the system foreground window**: sampling showed
  the foreground stayed on other apps (Chrome) for several seconds, and the
  dialog only became foreground later/at the end of the sampling window.
  So the legacy "Hello appears in background" class of symptom is **not** fully
  eliminated by the HWND alone — parentage is correct, but the dialog does not
  always force itself foreground.
* No taskbar flash was observed during the sampling window.

**Recommendation:** if "prompt must come to the front" is a requirement, the
bridge may need to additionally `SetForegroundWindow`/allow-foreground on its
own HWND (or flash) after the ceremony starts. Parentage (the structural fix) is
in place and verified; foreground acquisition is not guaranteed. Note this
machine's focus was being actively used (a browser was in front), which is the
worst case for foreground stealing; the result may be milder in a quiet session.

---

## 10. Windows floor (D5)

* Observed `api_version = 9` (Windows 11). The plan's floor is Windows 10 1903
  (build 18362); that is unchanged by this spike, but note §4 (attestation) is
  the binding compatibility question, not the API version.
* **Echo field:** `client_data_json_echo` requires `WEBAUTHN_ASSERTION.dwVersion
  >= 6`. On an older API the field is absent and the bridge's FFI returns
  `None`, which `Response::assertion` serializes as `"client_data_json_echo":
  null`. **Confirmed in code** (`crates/wsl-webauthn-bridge/src/ffi.rs`,
  `get_assertion`: `if (*out).dw_version >= 6 && cb > 0 { Some(..) } else { None }`)
  and **unit-tested** (`ceremony.rs::assert_without_echo_serializes_null`). The
  PAM module must treat `null` as "no echo available" and fall back to its own
  stored clientData bytes — it must not fail-closed on a missing echo if a
  pre-API-6 host is ever supported. (On this host the echo is always present.)

---

## 11. Not exercised on this host

* **UV-required error path** (`not_available` / UV unavailable): would require a
  Windows account with Hello **not** enrolled. Not feasible without changing
  Windows state — **N/A on this host**. The unit tests cover the mapping.
* **aarch64**: no hardware — skipped.
* **`busy` (`NTE_EXISTS`)**: not exercised (would need a concurrent ceremony).

---

## 12. Deviations from plan assumptions (summary)

1. **D3/D4 — attestation format.** Real format is **`tpm`** (with `x5c`,
   `certInfo`, `pubArea`, `sig`), not `packed`; `alg = -65535`.
   *Action:* add a verified `tpm` path or explicitly narrow Strict.
2. **D3 — first-enroll returns `none`.** The first credential ever for an RP ID
   is `none`-attested; Strict would reject a fresh enroll.
   *Action:* decide policy for first enrollment.
3. **D3/§4 — leaf rules.** The `tpm` leaf has an empty subject and **no**
   `OU = "Authenticator Attestation"` and **no** AAGUID extension; those
   `packed` rules must not be applied to `tpm`.
4. **§3 — timeout taxonomy.** Watchdog self-cancel yields `user_cancelled`
   (`0x80090036`), not `timeout`.
   *Action:* optionally have the bridge report `timeout` when its own watchdog
   fired.
5. **SR-11 — prompt shows RP_ID, not RP_NAME**, and hides `user_display_name`.

Confirmed as planned: RP ID acceptance + `rpIdHash` (D2), echo pass-through (D5),
pinned root fingerprint + chain-to-pinned-root (D3), AAGUID in the Strict set,
UP/UV=1, ES256/P-256, non-resident credential, hidden-window parentage,
Linux-deadline safety margin, no stray processes.

---

## 13. Prompts triggered (for the user's awareness)

All prompts were Windows Security "Sign in with a passkey" dialogs:

1. enroll, pinned RP, `spike` — completed (→ `tpm`)
2. assert, pinned RP — completed (crash-lost; harness bug)
3. assert, pinned RP — completed
4. assert, pinned RP — **not touched** (5 s timeout test, self-cancelled)
5. assert, pinned RP — **cancel** (user-cancel test + screenshot)
6. enroll, `-test` RP, `spike-testrp` — completed (→ `none`)
7. assert, `-test` RP — completed
8. enroll, pinned RP, `spike2` — completed (→ `tpm`)
9. enroll, `-test` RP, `spike-testrp2` — completed (→ `tpm`)
10. assert, pinned RP — **not touched** (focus sample #1, self-cancelled)
11. assert, pinned RP — **not touched** (focus sample #2, self-cancelled)

---

## 14. Golden vectors (git-ignored)

`tests/vectors/local/spike-enroll-assert.json` — `{rp_id, origin,
client_data_json, enroll_request, enroll_response, enroll_summary,
assert_request, assert_response, assert_summary}` for the pinned RP on this
host, enough for the verifier owner (A1/R1) to add an `#[ignore]`d
real-machine conformance test by copying it into their own branch. **Not
committed** (contains machine-linked key material). `tests/vectors/local/` is
git-ignored (`.gitignore`); only the ignore rule is committed, plus
`tests/vectors/local/bridge.sha256` (local, ignored) recording the built exe
hash.

Self-check of the stored pair:

```
$ python3 spike/harness.py verify tests/vectors/local/spike-enroll-assert.json
enroll: rpIdHash matches ✅  UP ✅  UV ✅  AAGUID 9ddd1817-… ✅
assert: UP ✅  UV ✅  rpIdHash ✅  signature verifies ✅  echo == sent ✅
VERDICT: OK
```

---

## 15. Reproduction

See `spike/README.md`. In short: build the gnu-target exe, then
`python3 spike/harness.py probe`, `… enroll --out tests/vectors/local/…`,
`… assert --merge … --out …`, `… verify …`. Every invocation is deadline-bounded;
`spike/build_testrp.sh` reproduces the second-RP-ID experiment.
