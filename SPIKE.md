# Windows WebAuthn spike — findings

Empirical results from running the bridge on a real Windows host: WSL2 on Windows 11, a
local Windows user at the keyboard, TPM ready, Windows Hello enrolled.

**Redaction rule:** account SID, username, and machine identifiers are not recorded in this
document, and machine-linked key material is never committed. Captured vectors live only in
the git-ignored `tests/vectors/local/`.

## API surface

`probe` returned `api_version = 9` (`WebAuthNGetApiVersionNumber()`), with Windows Hello
and TPM available.

The bridge's declared struct versions worked unchanged on api 9:

| Struct | Declared | Filled |
|---|---|---|
| `MAKE_CREDENTIAL_OPTIONS` | v9 size | `dwVersion = 3` |
| `GET_ASSERTION_OPTIONS` | v9 size | `dwVersion = 4` |
| `WEBAUTHN_ASSERTION` | v6 size | — |

No `invalid_parameter` and no over/under-allocation fault.

On the Windows 10 1903 (build 18362) API floor, `client_data_json_echo` is absent unless
`WEBAUTHN_ASSERTION.dwVersion >= 6`. The bridge then returns `None`, serialized as
`"client_data_json_echo": null`
(`crates/wsl-webauthn-bridge/src/ffi.rs::get_assertion`). The PAM module must treat `null`
as "no echo" and fall back to its own stored clientData bytes rather than fail closed. This
host always provides the echo.

## RP ID acceptance

> **Superseded:** the pinned RP ID was later shortened to `wsl-webauthn-pam` (the
> `kirin-xiao` segment was dropped from the displayed name). The measurements below were
> taken with the original string and are kept as the record of the platform-acceptance
> experiment; the same acceptance was re-checked for the new value.

`rp_id = io.github.kirin-xiao.wsl-webauthn-pam` (original), with `origin` pinned equal to
the RP ID.

Enrollment returned `ok:true`. In `authenticatorData`:

```
rpIdHash = 7c76942798253f3dacc9920309f0b87735aa5de21ddae615cef26255a7b0e4fc
SHA-256("io.github.kirin-xiao.wsl-webauthn-pam") = 7c7694…e4fc   equal
```

The platform accepts the pinned string with no `invalid_parameter`/NTE error and hashes it
exactly.

## clientDataJSON pass-through

The Linux side builds `clientDataJSON` and sends it verbatim; the bridge never inspects it.
On assertion (`ASSERTION.dwVersion >= 6`) the response carried `client_data_json_echo`:

| Check | Result |
|---|---|
| echo base64url string == sent | true |
| decoded echo bytes == sent bytes | true |
| decoded echo | exactly `{"type":"webauthn.get","challenge":"…","origin":"io.github.kirin-xiao.wsl-webauthn-pam"}` |
| signature over `authData ‖ SHA-256(clientData)` verifies with the enrolled COSE key | true |

`WEBAUTHN_ASSERTION.pbClientDataJSON` is the raw bytes passed in, not a re-encoded form, so
the PAM module can compare the echoed bytes to the bytes it minted without normalization.

The assertion's `authenticatorData` has `AT = 0`, so no COSE key is embedded in an
assertion; verification uses the enrolled key.

## Attestation format and chain

With `attestation = DIRECT`, `UV = REQUIRED`, `attachment = PLATFORM`, Windows Hello
returned format `tpm`:

```
fmt        = "tpm"
attStmt    = { ver: "2.0", alg: -65535, x5c: [ … 2 certs … ],
               sig: <256 B>, certInfo: <161 B>, pubArea: <118 B> }
authData   = 164 bytes, flags 0x45 (UP|UV|AT), signCount 0
AAGUID     = 9ddd1817-af5a-4672-a2b9-3e3dd95000a9
COSE       = ES256 (-7), EC2 P-256, uncompressed point
credential_id = 32 bytes; reported id == id inside authData
```

`alg = -65535` is `TPM_ALG_NULL`. `x5c` holds the AIK leaf plus its intermediate;
`certInfo`/`pubArea` are TPMT_PUBLIC / TPMS_ATTEST structures.

The pinned root is `Microsoft TPM Root Certificate Authority 2014`,
`SHA-256 = 87:0C:7A:35:CE:AB:3D:59:97:9F:2C:6A:52:40:42:D4:04:CB:71:51:80:04:35:09:25:FB:2C:ED:79:A9:99:DA`.
Exporting the same-named certificate from the Windows `ROOT` store gives exactly that
fingerprint. The chain has two links:

| Cert | Role | Notes |
|---|---|---|
| `x5c[1]` | intermediate | subject is a per-TPM-vendor key-id string (not recorded here); RSA-4096, `CA:TRUE, pathlen:0`, EKU `1.3.6.1.4.1.311.21.36` + AIK; issued by the pinned root |
| `x5c[0]` | AIK leaf | empty subject, EKU AIK, RSA-2048; issued by the intermediate |

`openssl verify -CAfile <pinned root> -untrusted <x5c[1]> <x5c[0]>` → OK.

The `tpm` leaf has an empty subject and no `OU = "Authenticator Attestation"` and no FIDO
AAGUID extension (`1.3.6.1.4.1.45724.1.1.4`); those rules apply to `packed`, not to `tpm`.
For `tpm`, authenticity comes from `certInfo`/`pubArea` signed by the AIK plus the AIK chain
to the pinned root, and the AAGUID is carried in `authenticatorData`.

A Strict policy that admits only `packed`/AttCA would refuse this platform's own TPM
attestation, since `tpm` is outside that scope. A `tpm` path — attStmt parse,
`pubArea`/`certInfo` consistency, AIK chain-to-pinned-root — is needed to admit it; the
observed chain already verifies to the pinned root and the AAGUID is in the Strict set.

## Unattested first-ever enrollment

Across four enrollment ceremonies:

| # | RP ID | fmt |
|---|---|---|
| 1 | `io.github.kirin-xiao.wsl-webauthn-pam` | `tpm` |
| 2 | `io.github.kirin-xiao.wsl-webauthn-pam-test` (first ever for this RP) | `none` (empty attStmt) |
| 3 | `io.github.kirin-xiao.wsl-webauthn-pam` | `tpm` |
| 4 | `io.github.kirin-xiao.wsl-webauthn-pam-test` | `tpm` |

A first-ever credential may yield `none` (empty `attStmt`) instead of `tpm`, so `none` is
not a guaranteed first-enrollment outcome. A Strict install that only admits `none` under
`AllowUnattested` can therefore reject a first enrollment; first-enroll handling needs an
explicit policy (pre-warm the RP, admit `none` for the first enrollment only, or require
`--allow-unattested` for it).

## Timeout enforcement and self-cancel

`assert` with `timeout_ms = 5000`, prompt deliberately not touched:

```
linux deadline (harness) = 30 s
observed elapsed         = 5.13 s
linux deadline hit       = false
response                 = {"op":"*","ok":false,"error":"user_cancelled"}
stderr                   = PID <n>
                           WebAuthNAuthenticatorGetAssertion: hr=0x80090036 NotAllowedError
stray processes          = none
```

The bridge's watchdog fired at ~5 s and the ceremony self-cancelled before the Linux-side
deadline; no stray Windows process remained after exit.

`WebAuthNCancelCurrentOperation` makes the platform return `NTE_USER_CANCELLED`
(`0x80090036`, `NotAllowedError`), the same HRESULT a manual cancel produces, so the wire
error alone does not distinguish "timed out" from "user hit cancel". Both map to
`PAM_AUTH_ERR`. The bridge distinguishes them locally: when its own watchdog fired it
reports `timeout` regardless of the HRESULT
(`crates/wsl-webauthn-bridge/src/ceremony.rs::remap_watchdog_fire`); a genuine user cancel —
watchdog not fired — still reports `user_cancelled`.

## User-cancel mapping

`assert`, user pressed Cancel: elapsed 13.1 s, response
`{"op":"*","ok":false,"error":"user_cancelled"}`, `hr = 0x80090036` (`NTE_USER_CANCELLED` /
`NotAllowedError`), exit 0, no stray process.

## Second-RP-ID experiment

A spike-only exe pinning `io.github.kirin-xiao.wsl-webauthn-pam-test`
(`spike/build_testrp.sh` patches the compile-time `RP_ID` constant, builds, and restores the
source; the patch is never committed).

* Enrollment on the `-test` RP accepted (`ok:true`, `rpIdHash == SHA-256` of the test
  string); the prompt showed the test string.
* Assertion against that credential succeeds end-to-end (UP/UV, signature verifies, echo
  byte-exact).
* Re-enroll on the same `-test` RP: `tpm`.

RP IDs of the pinned shape are flexible; the platform does not restrict the suffix.

Windows exposes no API to enumerate or delete non-resident platform credentials: they are
keyed by a credential-ID hash and invisible in Settings. Credentials created for testing
cannot be removed from the Windows side and become orphaned — they are never selectable
without their credential ID, which only the Linux store would hold. Re-enrolling under a new
RP ID or with `--replace` leaves the old Windows key in place.

## Prompt UX

Windows Security dialog during `assert` (screenshot not committed):

```
┌─ Windows Security ────────────────────────────────────────┐
│  Sign in with a passkey                                    │
│                                                            │
│  ●─  <user_name>                              ○───○         │
│      Passkey for wsl-webauthn-pam                          │
│                                                            │
│              ⋮⋮⋮ ⋮⋮⋮ ⋮⋮⋮                                   │
│              Enter your PIN                                │
│              [ PIN __________________ ]                    │
│              I forgot my PIN                               │
│                          [ Cancel ]                        │
└────────────────────────────────────────────────────────────┘
```

* Heading: "Sign in with a passkey".
* Primary line: the `user_name` passed in the request.
* Secondary line: "Passkey for `<RP_ID>`" — it shows the RP ID, not `RP_NAME`.
* `user_display_name` is not shown.
* No `challenge`/`origin` is shown.
* Enrollment uses the same dialog.

The dialog shows the RP ID string; `RP_NAME` (e.g. `sudo on WSL (wsl-webauthn-pam)`) and
`user_display_name` are not displayed by this Windows build. To surface a friendlier service
name, fold it into `RP_ID` or show it through a PAM `pam_conv` info message on the Linux
side; the Windows-side dialog will not show it.

## HWND / focus behavior

Enumerated top-level windows throughout a self-cancelling (`timeout_ms = 15000`) assertion
via a `user32!EnumWindows` probe:

```
t≈1.0s..14.3s  visible  iconic=N  rect=0,0,456,502  owner='WSLWebAuthnBridge'  title='Windows Security'
t<1.0s, t>14.9s  (no such window)
```

* The dialog is a normal, visible top-level window, appears ~1 s into the ceremony, and
  disappears on cancel/timeout. It is a direct child/owned window of the bridge's hidden
  window (`owner = WSLWebAuthnBridge`), so Windows Hello is parented to the bridge's HWND,
  not to whatever was foreground.
* The dialog is not initially the system foreground window: the foreground stayed on other
  apps for several seconds, and the dialog only became foreground later. Parentage is
  correct, but the dialog does not always force itself foreground.
* No taskbar flash was observed.

If the prompt must come to the front, the bridge may need to call `SetForegroundWindow` on
its own HWND (or flash) after the ceremony starts. Focus was being actively used (a browser
in front), the worst case for foreground stealing; a quiet session may be milder.

**Implemented.** The bridge (a) passes the current visible
`GetForegroundWindow()` as the WebAuthn `hWnd` (libfido2 does the same) so the dialog is
owned by the window the user is looking at, and (b) runs a bounded focus watcher thread
around each blocking ceremony: it polls for a **visible** top-level window whose class is
`Credential Dialog Xaml Host` **and** whose owner is the HWND we passed (matched by class,
never the localized title; the owner match blocks a look-alike from stealing focus), then
tries `SetForegroundWindow`, then `AttachThreadInput` + `SetForegroundWindow`/
`BringWindowToTop`/`SetFocus` (RAII-detached, attempted once per dialog), then
`FlashWindowEx(FLASHW_ALL | FLASHW_TIMERNOFG)`. It also writes `PROGRESS prompt_open` /
`PROGRESS prompt_closed` to stderr, which the CLI surfaces as a PIN line and the PAM
module logs at debug level; the runner additionally emits explicit start/finish
boundaries so the CLI's step counter is unaffected if the bridge's trailing
`prompt_closed` is lost to the pipe close. All of this is best-effort: denial degrades
to a taskbar flash and never changes the ceremony result. The owner/ladder choice still
needs confirmation on a real host, and non-English Windows is specifically why the
class-only match is used.

## Bridge version resource

The Windows WebAuthn prompt can surface a "Requested by <name> (<publisher>)" line
sourced from the **calling executable's version resource** (documented in
`microsoft/webauthn`'s `webauthn.h`, and used by the DEF CON "Passkeys Pwned" work).
`WSLWebAuthnBridge.exe` originally carried no resource, so the prompt could not name its
requester.

`crates/wsl-webauthn-bridge/build.rs` now compiles `bridge.rc` into a `VERSIONINFO`
resource for Windows targets (`rc.exe` for MSVC; `windres` + a direct linker argument for
the GNU cross target — a resource-only object in a `static` archive is *not* pulled in, so
the object is passed to the linker directly). The build is best-effort: if no resource
compiler is found, the bridge is produced unchanged. The cross-built exe was checked to
contain a `.rsrc` section and the UTF-16 `FileDescription`/`ProductName` strings.

This is UX-only and carries no trust: the Linux side pins the whole `.exe` by SHA-256, so
the resource cannot influence verification. Whether this Windows build renders the line,
and exactly how, still needs confirmation on a real host.

## Not exercised on this host

* **UV-required error path** (`not_available` / UV unavailable): would require a Windows
  account with Hello not enrolled. Unit tests cover the mapping.
* **aarch64**: no hardware.
* **`busy` (`NTE_EXISTS`)**: would need a concurrent ceremony.

## Golden vectors (git-ignored)

`tests/vectors/local/spike-enroll-assert.json` holds `{rp_id, origin, client_data_json,
enroll_request, enroll_response, enroll_summary, assert_request, assert_response,
assert_summary}` for the pinned RP. It contains machine-linked key material and is never
committed; `tests/vectors/local/` is git-ignored, with only the `.gitignore` rule committed,
plus a local `tests/vectors/local/bridge.sha256` recording the built exe hash. A
real-machine conformance test can be added from the stored pair as an `#[ignore]`d test.
`python3 spike/harness.py verify tests/vectors/local/spike-enroll-assert.json` self-checks
the pair and reports `VERDICT: OK`.

## Reproduction

See `spike/README.md`. Build the gnu-target exe, then run `python3 spike/harness.py probe`,
`… enroll --out tests/vectors/local/…`, `… assert --merge … --out …`, `… verify …`. Every
invocation is deadline-bounded; `spike/build_testrp.sh` reproduces the second-RP-ID
experiment.
