+++
title = "How it works"
description = "From sudo to PAM to the Windows bridge to Windows Hello — and back, with the verification on the Linux side."
weight = 2
+++

`sudo` does not change. It asks PAM to authenticate, PAM loads
`pam_wsl_webauthn.so`, and the module either returns `PAM_SUCCESS` after a
verified Windows Hello assertion or falls through to the next method.

## The sequence

<figure class="sequence" aria-labelledby="sequence-caption">
<figcaption class="sequence__caption" id="sequence-caption">One <code>sudo</code> call, from the Linux side across the WSL boundary to Windows Hello and back. Verification happens after the return trip.</figcaption>

<div class="sequence__zone sequence__zone--host">
<p class="sequence__zone-title">Linux side · root-owned</p>
<ol class="sequence__steps">
  <li><strong>You / shell</strong> — run <code>sudo whoami</code>.</li>
  <li><strong>sudo → PAM stack</strong> — PAM asks the configured modules to authenticate <code>alice</code>.</li>
  <li><strong>pam_wsl_webauthn.so</strong> — loads the credential record for the user and mints a fresh 32-byte challenge.</li>
  <li><strong>pam_wsl_webauthn.so</strong> — spawns the bridge over WSL interop: framed stdio, no shell, no temporary challenge file.</li>
</ol>
</div>

<p class="sequence__boundary"><strong>WSL boundary — Linux side → Windows side.</strong> The challenge and <code>clientDataJSON</code> cross as a length-prefixed frame on the child's stdin. Nothing listens on a socket; this is local interop, not a service.</p>

<div class="sequence__zone sequence__zone--windows">
<p class="sequence__zone-title">Windows side · user session</p>
<ol class="sequence__steps" start="5">
  <li><strong>WSLWebAuthnBridge.exe</strong> — calls <code>WebAuthNAuthenticatorGetAssertion</code> with user verification required.</li>
  <li><strong>Windows Hello</strong> — raises the passkey prompt: PIN, fingerprint, or face.</li>
  <li><strong>You</strong> — perform the gesture in the Windows-owned dialog.</li>
  <li><strong>Windows Hello → bridge</strong> — the platform authenticator signs and returns an assertion.</li>
</ol>
</div>

<p class="sequence__boundary"><strong>WSL boundary — Windows side → Linux side.</strong> Only bytes come back: <code>authenticatorData</code>, <code>signature</code>, <code>credentialId</code>. The PIN or biometric is checked by Windows and never leaves the dialog; it is never sent to Linux, and the module never sees it.</p>

<div class="sequence__zone sequence__zone--verify">
<p class="sequence__zone-title">Linux side · verification</p>
<ol class="sequence__steps" start="9">
  <li><strong>pam_wsl_webauthn.so</strong> — verifies the RP ID hash, the user-presence and user-verification flags, the credential binding, and the signature against the enrolled public key.</li>
  <li><strong>pam_wsl_webauthn.so → PAM</strong> — returns <code>PAM_SUCCESS</code>. Every other path is fail-closed; there is exactly one success return.</li>
  <li><strong>sudo</strong> — runs the command.</li>
</ol>
</div>

</figure>

The bridge is a courier. It makes no security decision and holds no trust: a
compromised bridge can fail, stall, or try to talk you into approving a ceremony,
but it cannot forge an assertion, because it has no private key and the verifier
checks the signature on the Linux side. The full argument is on the
[security page](@/docs/security.md).

## What you see

On `sudo`, the module prints a one-line cue naming the service and the Linux user
being elevated (for example: *Windows Hello: authenticating 'sudo' for Linux user
alice — a Windows passkey prompt is waiting; check the taskbar and do not type
here*). The Windows dialog is titled *Sign in with a passkey* and shows
**Passkey for wsl-webauthn-pam** — the pinned relying-party ID, not a
configurable display name.

The cue is suppressed with the `quiet` module argument, and it is only emitted
when a terminal is attached.

## Decline, cancel, and timeout

Cancelling the prompt is an ordinary failure: `sudo` falls through to the
password prompt (with a short delay). Pressing *cancel* in the dialog is reported
as `user_cancelled`.

The default deadline is 60 s — a 55 s advisory in the dialog plus a hard
Linux-side deadline, with up to ~5 s of cleanup. A watchdog expiry is reported as
`timeout` and also falls through. Override it with the `timeout=<secs>` module
argument or `timeout_secs` in `/etc/wsl_webauthn/config`.

## The password fallback branch

The shipped profile carries the fail-through control:

```text
[success=end default=ignore]  pam_wsl_webauthn.so
```

so nothing the module can return on a failed Hello attempt ends the stack.
`PAM_USER_UNKNOWN` (no credential record), `PAM_AUTHINFO_UNAVAIL` (missing
config, store error, bridge pin mismatch, interop unavailable, timeout) and
`PAM_AUTH_ERR` (cancel, bad signature, malformed response) are all **ignored**,
and PAM moves on to the next method — normally your password. `PAM_ABORT` (a
panic inside the module) is the one code that stops the stack.

Under a hand-edited required-only stack the denial is final. The installer
refuses to produce one, and
[Don't lock yourself out](@/docs/install.md#don-t-lock-yourself-out) is the
recovery page.

## The pins that make the return trip trustworthy

| Item | Value / rule |
|---|---|
| RP ID | `wsl-webauthn-pam`, a compile-time constant |
| Origin | pinned equal to the RP ID — this is a native client, not a browser page |
| Challenge | fresh 32 bytes, minted on the Linux side for every attempt |
| Signed message | `authenticatorData ‖ SHA-256(clientDataJSON)`, verified as ES256, RS256, or EdDSA |
| Bridge binary | SHA-256 recorded at enrollment, re-checked on every launch against the same file descriptor it executes |

The bridge pin means a replaced or upgraded `.exe` stops authentication until
you re-enroll (`sudo wsl-webauthn-pam enroll --replace`). There is no module
argument that disables it.

## Is the bridge a network service?

No. It is a short-lived child process started through WSL interop, talking to the
module over stdin/stdout. There is no listener, no port, and no network traffic
at authentication time. The only network use in the project is the release
download you run yourself.
