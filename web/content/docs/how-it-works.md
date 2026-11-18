+++
title = "How it works"
description = "From sudo to PAM to the Windows bridge to Windows Hello, with verification on the Linux side."
weight = 2
+++

`sudo` does not change. PAM loads `pam_wsl_webauthn.so`, which either returns
`PAM_SUCCESS` after a verified Windows Hello assertion or lets PAM try the next
method.

## The sequence

<figure class="sequence" aria-labelledby="sequence-caption">
<figcaption class="sequence__caption" id="sequence-caption">One <code>sudo</code> call, from the Linux side across WSL to Windows Hello and back.</figcaption>

<div class="sequence__zone sequence__zone--host">
<p class="sequence__zone-title">Linux side · root-owned</p>
<ol class="sequence__steps">
  <li><strong>You / shell</strong> — run <code>sudo whoami</code>.</li>
  <li><strong>sudo → PAM</strong> — authenticate <code>alice</code>.</li>
  <li><strong>pam_wsl_webauthn.so</strong> — load the credential and mint a fresh challenge.</li>
  <li><strong>pam_wsl_webauthn.so</strong> — start the bridge over WSL interop.</li>
</ol>
</div>

<p class="sequence__boundary"><strong>Linux → Windows.</strong> The request crosses on the bridge's stdin; no shell, no socket.</p>

<div class="sequence__zone sequence__zone--windows">
<p class="sequence__zone-title">Windows side · user session</p>
<ol class="sequence__steps" start="5">
  <li><strong>WSLWebAuthnBridge.exe</strong> — ask Windows Hello for an assertion.</li>
  <li><strong>Windows Hello</strong> — prompt for PIN, fingerprint, or face.</li>
  <li><strong>You</strong> — approve in the Windows dialog.</li>
  <li><strong>Windows Hello</strong> — sign and return the assertion.</li>
</ol>
</div>

<p class="sequence__boundary"><strong>Windows → Linux.</strong> Only the signed assertion returns; your PIN or biometric never leaves the dialog.</p>

<div class="sequence__zone sequence__zone--verify">
<p class="sequence__zone-title">Linux side · verification</p>
<ol class="sequence__steps" start="9">
  <li><strong>pam_wsl_webauthn.so</strong> — verify the signature against the enrolled public key.</li>
  <li><strong>pam_wsl_webauthn.so → PAM</strong> — return <code>PAM_SUCCESS</code>.</li>
  <li><strong>sudo</strong> — run the command.</li>
</ol>
</div>

</figure>

The bridge only relays bytes and makes no security decision: a compromised
bridge can stall or try to talk you into approving a ceremony, but it cannot
forge an assertion. The full argument is in
[SECURITY.md](https://github.com/kirin-xiao/wsl-webauthn-pam/blob/main/SECURITY.md);
the [security page](@/docs/security.md) is the short version.

## What you see

On `sudo`, the module prints a one-line cue naming the service and the Linux
user, for example *Windows Hello: authenticating 'sudo' for Linux user alice —
check the taskbar and do not type here*. The Windows dialog is titled *Sign in
with a passkey* and shows **Passkey for wsl-webauthn-pam**. The cue is suppressed
with the `quiet` module argument and only appears with a terminal attached.

## Decline, cancel, and timeout

Cancelling is an ordinary failure: `sudo` falls through to the password prompt
after a short delay. The default deadline is 60 s; override it with the
`timeout=<secs>` module argument or `timeout_secs` in
`/etc/wsl_webauthn/config`.

## The password fallback

Any non-success result falls through to your password under the shipped profile.
