+++
title = "wsl-webauthn-pam"
description = "Passwordless sudo and su inside WSL2, authenticated with the Windows Hello passkey you already use."
+++

<section class="hero" aria-labelledby="hero-title">

<h1 id="hero-title">wsl-webauthn-pam</h1>

<p class="hero__pitch">Passwordless <code>sudo</code> and <code>su</code> inside WSL2, authenticated with the Windows Hello passkey you already use.</p>

<p class="hero__trust">Every check runs on the Linux side; the bridge only relays bytes — <a href="{{ get_url(path='@/docs/security.md') }}">see the trust model</a>.</p>

</section>

> [!WARNING]
> Keep a second WSL shell open while you test, and confirm `sudo` still falls back to your password before you close it.

{% <term label="debian / ubuntu · apt" copy={true} glyph=">" aria="Signed apt repository install commands"> %}
# 1. Add the archive key and the signed repository.
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://kirin-xiao.github.io/wsl-webauthn-pam/wsl-webauthn-pam-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/wsl-webauthn-pam.gpg >/dev/null
sudo tee /etc/apt/sources.list.d/wsl-webauthn-pam.sources >/dev/null <<'EOF'
Types: deb
URIs: https://kirin-xiao.github.io/wsl-webauthn-pam
Suites: stable
Components: main
Architectures: amd64 arm64
Signed-By: /etc/apt/keyrings/wsl-webauthn-pam.gpg
EOF
# 2. Install the PAM module, the CLI, and the profile (left disabled).
sudo apt update && sudo apt install wsl-webauthn-pam
# 3. Copy the bridge to Windows, then enroll and enable sudo.
sudo wsl-webauthn-pam install --skip-enroll --artifact-dir /usr/lib/wsl-webauthn-pam
sudo wsl-webauthn-pam enroll
{% </term> %}

<p class="next-step">
<a href="{{ get_url(path='@/docs/install.md') }}#enrollment">what enrollment does <span aria-hidden="true">→</span></a>
<span>Two Windows dialogs: first confirm the passkey, then your PIN or biometric. The dialog can open behind the terminal — type the PIN into the Windows dialog, never the terminal.</span>
</p>

<section class="why" aria-labelledby="why-title">

<p class="eyebrow">Why it works</p>

<h2 id="why-title">The decision is made on the Linux side.</h2>

<p><code>sudo</code> hands the request to PAM. The module mints a fresh 32-byte challenge and spawns the Windows bridge over WSL interop with framed stdio — no shell, no temporary challenge file. The bridge asks Windows Hello for an assertion and relays bytes; the root-owned Linux side verifies the RP ID hash, the user-presence and user-verification flags, the credential binding, and the signature against the enrolled public key.</p>

<p>Exactly one path returns <code>PAM_SUCCESS</code>: a fully verified assertion. Everything else is fail-closed, and a failed, declined, or timed-out Hello attempt falls through to your password under the shipped profile.</p>

</section>

<p class="aside-note">The crypto stack self-test:</p>

{% <term label="shell" glyph=">" aria="wsl-webauthn-pam verify output" raw={true}> %}
<span class="prompt">$</span> wsl-webauthn-pam verify
verify: PASS
  attestation: packed / SelfAttested
  assertion:   verified (ES256)
  negative control: tampered signature rejected
  negative control: disallowed AAGUID rejected
{% </term> %}

<section class="security" aria-labelledby="security-title">

<p class="eyebrow">Trust model</p>

<h2 id="security-title">Small surface, checked in the right place.</h2>

<ul class="security-strip">
  <li>
    <h3>Attested enrollment</h3>
    <p><code>tpm</code>/<code>packed</code> attestation chains to the pinned Microsoft TPM root with a Windows Hello AAGUID. A software key needs an explicit <code>--allow-unattested</code>.</p>
  </li>
  <li>
    <h3>Pinned RP ID</h3>
    <p>The relying-party ID and origin are compile-time constants, asserted byte-for-byte on the Linux side.</p>
  </li>
  <li>
    <h3>Hash-pinned bridge</h3>
    <p>The bridge <code>.exe</code> is SHA-256 checked on every launch, against the same file descriptor it executes.</p>
  </li>
  <li>
    <h3>No telemetry</h3>
    <p>No accounts and no network at authentication time. The only network use is the release download you run yourself.</p>
  </li>
  <li>
    <h3>Password fallback</h3>
    <p>The shipped profile is fail-through: an unavailable bridge, a timeout, or a cancel falls through to your local password.</p>
  </li>
</ul>

</section>
