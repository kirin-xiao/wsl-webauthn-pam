+++
title = "wsl-webauthn-pam"
description = "Passwordless sudo and su inside WSL2, authenticated with the Windows Hello passkey you already use."
+++

<section class="hero" aria-labelledby="hero-title">

<h1 id="hero-title">wsl-webauthn-pam</h1>

<p class="hero__pitch">Passwordless <code>sudo</code> and <code>su</code> inside WSL2, authenticated with the Windows Hello passkey you already use.</p>

<p class="hero__trust">Every check runs on the Linux side; the bridge only relays bytes. <a href="{{ get_url(path='@/docs/security.md') }}">What that means <span aria-hidden="true">→</span></a></p>

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

<p>A failed or cancelled Hello attempt falls through to your password.</p>
