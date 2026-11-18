+++
title = "Prior art"
description = "How WSL-Hello-sudo shaped this project, and why this is an independent rewrite rather than a drop-in upgrade."
weight = 7
+++

This project would not exist without
[WSL-Hello-sudo](https://github.com/nullpo-head/WSL-Hello-sudo).
`wsl-webauthn-pam` is an independent rewrite, not a drop-in upgrade: the
protocol, installer, and credential store are all new.

WSL-Hello-sudo established the idea — inside WSL, make `sudo` ask Windows Hello
through a Windows helper. This project keeps that shape and replaces the trust
model: a WebAuthn ceremony with a challenge minted on the Linux side, attested
enrollment by default, a pinned relying-party ID, and signature verification on
the Linux side. The reasoning is in
[SECURITY.md](https://github.com/kirin-xiao/wsl-webauthn-pam/blob/main/SECURITY.md);
the [security page](@/docs/security.md) is the short version.

Nothing is imported from a WSL-Hello-sudo installation. The legacy key is never
read, there is no compatibility layer, and every user must re-enroll with a
fresh ceremony. If `install` finds the old project, it offers legacy cleanup —
rewriting `/etc/pam.d` references with a timestamped backup, removing the old
`wsl-hello` profile and module, and offering to remove `/etc/pam_wsl_hello` —
each step behind its own confirmation. The old Windows credential cannot be
deleted through this project; it is inert without the credential ID, which only
the old Linux store held.
