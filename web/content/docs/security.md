+++
title = "Security"
description = "What the design protects, what it trusts, what it never does, and where the formal threat model lives."
weight = 3
+++

`wsl-webauthn-pam` puts a Windows Hello gesture in front of `sudo` and `su` in
this WSL distro. You keep the same PIN, fingerprint, or face you already use to
unlock Windows; the Linux side verifies a fresh signature before it returns
`PAM_SUCCESS`.

## What it trusts

The Windows Hello authenticator, and the Windows session that owns it. That is
the honest limit: this is **not a privilege boundary against a compromised
Windows session**. Anyone who controls that session can already open a root
shell with `wsl.exe -u root`, so no design inside WSL can defend that account
from itself. What the design does defend is an attacker who can reach Linux but
cannot execute Windows code.

## What stops an attacker

- Enrollment attests the credential, and the chain must reach a pinned Microsoft
  TPM root before a record is written.
- The relying-party ID and origin are fixed, so an assertion made for anything
  else is rejected.
- The bridge executable is hash-pinned, so replacing it on the Windows side does
  not let it produce an accepted assertion.
- Credential records are root-owned, and every check — the signature, the
  challenge, the presence and verification flags, the credential binding — runs
  on the Linux side.
- Every failure is fail-closed: there is exactly one path to success.

## What it never does

- It makes no network connection at authentication time.
- It collects no telemetry and creates no account.
- A failed, declined, or timed-out gesture falls through to your login password
  under the shipped PAM profile.

The formal threat model — trust anchors, verified invariants, residual risk —
and the private vulnerability-reporting process live in
[SECURITY.md](https://github.com/kirin-xiao/wsl-webauthn-pam/blob/main/SECURITY.md).
