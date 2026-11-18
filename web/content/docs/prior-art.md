+++
title = "Prior art"
description = "How WSL-Hello-sudo shaped this project, and why this is an independent rewrite rather than a drop-in upgrade."
weight = 7
+++

This project would not exist without
[WSL-Hello-sudo](https://github.com/nullpo-head/WSL-Hello-sudo).
`wsl-webauthn-pam` is an independent rewrite, not a drop-in upgrade: the trust
model, protocol, installer, and credential store are all new.

## What WSL-Hello-sudo did

WSL-Hello-sudo established the idea this project starts from: inside WSL, make
`sudo` ask Windows Hello instead of the Linux password, by bridging to a Windows
helper. It shipped a PAM module (`pam_wsl_hello.so`), a `pam-auth-update` profile
named `wsl-hello`, and its own config directory (`/etc/pam_wsl_hello`). Its
enrollment kept a PEM-encoded credential on the Linux side.

That is a real contribution, and the shape of the problem — a Linux PAM module
that has to ask a Windows process for a gesture — is unchanged.

## The three structural weaknesses

The legacy design's weaknesses are what this project's trust model is built to
remove:

| Weakness | Why it matters | What this project does instead |
|---|---|---|
| Enrollment accepted a public key that an attacker could influence | If the enrolled key is not authenticated as coming from a real Windows Hello authenticator, the credential proves nothing about the gesture that later approves it | A WebAuthn ceremony with a challenge minted on the Linux side, and attestation that must chain to the pinned Microsoft TPM Root CA 2014 with a Windows Hello AAGUID. A software key needs an explicit `--allow-unattested` and is recorded as such |
| A blind consent dialog | The user is asked to approve a ceremony without a pinned relying-party identity to check it against | The relying-party ID is a pinned constant, so the dialog reads *Passkey for wsl-webauthn-pam*; attestation, user verification, and Linux-side signature checking mean the dialog is not the security decision |
| A shell-based installer | A shell installer editing PAM is a large, hard-to-review surface, and a mistake there locks the user out | A pure-Rust installer (no shell) that writes atomically, refuses symlinks, verifies what it installed, rolls back its own partial work, and only discards that rollback once verification passes |

## What replaces each weakness

The replacement is not a patch on the old protocol; it is WebAuthn:

- **Fresh challenge, checked on the Linux side.** The module mints 32 random
  bytes per attempt and verifies the assertion against them.
- **Pinned RP ID and origin.** Compile-time constants, asserted byte-for-byte.
- **Attested enrollment by default.** `tpm`/`packed` must chain to the pinned
  Microsoft TPM root with an allowed AAGUID.
- **A hash-pinned bridge.** The `.exe` is SHA-256 checked on every launch,
  against the same file descriptor it executes.
- **A hardened store.** One root-owned record per Linux user, `0700`/`0600`,
  symlink-refusing, swap-detecting, atomic, and bounded.
- **A fail-through PAM profile.** A failed Hello attempt is ignored, so the
  password still works.

The reasoning behind each of these — including what it does *not* protect
against — is on the [security page](@/docs/security.md).

## Not a drop-in upgrade

Nothing is imported from a WSL-Hello-sudo installation:

- **Credentials do not migrate.** The legacy key is never read and never
  imported. Every user re-enrolls from scratch, with a fresh ceremony.
- **The wire format and record schema are new.** There is no compatibility
  layer in either direction.
- **Enrollment is a new ceremony,** not a re-registration of an old public key.

What `install` will do, if it finds a legacy installation, is housekeeping, each
step behind its own confirmation: rewrite `/etc/pam.d` references from
`pam_wsl_hello` to `pam_wsl_webauthn.so` (keeping a fail-safe control, with a
timestamped copy of each file first), run `pam-auth-update --remove wsl-hello`,
then remove the old module, profile, and `/etc/pam_wsl_hello` directory.
`uninstall` never removes that directory; it is not this project's.

## For users of the legacy project

Plan for a cutover, not an upgrade:

1. Run `install` (or the bootstrap script). It provisions the new module and
   bridge, then offers the legacy cleanup.
2. Enroll, then confirm `sudo` works and that declining the prompt still falls
   back to the password.
3. If you declined the cleanup, remove the legacy profile and module by hand
   (see [Don't lock yourself out](@/docs/install.md#don-t-lock-yourself-out)).

The old Windows credential cannot be deleted through this project — Windows
does not enumerate non-resident platform credentials — so it is orphaned rather
than revoked. It is inert without the credential ID, which only the old Linux
store held.
