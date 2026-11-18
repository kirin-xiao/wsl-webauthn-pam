+++
title = "FAQ"
description = "Shared Windows accounts, multiple distros, machines without a TPM, and what happens when you upgrade."
weight = 6
+++

## Several Linux users share one Windows account — does that work?

Yes, and that is the normal WSL case. Windows Hello verifies the same Windows
account for all of them, while each Linux user enrolls separately and has
exactly one credential record of their own, bound for audit to the Windows
account that enrolled it.

Add another user with:

```sh
sudo wsl-webauthn-pam enroll --user <name>
```

The record lives under `/etc/wsl_webauthn/credentials/`, root-owned, so no user
can read or edit another user's.

## I installed it in one distro. What about my other distros?

Each distro is a separate Linux system with its own `/etc/pam.d`, so install and
enroll once per distro. The Windows side is shared — the bridge and the Windows
Hello credential are common to all of them.

## Can I use this on a machine without a TPM?

Only with `--allow-unattested`, and only on a machine you control. Without a TPM
there is no attestation, so the software key is accepted on trust and the record
says so (`attestation.mode: "unattested-opt-in"`). It is an explicit flag on
every enrollment, never a silent fallback. Details are on the
[install page](@/docs/install.md#what-allow-unattested-records).

## Does it replace `sudo` or edit `sudoers`?

No. It is a pure PAM module. It does not fork or replace `sudo`, does not touch
`sudoers`, and works for anything that authenticates through PAM. It adds one
line to the PAM stack through the `pam-auth-update` profile.

## Does it replace my password?

No. The shipped profile is fail-through: a failed, declined, unavailable, or
timed-out Hello attempt is ignored and PAM asks for the password. The module adds
no new way to lose password access under that profile — see
[Don't lock yourself out](@/docs/install.md#don-t-lock-yourself-out).

## What happens on uninstall?

`sudo wsl-webauthn-pam uninstall --all` removes the PAM profile, the module, the
Linux config, the Windows bridge, and the CLI. `uninstall --user <name>` (or
`unregister --user <name>`) removes one user's credential and leaves everything
else in place.

Two things are deliberately left behind:

- A legacy `/etc/pam_wsl_hello` directory from WSL-Hello-sudo — it is not this
  project's, so `uninstall` never removes it. (The `install` migration offers to,
  as a separate confirmed step.)
- Any `/etc/pam.d` line that still names the module. `uninstall` does not
  blind-edit `/etc/pam.d`; it warns about the references it finds so you can
  remove them by hand.

If you installed from apt, `sudo apt remove wsl-webauthn-pam` removes the
packaged files. The `/usr/local/bin/wsl-webauthn-pam` copy that `install` wrote
is not owned by the package, so remove it with `uninstall --all` or by hand.

## Do my WSL-Hello-sudo credentials migrate?

No. The legacy key is never imported, and every user re-enrolls from scratch.
`install` rewrites `/etc/pam.d` references from `pam_wsl_hello` to
`pam_wsl_webauthn`, removes the old "wsl-hello" profile and module (and offers to
remove `/etc/pam_wsl_hello`), each behind its own confirmation, and never reads
the legacy PEM. See [Prior art](@/docs/prior-art.md) for why the formats are not
compatible.

## I upgraded and sudo stopped working. Why?

A new release ships a new bridge `.exe`, and its bytes are part of the SHA-256
pin recorded at enrollment. The pin fails until you re-enroll:

```sh
sudo wsl-webauthn-pam enroll --replace
```

This is by design; there is no flag that disables the pin.

## Does it work for `su` as well as `sudo`?

It works for anything that authenticates through PAM. The `pam-auth-update`
profile is `Auth-Type: Primary`, so it lands in the common auth stack that
`sudo` and `su` both use. `sudo` is the case this project tests and documents
most.

## Does it need the network or a cloud account?

No. There is no telemetry, no account, and no network at authentication time. The
bridge talks to Windows Hello through `webauthn.dll` on the same machine, over
WSL interop. The only network use is the release download you run yourself.

## Do I need to be online for Windows Hello to work?

The PIN, fingerprint, and face are verified locally by the Windows platform
authenticator. Authentication does not contact a server.

## Can I run it from a systemd service?

Usually not. WSL interop needs the session leader, and systemd services often
cannot reach it, so Hello can work from an interactive shell but not from a
service. The runner fails with `interop-unavailable` instead of hanging.

## Is WSL1 supported?

WSL1 is untested. The documented requirement is WSL2 with interop enabled.

## What exactly does the PAM module see?

The signature and the assertion metadata — never your PIN, fingerprint, or face.
Those are checked inside the Windows-owned dialog and never cross into Linux.
