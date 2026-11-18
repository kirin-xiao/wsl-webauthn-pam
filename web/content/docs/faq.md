+++
title = "FAQ"
description = "Shared Windows accounts, multiple distros, machines without a TPM, and what happens when you upgrade."
weight = 6

[extra]
# The questions are the navigation; a second list of all of them only pushes
# the first answer off the screen.
toc = false
+++

## Several Linux users share one Windows account — does that work?

Yes, and that is normal in WSL: Windows Hello verifies the same account, while
each Linux user enrolls separately with one root-owned record.

```sh
sudo wsl-webauthn-pam enroll --user <name>
```

## I installed it in one distro. What about my other distros?

Each distro has its own `/etc/pam.d`, so install and enroll once per distro. The
Windows bridge and Hello credential are shared.

## Can I use this on a machine without a TPM?

Only with `--allow-unattested`, on a machine you control. Without a TPM
the software key is accepted on trust; see the
[install page](@/docs/install.md#allow-unattested) and the
[security page](@/docs/security.md).

## Does it replace `sudo` or edit `sudoers`?

No. It is a pure PAM module: it does not touch `sudoers` and works for anything
PAM authenticates.

## Does it replace my password?

No. A failed, declined, unavailable, or timed-out Hello attempt is ignored and
PAM asks for your password — see
[Don't lock yourself out](@/docs/install.md#don-t-lock-yourself-out).

## What happens on uninstall?

`uninstall --all` removes the profile, module, config, bridge, and CLI;
`uninstall --user <name>` (or `unregister --user <name>`) removes one
credential. It leaves the legacy `/etc/pam_wsl_hello` directory and
`/etc/pam.d` alone. If you installed from apt, also run
`sudo apt remove wsl-webauthn-pam`.

## Do my WSL-Hello-sudo credentials migrate?

No — re-enroll from scratch. The legacy key is never imported; `install` only
rewrites PAM references and removes the old profile and module. See
[Prior art](@/docs/prior-art.md).

## I upgraded and sudo stopped working. Why?

A new release changes the `.exe` bytes, so the pin fails until you re-enroll:

```sh
sudo wsl-webauthn-pam enroll --replace
```

No flag disables the pin.

## Does it work for `su` as well as `sudo`?

Yes. It works for anything that authenticates through PAM; the profile is in
the common auth stack.

## Does it need the network, a cloud account, or an internet connection?

No. There is no telemetry, no account, and no network at authentication time,
and the PIN, fingerprint, or face is verified locally. The only network use is
the release download you run yourself.

## Can I run it from a systemd service?

Usually not. WSL interop needs the session leader, which systemd services often
cannot reach; the runner fails with `interop-unavailable`.

## Is WSL1 supported?

No. WSL1 is untested; use WSL2 with interop enabled.

## What exactly does the PAM module see?

The signature and assertion metadata — never your PIN, fingerprint, or face,
which stay in the Windows dialog.
