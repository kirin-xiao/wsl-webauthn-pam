#!/bin/sh
# Verify a built .deb's layout, file modes, dependencies, and maintainer scripts.
#
# This is the guard that keeps the package *installable*. In particular it asserts
# that the installer's `--artifact-dir` module is a REGULAR FILE: the CLI reads
# the module with a no-follow read and refuses a symlinked source (pinned by the
# `install_rolls_back_partial_state_on_module_failure` unit test), so a symlinked
# artifact would make every packaged `install` roll back with "refusing to follow
# symlink at source". Modes are asserted too, because nfpm applies
# `file_info.mode` verbatim and a regression (a non-executable CLI, say) is
# otherwise invisible.
#
# Usage: check-deb-layout.sh <deb> <triplet>
#   check-deb-layout.sh wsl-webauthn-pam_0.2.0_amd64.deb x86_64-linux-gnu
set -eu

deb=${1:?usage: check-deb-layout.sh <deb> <triplet>}
triplet=${2:?usage: check-deb-layout.sh <deb> <triplet>}

[ -f "$deb" ] || { echo "check-deb-layout: $deb not found" >&2; exit 1; }

listing=$(dpkg-deb -c "$deb")
control=$(dpkg-deb -I "$deb")

status=0
want() {
    # want <description> <extended-regexp>
    if printf '%s\n' "$listing" | grep -Eq "$2"; then
        echo "deb layout OK: $1"
    else
        echo "::error file=$deb::$1 (no line matching: $2)" >&2
        status=1
    fi
}

want "module in the security directory (0644 root)" \
    "^-rw-r--r-- root/root.* \./usr/lib/$triplet/security/pam_wsl_webauthn\.so$"
want "artifact-dir module is a regular file (0644 root)" \
    "^-rw-r--r-- root/root.* \./usr/lib/wsl-webauthn-pam/pam_wsl_webauthn\.so$"
want "bridge staged as a regular file (0644 root)" \
    "^-rw-r--r-- root/root.* \./usr/lib/wsl-webauthn-pam/WSLWebAuthnBridge\.exe$"
want "CLI executable (0755 root)" \
    "^-rwxr-xr-x root/root.* \./usr/bin/wsl-webauthn-pam$"
want "pam-configs profile (0644 root)" \
    "^-rw-r--r-- root/root.* \./usr/share/pam-configs/wsl-webauthn$"
want "copyright installed (policy 12.5)" \
    "^-rw-r--r-- root/root.* \./usr/share/doc/wsl-webauthn-pam/copyright$"
want "README installed" \
    "^-rw-r--r-- root/root.* \./usr/share/doc/wsl-webauthn-pam/README\.md$"

# Name the symlink case explicitly, so the failure reads as the cause rather than
# as an unexplained missing file.
if printf '%s\n' "$listing" | grep -Eq "^l.* \./usr/lib/wsl-webauthn-pam/pam_wsl_webauthn\.so$"; then
    echo "::error file=$deb::artifact-dir module is a symlink; the installer refuses a symlinked source" >&2
    status=1
fi

for script in postinst prerm postrm; do
    if printf '%s\n' "$control" | grep -Fq "$script"; then
        echo "deb layout OK: maintainer script $script present"
    else
        echo "::error file=$deb::missing maintainer script $script" >&2
        status=1
    fi
done

for dep in 'libc6 (>= 2.31)' libgcc-s1 libpam0g libpam-runtime; do
    if printf '%s\n' "$control" | grep -Fq "$dep"; then
        echo "deb layout OK: Depends includes $dep"
    else
        echo "::error file=$deb::Depends is missing '$dep'" >&2
        status=1
    fi
done

exit $status
