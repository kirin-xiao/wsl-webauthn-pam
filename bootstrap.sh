#!/bin/sh
# wsl-webauthn-pam one-command bootstrap.
#
# Downloads a release tarball, verifies it against the release `SHA256SUMS` (and,
# best-effort, the signed build-provenance attestation when `gh` is available),
# extracts it to a temporary directory, and runs `wsl-webauthn-pam install` as
# root. The tarball is removed afterwards; the CLI is copied to /usr/local/bin by
# `install`.
#
# Usage:
#   curl -fsSL https://github.com/kirin-xiao/wsl-webauthn-pam/releases/latest/download/bootstrap.sh | sudo bash
#   curl -fsSL .../releases/latest/download/bootstrap.sh | sudo bash -s -- --allow-unattested
#   ./bootstrap.sh --version v0.1.0
#
# Anything after `--version <tag>` (or `--version=<tag>`) is forwarded to
# `wsl-webauthn-pam install`. The `WSL_WEBAUTHN_VERSION` environment variable may
# also pin the tag.
#
# The script never re-points its own stdin (`exec </dev/tty`), because the
# documented invocation pipes the script itself into `bash`: fd 0 is then the
# script source, and re-pointing it would truncate the script and start executing
# the terminal as root. Only the installer child gets the terminal.
set -eu

REPO="kirin-xiao/wsl-webauthn-pam"
VERSION="${WSL_WEBAUTHN_VERSION:-}"

usage() {
    cat <<'EOF'
wsl-webauthn-pam bootstrap

Usage:
  bootstrap.sh [--version <tag>] [install options...]

Options:
  --version <tag>   Install a specific release tag (e.g. v0.1.0).
                    Default: the latest release.
  -h, --help        Show this help.

Any other arguments are passed to `wsl-webauthn-pam install`.
Environment:
  WSL_WEBAUTHN_VERSION   Same as --version.
EOF
}

# Pull `--version` off the front; forward the rest to `install`.
while [ $# -gt 0 ]; do
    case "$1" in
        -h | --help)
            usage
            exit 0
            ;;
        --version)
            [ $# -ge 2 ] || { echo "error: --version requires a tag" >&2; exit 2; }
            VERSION="$2"
            shift 2
            ;;
        --version=*)
            VERSION="${1#--version=}"
            [ -n "$VERSION" ] || { echo "error: --version requires a tag" >&2; exit 2; }
            shift
            ;;
        *)
            break
            ;;
    esac
done

case "$(uname -m)" in
    x86_64 | amd64) ARCH="x86_64" ;;
    aarch64 | arm64) ARCH="aarch64" ;;
    *)
        echo "error: unsupported architecture '$(uname -m)' (expected x86_64 or aarch64)" >&2
        exit 1
        ;;
esac

for tool in curl sha256sum tar mktemp awk sed; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: required tool '$tool' not found on PATH" >&2
        exit 1
    }
done

if [ -z "$VERSION" ]; then
    # Resolve the latest tag from the /releases/latest redirect, with no jq dependency.
    VERSION="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed -n 's#.*/tag/##p')"
    if [ -z "$VERSION" ]; then
        echo "error: could not resolve the latest release for $REPO" >&2
        exit 1
    fi
fi

VER="${VERSION#v}"
TARBALL="wsl-webauthn-pam-${VER}-${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "wsl-webauthn-pam bootstrap"
echo "  repository: $REPO"
echo "  release:    $VERSION"
echo "  arch:       $ARCH"
echo "  asset:      $BASE/$TARBALL"

# Fetch SHA256SUMS and the tarball from the *same* resolved tag, so the checksum and
# the bytes can never come from different releases.
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
curl -fsSL "$BASE/$TARBALL" -o "$TMP/$TARBALL"

expected="$(awk -v f="$TARBALL" '$2 == f { print $1 }' "$TMP/SHA256SUMS")"
if [ -z "$expected" ]; then
    echo "error: $TARBALL is not listed in SHA256SUMS" >&2
    exit 1
fi
actual="$(sha256sum "$TMP/$TARBALL" | awk '{ print $1 }')"
if [ "$actual" != "$expected" ]; then
    echo "error: SHA-256 mismatch for $TARBALL" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
fi
echo "  sha256:     OK ($actual)"

if command -v gh >/dev/null 2>&1; then
    echo "  provenance: verifying build attestation with gh..."
    if gh attestation verify "$TMP/$TARBALL" -R "$REPO"; then
        echo "  provenance: OK"
    else
        # The SHA-256 check above is mandatory; provenance is defense-in-depth. Do not
        # abort a working install because `gh` is unauthenticated or rate-limited.
        echo "warning: could not verify build provenance with gh" >&2
        echo "         (continuing; the SHA-256 checksum was verified)" >&2
        echo "         Verify by hand later: gh attestation verify <file> -R $REPO" >&2
    fi
else
    echo "  provenance: skipped ('gh' not installed; checksum verified)"
fi

tar -xzf "$TMP/$TARBALL" -C "$TMP"
DIR="$TMP/wsl-webauthn-pam-${VER}-${ARCH}"
if [ ! -x "$DIR/wsl-webauthn-pam" ]; then
    echo "error: $TARBALL did not contain an executable CLI" >&2
    exit 1
fi

# Hand the installer a real terminal for sudo's password prompt and the Hello dialog
# notice, without touching this shell's stdin (which may be the piped script).
TTY=/dev/null
if [ -e /dev/tty ]; then
    if (exec </dev/tty) 2>/dev/null; then
        TTY=/dev/tty
    fi
fi

# Run the installer normally (not via exec) so the EXIT trap cleans up $TMP, and
# propagate its exit status. When this script is already root (the documented
# `curl | sudo bash`), run the CLI directly: a nested `sudo` would reset `SUDO_USER`
# to root and enroll the wrong user.
set +e
if [ "$(id -u)" = 0 ]; then
    "$DIR/wsl-webauthn-pam" install "$@" <"$TTY"
else
    sudo "$DIR/wsl-webauthn-pam" install "$@" <"$TTY"
fi
status=$?
set -e
exit "$status"
