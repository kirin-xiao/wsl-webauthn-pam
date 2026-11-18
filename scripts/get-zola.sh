#!/bin/sh
# Fetch the checksum-pinned Zola binary used to build the GitHub Pages site.
#
# v0.23.6 is pinned by the SHA-256 of the official release tarball for each
# supported host. The binary is cached under .cache/zola/<version>/ (ignored by
# git), so repeated builds work offline. On success this script prints one
# line to stdout: the absolute path of the Zola binary. Everything else goes to
# stderr.
#
# Override the binary with ZOLA_BIN=/path/to/zola (it must be executable).

set -eu

VERSION=0.23.6
RELEASE_BASE="https://github.com/getzola/zola/releases/download/v${VERSION}"

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
cache_dir=${ZOLA_CACHE_DIR:-"$repo_root/.cache/zola/$VERSION"}
cached_bin="$cache_dir/zola"

die() {
    printf 'get-zola: %s\n' "$*" >&2
    exit 1
}

log() {
    printf 'get-zola: %s\n' "$*" >&2
}

# An explicit override wins, but only if it actually runs.
if [ -n "${ZOLA_BIN:-}" ]; then
    resolved=$(command -v -- "$ZOLA_BIN" 2>/dev/null || true)
    [ -n "$resolved" ] || die "ZOLA_BIN=$ZOLA_BIN is not an executable file"
    case $resolved in
        */*) bin_dir=$(CDPATH='' cd -- "$(dirname -- "$resolved")" && pwd -P) ;;
        *) bin_dir=$(CDPATH='' cd -- "$(dirname -- "$(command -v -- "$resolved")")" && pwd -P) ;;
    esac
    printf '%s/%s\n' "$bin_dir" "$(basename -- "$resolved")"
    exit 0
fi

if [ -x "$cached_bin" ]; then
    printf '%s\n' "$cached_bin"
    exit 0
fi

case $(uname -s) in
    Linux) os=unknown-linux-gnu ;;
    *) die "unsupported host OS '$(uname -s)'; this fetcher supports Linux (x86_64, aarch64)" ;;
esac

case $(uname -m) in
    x86_64 | amd64)
        arch=x86_64
        expected=8f5132b3522412d04e395e0b25f6d68613ad272a873e54a2b3ebf664873024a4
        ;;
    aarch64 | arm64)
        arch=aarch64
        expected=266448fffbf7c7004ca399d0e76dd699541771096d8a42aede98cebe2a029d02
        ;;
    *)
        die "unsupported host architecture '$(uname -m)'; this fetcher supports x86_64 and aarch64"
        ;;
esac

asset="zola-v${VERSION}-${arch}-${os}.tar.gz"
url="$RELEASE_BASE/$asset"

tmp=
cleanup() {
    [ -n "$tmp" ] && rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$cache_dir" || die "cannot create cache directory $cache_dir"
tmp=$(mktemp -d "$cache_dir/.tmp.XXXXXX") || die "cannot create a temporary directory under $cache_dir"

log "downloading Zola v$VERSION ($arch)"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 2 --connect-timeout 20 -o "$tmp/$asset" "$url" ||
        die "download failed: $url (offline? run once with network access)"
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp/$asset" "$url" ||
        die "download failed: $url (offline? run once with network access)"
else
    die "neither curl nor wget is available to download $url"
fi

if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
else
    die "no SHA-256 tool found (need sha256sum or shasum)"
fi

[ "$actual" = "$expected" ] ||
    die "SHA-256 mismatch for $asset: got $actual, want $expected; refusing to install"

log "checksum verified"
tar -xzf "$tmp/$asset" -C "$tmp" zola || die "cannot extract zola from $asset"
[ -f "$tmp/zola" ] || die "release archive did not contain a zola binary"
chmod 0755 "$tmp/zola" || die "cannot make the extracted binary executable"

# Move into place only after verification and extraction both succeeded.
mv "$tmp/zola" "$cached_bin" || die "cannot install $cached_bin"
printf '%s\n' "$cached_bin"
