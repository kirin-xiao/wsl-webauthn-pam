#!/bin/sh
# Fetch a pinned, checksum-verified nfpm binary.
#
# nfpm is a single static Go binary with no runtime dependencies; it is not
# packaged in the runners, so it is fetched like actionlint (see the Makefile):
# pinned version, pinned per-arch SHA-256, refuse anything unverified. Bump the
# version and both hashes together.
#
# Usage: install-nfpm.sh [dest-dir]     (default: $HOME/.local/bin)
set -eu

dest=${1:-"$HOME/.local/bin"}
version=2.48.0

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64 | Linux/amd64)
        asset="nfpm_${version}_Linux_x86_64.tar.gz"
        expected=6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750
        ;;
    Linux/aarch64 | Linux/arm64)
        asset="nfpm_${version}_Linux_arm64.tar.gz"
        expected=a9a75213763783b7669719e505474c748c5ad7dc66591a195619deb50f85c2f4
        ;;
    *)
        echo "install-nfpm: unsupported platform $(uname -s)/$(uname -m)" >&2
        exit 1
        ;;
esac

url="https://github.com/goreleaser/nfpm/releases/download/v${version}/${asset}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "install-nfpm: downloading nfpm v$version ($asset)"
curl -fsSL "$url" -o "$tmp/nfpm.tar.gz"

actual=$(sha256sum "$tmp/nfpm.tar.gz" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
    echo "install-nfpm: SHA-256 mismatch for $asset" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
fi

tar -xzf "$tmp/nfpm.tar.gz" -C "$tmp" nfpm
mkdir -p "$dest"
install -m 0755 "$tmp/nfpm" "$dest/nfpm"
echo "install-nfpm: installed $dest/nfpm"
