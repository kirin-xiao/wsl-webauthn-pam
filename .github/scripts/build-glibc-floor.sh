#!/bin/sh
# Build the released Linux artifacts (PAM module + CLI) on the oldest glibc the
# project supports, so the shipped bytes load on every supported distribution.
#
# Debian 11 and Ubuntu 20.04 both ship glibc 2.31, the declared floor. We build on
# `ubuntu:20.04` rather than `debian:11` because bullseye-security was retired to
# archive.debian.org (plain `apt-get update` there no longer resolves, 2026-10),
# while focal's archive is still live. Building in the oldest environment is what
# keeps the floor honest: a newer symbol in a dependency would otherwise silently
# raise it, which `check-glibc-floor.sh` then catches on the built ELF.
#
# The container runs as root and writes into the bind-mounted workspace, so the
# produced `target/` is root-owned on the host. Every later step only reads it.
#
# Usage: build-glibc-floor.sh
# Env:
#   CARGO_TARGET_DIR    build directory (default: target); a relative path is
#                       resolved inside the container's /src
#   GLIBC_FLOOR_IMAGE   build image (default: ubuntu:20.04)
#   RUSTUP_DIST_SERVER / RUSTUP_UPDATE_ROOT   forwarded into the container when
#                       set, for networks that cannot reach static.rust-lang.org
#                       from inside Docker
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
target_dir=${CARGO_TARGET_DIR:-target}
case "$target_dir" in
    /*) ;;
    *) target_dir="/src/$target_dir" ;;
esac
image=${GLIBC_FLOOR_IMAGE:-ubuntu:20.04}

set -- docker run --rm \
    -v "$repo_root:/src" -w /src \
    -e CARGO_TARGET_DIR="$target_dir" \
    -e DEBIAN_FRONTEND=noninteractive

# Escape hatch for environments (some WSL/proxy setups) where the container
# cannot reach the default rustup distribution server.
if [ -n "${RUSTUP_DIST_SERVER:-}" ]; then
    set -- "$@" -e "RUSTUP_DIST_SERVER=$RUSTUP_DIST_SERVER"
fi
if [ -n "${RUSTUP_UPDATE_ROOT:-}" ]; then
    set -- "$@" -e "RUSTUP_UPDATE_ROOT=$RUSTUP_UPDATE_ROOT"
fi

# The build script is executed inside the container, so its `$HOME` (and the
# rest of the single-quoted string) must reach bash unexpanded.
# shellcheck disable=SC2016
set -- "$@" "$image" bash -euxo pipefail -c '
        apt-get update
        apt-get install -y --no-install-recommends \
            ca-certificates curl build-essential pkg-config libpam0g-dev
        curl -fsSL https://sh.rustup.rs \
            | sh -s -- -y --profile minimal --default-toolchain stable
        . "$HOME/.cargo/env"
        cargo build --release --locked -p wsl-webauthn-pam -p wsl-webauthn-cli
    '

exec "$@"
