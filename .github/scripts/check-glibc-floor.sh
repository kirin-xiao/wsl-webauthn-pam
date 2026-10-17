#!/bin/sh
# Fail if a shipped ELF requires a glibc symbol newer than the declared floor.
#
# The floor is a promise to users: the release binaries must load on the oldest
# supported distribution (Debian 11 / Ubuntu 20.04, glibc 2.31). glibc symbol
# versioning is forward-only, so a single new symbol makes the binary refuse to
# start on an older glibc with "version `GLIBC_x.y' not found". The release build
# pins the floor by compiling in an old container; this check makes a regression
# in a dependency fail instead of shipping.
#
# Usage: check-glibc-floor.sh <max-version> <file>...
#   check-glibc-floor.sh 2.31 target/release/libpam_wsl_webauthn.so
set -eu

max=${1:?usage: check-glibc-floor.sh <max-version> <file>...}
shift
[ "$#" -gt 0 ] || { echo "check-glibc-floor: no files given" >&2; exit 2; }

# A missing objdump would otherwise read as "this binary uses no glibc symbols",
# which is a very confusing way to diagnose a broken runner.
command -v objdump >/dev/null 2>&1 || {
    echo "check-glibc-floor: objdump not found (install binutils)" >&2
    exit 2
}

status=0
for file in "$@"; do
    if [ ! -f "$file" ]; then
        echo "check-glibc-floor: $file not found" >&2
        exit 1
    fi

    # Highest GLIBC_<version> referenced by the file's dynamic symbols. An empty
    # result means the file does not use glibc at all (e.g. a static or musl
    # object), which is reported rather than passed as trivially below the floor.
    required=$(objdump -T "$file" | grep -o 'GLIBC_[0-9.]*' | sed 's/^GLIBC_//' | sort -Vu | tail -n1 || true)

    if [ -z "$required" ]; then
        echo "check-glibc-floor: $file: no GLIBC symbols found (not a glibc ELF?)" >&2
        status=1
        continue
    fi

    # sort -V puts the larger of the two last; a floor match keeps `max` last.
    highest=$(printf '%s\n%s\n' "$max" "$required" | sort -V | tail -n1)
    if [ "$highest" != "$max" ]; then
        echo "::error file=$file::requires GLIBC_$required, above the declared floor $max" >&2
        status=1
    else
        echo "glibc floor OK: $file requires GLIBC_$required (floor $max)"
    fi
done

exit $status
