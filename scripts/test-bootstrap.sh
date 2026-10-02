#!/bin/sh
# Hermetic tests for bootstrap.sh.
#
# bootstrap.sh runs as root on end-user machines (the documented `curl … | sudo
# bash`) and is attested at release time. This harness exercises its argument
# parsing, fetch/verify logic, provenance behavior, the root-vs-non-root
# installer invocation, cleanup, and exit-status propagation.
#
# It is hermetic and privileged-free:
#
#   * no network and no GitHub: a *whole-PATH* shim directory supplies fake
#     `curl`, `uname`, `id`, `sudo`, and `gh`, while the real `sha256sum`,
#     `tar` (which shells out to `gzip`), `mktemp`, `awk`, `sed`, `rm`, `cp`,
#     and `cat` are symlinked, so the checksum/extract logic is genuinely
#     exercised;
#   * the fake `curl` rewrites only `https://github.com/$REPO/...` to a synthetic
#     release tree and hard-errors on any other URL, so a URL change in
#     bootstrap.sh fails the test;
#   * every scenario runs under `env -i` with a fixed environment, so a dev
#     box's `WSL_WEBAUTHN_VERSION`/`gh` cannot leak in and change the result;
#   * `TMPDIR` is pointed into the scenario directory, and its cleanup by
#     bootstrap's EXIT trap is asserted after *every* scenario (including the
#     fail-closed paths, where downloaded bytes would otherwise linger).
#
# bootstrap.sh exposes no release-base override: whoever controls the
# environment would control both the bytes and the checksum. The harness injects
# its synthetic release base through the shimmed PATH.
#
# Usage: sh scripts/test-bootstrap.sh
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
BOOTSTRAP=${BOOTSTRAP:-"$root/bootstrap.sh"}
REPO=kirin-xiao/wsl-webauthn-pam

[ -f "$BOOTSTRAP" ] || { echo "cannot find bootstrap.sh at $BOOTSTRAP" >&2; exit 1; }

FAILS=0
ok() { printf 'ok   %s\n' "$*"; }
bad() { printf 'FAIL %s\n' "$*" >&2; FAILS=$((FAILS + 1)); }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

SH_BIN=$(command -v sh)
BASH_BIN=$(command -v bash)
CAT_BIN=$(command -v cat)
ENV_BIN=$(command -v env)

# Real tools the harness (and the shims) rely on, plus every external command
# bootstrap.sh itself invokes: `cat` (usage), `tar` (which shells out to
# `gzip` for -z), `sha256sum`, `mktemp`, `awk`, `sed`, `rm`. `command -v` runs
# in the host environment, before any `env -i` scenario.
TOOLKIT="$WORK/toolkit"
mkdir -p "$TOOLKIT"
for t in sha256sum tar mktemp awk sed rm cp cat gzip; do
    p=$(command -v "$t") || {
        echo "harness requires the real '$t' on PATH" >&2
        exit 1
    }
    ln -s "$p" "$TOOLKIT/$t"
done

# ---------------------------------------------------------------------------
# Shims (only environment-coupled commands are faked)
# ---------------------------------------------------------------------------
SHIM="$WORK/shim"
mkdir -p "$SHIM"

cat >"$SHIM/curl" <<'EOS'
#!/bin/sh
# Fake curl: serve the synthetic release tree for the one repo URL shape
# bootstrap.sh uses, and fail closed on anything else.
set -eu
repo=${BOOTSTRAP_TEST_REPO:?BOOTSTRAP_TEST_REPO unset}
root=${BOOTSTRAP_TEST_ROOT:?BOOTSTRAP_TEST_ROOT unset}
out=
probe=0
url=
while [ $# -gt 0 ]; do
    case "$1" in
        -o)
            out=$2
            shift 2
            ;;
        -w)
            # Only the latest-tag probe format is used.
            shift 2
            ;;
        -fsSLI)
            probe=1
            shift
            ;;
        -fsSL)
            shift
            ;;
        -*)
            # Reject any other flag rather than silently ignoring it, so a
            # change to bootstrap.sh's curl flags (e.g. dropping `-f`, which is
            # what makes a fetch failure fail closed) is caught here.
            echo "fake-curl: unexpected flag: $1" >&2
            exit 1
            ;;
        *)
            url=$1
            shift
            ;;
    esac
done
[ -n "$url" ] || { echo "fake-curl: no URL argument" >&2; exit 1; }
prefix="https://github.com/$repo/"
case "$url" in
    "${prefix}releases/latest")
        [ "$probe" = 1 ] || { echo "fake-curl: latest needs -I" >&2; exit 1; }
        printf '%s\n' "${BOOTSTRAP_TEST_LATEST_URL:-${prefix}releases/tag/vTEST}"
        exit 0
        ;;
    "${prefix}releases/download/"*)
        rel=${url#"$prefix"}
        src="$root/$rel"
        # Mimic `curl -f`: a missing asset is a hard error, and the caller's
        # `set -e` is what makes the fetch fail closed.
        [ -f "$src" ] || exit 22
        [ -n "$out" ] || out=/dev/stdout
        cp "$src" "$out"
        exit 0
        ;;
    *)
        echo "fake-curl: unexpected URL: $url" >&2
        exit 1
        ;;
esac
EOS

cat >"$SHIM/uname" <<'EOS'
#!/bin/sh
# bootstrap.sh only ever asks for `uname -m`.
printf '%s\n' "${BOOTSTRAP_TEST_UNAME:-x86_64}"
EOS

cat >"$SHIM/id" <<'EOS'
#!/bin/sh
# bootstrap.sh only ever asks for `id -u`.
printf '%s\n' "${BOOTSTRAP_TEST_UID:-1000}"
EOS

cat >"$SHIM/sudo" <<'EOS'
#!/bin/sh
# Record that sudo was used, then run the command (as real sudo would).
printf '%s\n' "$*" >>"${BOOTSTRAP_TEST_SUDO_LOG:-/dev/null}"
exec "$@"
EOS

cat >"$SHIM/gh" <<'EOS'
#!/bin/sh
# Fake `gh attestation verify`: success iff the scenario says so.
[ "${BOOTSTRAP_TEST_GH:-0}" = "1" ]
EOS

chmod 0755 "$SHIM/curl" "$SHIM/uname" "$SHIM/id" "$SHIM/sudo" "$SHIM/gh"

# ---------------------------------------------------------------------------
# Synthetic release tree
# ---------------------------------------------------------------------------
VER=TEST
FIXTURE_ROOT="$WORK/release"
REL="$FIXTURE_ROOT/releases"
build_tarball() { # <arch>
    arch=$1
    topdir="wsl-webauthn-pam-$VER-$arch"
    stage="$WORK/stage/$topdir"
    rm -rf "$stage"
    mkdir -p "$stage" "$REL/download/v$VER"
    cat >"$stage/wsl-webauthn-pam" <<'EOS'
#!/bin/sh
printf '%s\n' "$*" >>"$BOOTSTRAP_TEST_CLI_LOG"
exit "${BOOTSTRAP_TEST_CLI_EXIT:-0}"
EOS
    chmod 0755 "$stage/wsl-webauthn-pam"
    tar -czf "$REL/download/v$VER/wsl-webauthn-pam-$VER-$arch.tar.gz" -C "$WORK/stage" "$topdir"
}

build_tarball x86_64
build_tarball aarch64
( cd "$REL/download/v$VER" && sha256sum wsl-webauthn-pam-TEST-*.tar.gz >SHA256SUMS )

# ---------------------------------------------------------------------------
# Scenario driver
# ---------------------------------------------------------------------------
CASE=
PATH_DIR=
K_UNAME=x86_64
K_UID=1000
K_GH=0
K_LATEST=
K_CLI_EXIT=0
K_WSLVER=
RC=0

begin() { # <name>
    CASE="$WORK/cases/$1"
    mkdir -p "$CASE/tmp" "$CASE/shim" "$CASE/min" "$CASE/home"
    : >"$CASE/cli.log"
    : >"$CASE/sudo.log"
    for t in uname id sudo curl; do ln -sf "$SHIM/$t" "$CASE/shim/$t"; done
    # A minimal PATH for the missing-tool scenario: only `uname` exists.
    ln -sf "$SHIM/uname" "$CASE/min/uname"
    PATH_DIR="$CASE/shim:$TOOLKIT"
    K_UNAME=x86_64
    K_UID=1000
    K_GH=0
    K_LATEST=
    K_CLI_EXIT=0
    K_WSLVER=
}

# Run $BOOTSTRAP under a fixed environment with "$@" as its arguments.
run_boot() {
    "$ENV_BIN" -i \
        PATH="$PATH_DIR" \
        HOME="$CASE/home" \
        TMPDIR="$CASE/tmp" \
        BOOTSTRAP_TEST_REPO="$REPO" \
        BOOTSTRAP_TEST_ROOT="$FIXTURE_ROOT" \
        BOOTSTRAP_TEST_CLI_LOG="$CASE/cli.log" \
        BOOTSTRAP_TEST_SUDO_LOG="$CASE/sudo.log" \
        BOOTSTRAP_TEST_UNAME="$K_UNAME" \
        BOOTSTRAP_TEST_UID="$K_UID" \
        BOOTSTRAP_TEST_GH="$K_GH" \
        BOOTSTRAP_TEST_LATEST_URL="$K_LATEST" \
        BOOTSTRAP_TEST_CLI_EXIT="$K_CLI_EXIT" \
        WSL_WEBAUTHN_VERSION="$K_WSLVER" \
        "$SH_BIN" "$BOOTSTRAP" "$@"
}

run_case() {
    set +e
    run_boot "$@" >"$CASE/stdout" 2>"$CASE/stderr"
    RC=$?
    set -e
    # bootstrap's EXIT trap must remove its mktemp dir on every path.
    if [ -n "$(find "$CASE/tmp" -mindepth 1 -print -quit 2>/dev/null)" ]; then
        bad "$CASE: TMPDIR was not cleaned"
    fi
}

assert_rc() { # <expected>
    if [ "$RC" -eq "$1" ]; then ok "$CASE: exit $1"; else bad "$CASE: exit $RC, want $1"; fi
}
assert_rc_nonzero() {
    if [ "$RC" -ne 0 ]; then ok "$CASE: non-zero exit ($RC)"; else bad "$CASE: expected non-zero exit"; fi
}
assert_contains() { # <file> <needle>
    if grep -Fq -- "$2" "$1"; then ok "$CASE: $(basename "$1") contains '$2'"; else bad "$CASE: $(basename "$1") missing '$2'"; fi
}
assert_file_empty() {
    if [ -s "$1" ]; then bad "$CASE: expected empty $1"; else ok "$CASE: empty $(basename "$1")"; fi
}

# ---------------------------------------------------------------------------
# Naming coherence: bootstrap's tarball name must match the release builder's.
# The synthetic fixture hardcodes the same shape, so a drift here also breaks
# the happy path; this pins the three files to one another explicitly.
# ---------------------------------------------------------------------------
check_naming_coherence() {
    # Literal patterns (escaped `$` so they are not expanded).
    if grep -Fq "wsl-webauthn-pam-\${VER}-\${ARCH}.tar.gz" "$BOOTSTRAP"; then
        ok "bootstrap.sh names the tarball wsl-webauthn-pam-\${VER}-\${ARCH}.tar.gz"
    else
        bad "bootstrap.sh tarball-name pattern drifted"
    fi
    if grep -Fq "wsl-webauthn-pam-\${VERSION}-\${arch}" "$root/.github/workflows/release.yaml"; then
        ok "release.yaml builds wsl-webauthn-pam-\${VERSION}-\${arch}"
    else
        bad "release.yaml tarball-name pattern drifted"
    fi
    if grep -Fq "wsl-webauthn-pam-\$(VERSION)-\$(ARCH)" "$root/Makefile"; then
        ok "Makefile builds wsl-webauthn-pam-\$(VERSION)-\$(ARCH)"
    else
        bad "Makefile tarball-name pattern drifted"
    fi
}

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

# 1. --help: no tools, no network, exit 0.
begin help
run_case --help
assert_rc 0
assert_contains "$CASE/stdout" "wsl-webauthn-pam bootstrap"
assert_contains "$CASE/stdout" "Usage:"

# 2. Argument-parsing errors and the inline `--version=` form.
begin version-no-tag
run_case --version
assert_rc 2
assert_contains "$CASE/stderr" "--version requires a tag"

begin version-empty
run_case --version=
assert_rc 2
assert_contains "$CASE/stderr" "--version requires a tag"

begin version-inline
run_case --version=vTEST
assert_rc 0
assert_contains "$CASE/stdout" "release:    vTEST"
assert_contains "$CASE/cli.log" "install"

begin short-help
run_case -h
assert_rc 0
assert_contains "$CASE/stdout" "Usage:"

# 3. Happy path, non-root: sudo wraps the CLI; passthrough reaches install.
# `gh` is absent (begin() does not link it), so provenance is skipped.
begin happy-nonroot
run_case --version vTEST --skip-enroll --yes
assert_rc 0
assert_contains "$CASE/stdout" "sha256:     OK"
assert_contains "$CASE/stdout" "provenance: skipped"
assert_contains "$CASE/cli.log" "install --skip-enroll --yes"
assert_contains "$CASE/sudo.log" "wsl-webauthn-pam install"

# 4. Happy path, root: the CLI runs directly (no nested sudo).
begin happy-root
K_UID=0
run_case --version vTEST
assert_rc 0
assert_contains "$CASE/cli.log" "install"
assert_file_empty "$CASE/sudo.log"

# 5. aarch64/arm64 mapping.
begin happy-aarch64
K_UNAME=aarch64
run_case --version vTEST
assert_rc 0
assert_contains "$CASE/stdout" "asset:      https://github.com/$REPO/releases/download/vTEST/wsl-webauthn-pam-TEST-aarch64.tar.gz"
assert_contains "$CASE/cli.log" "install"

# 6. SHA-256 mismatch fails closed; the CLI is never invoked.
begin checksum-mismatch
corrupt="$CASE/rel"
cp -R "$FIXTURE_ROOT" "$corrupt"
printf 'x' >>"$corrupt/releases/download/vTEST/wsl-webauthn-pam-TEST-x86_64.tar.gz"
FIXTURE_ROOT_SAVED=$FIXTURE_ROOT
FIXTURE_ROOT="$corrupt"
run_case --version vTEST
FIXTURE_ROOT=$FIXTURE_ROOT_SAVED
assert_rc 1
assert_contains "$CASE/stderr" "SHA-256 mismatch"
assert_file_empty "$CASE/cli.log"

# 7. Asset absent from SHA256SUMS fails closed.
begin missing-sums-entry
corrupt="$CASE/rel"
cp -R "$FIXTURE_ROOT" "$corrupt"
( cd "$corrupt/releases/download/vTEST" && sha256sum /dev/null | sed 's# /dev/null#  other.tar.gz#' >SHA256SUMS )
FIXTURE_ROOT_SAVED=$FIXTURE_ROOT
FIXTURE_ROOT="$corrupt"
run_case --version vTEST
FIXTURE_ROOT=$FIXTURE_ROOT_SAVED
assert_rc 1
assert_contains "$CASE/stderr" "is not listed in SHA256SUMS"
assert_file_empty "$CASE/cli.log"

# 8. Provenance: gh success.
begin gh-ok
ln -sf "$SHIM/gh" "$CASE/shim/gh"
K_GH=1
run_case --version vTEST
assert_rc 0
assert_contains "$CASE/stdout" "provenance: OK"
assert_contains "$CASE/cli.log" "install"

# 9. Provenance: gh failure warns but a checksum-verified install still proceeds.
begin gh-fail
ln -sf "$SHIM/gh" "$CASE/shim/gh"
K_GH=0
run_case --version vTEST
assert_rc 0
assert_contains "$CASE/stderr" "warning: could not verify build provenance"
assert_contains "$CASE/cli.log" "install"

# 10. Unsupported architecture.
begin bad-arch
K_UNAME=riscv64
run_case --version vTEST
assert_rc 1
assert_contains "$CASE/stderr" "unsupported architecture"

# 11. Latest-tag probe returns no /tag/ component.
begin latest-malformed
K_LATEST="https://github.com/$REPO/releases"
run_case
assert_rc 1
assert_contains "$CASE/stderr" "could not resolve the latest release"

# 12. Latest-tag probe resolves and pins that tag.
begin latest-ok
K_LATEST="https://github.com/$REPO/releases/tag/vTEST"
run_case
assert_rc 0
assert_contains "$CASE/stdout" "release:    vTEST"
assert_contains "$CASE/cli.log" "install"

# 13. WSL_WEBAUTHN_VERSION pins the release (no network probe).
begin env-version
K_WSLVER=vTEST
run_case
assert_rc 0
assert_contains "$CASE/stdout" "release:    vTEST"
assert_contains "$CASE/cli.log" "install"

# 14. A `--version` *after* the first passthrough token is forwarded verbatim.
begin version-after-passthrough
K_LATEST="https://github.com/$REPO/releases/tag/vTEST"
run_case --skip-enroll --version vTEST
assert_rc 0
assert_contains "$CASE/cli.log" "install --skip-enroll --version vTEST"

# 15. Tarball with an unexpected root directory fails closed.
begin wrong-root
wrong="$CASE/wrong"
mkdir -p "$wrong/wsl-webauthn-pam-TEST-x86_64-BAD"
cp "$WORK/stage/wsl-webauthn-pam-TEST-x86_64/wsl-webauthn-pam" "$wrong/wsl-webauthn-pam-TEST-x86_64-BAD/"
chmod 0755 "$wrong/wsl-webauthn-pam-TEST-x86_64-BAD/wsl-webauthn-pam"
cp -R "$FIXTURE_ROOT" "$CASE/rel"
( cd "$wrong" && tar -czf "$CASE/rel/releases/download/vTEST/wsl-webauthn-pam-TEST-x86_64.tar.gz" wsl-webauthn-pam-TEST-x86_64-BAD )
( cd "$CASE/rel/releases/download/vTEST" && sha256sum wsl-webauthn-pam-TEST-*.tar.gz >SHA256SUMS )
FIXTURE_ROOT_SAVED=$FIXTURE_ROOT
FIXTURE_ROOT="$CASE/rel"
run_case --version vTEST
FIXTURE_ROOT=$FIXTURE_ROOT_SAVED
assert_rc 1
assert_contains "$CASE/stderr" "did not contain an executable CLI"
assert_file_empty "$CASE/cli.log"

# 16. A non-executable CLI in the tarball fails closed. bootstrap expects the
# canonical name exactly, so repack it in a private tree with mode 0644.
begin noexec-cli
cp -R "$FIXTURE_ROOT" "$CASE/rel"
stage="$CASE/stage/wsl-webauthn-pam-TEST-x86_64"
mkdir -p "$stage"
cp "$WORK/stage/wsl-webauthn-pam-TEST-x86_64/wsl-webauthn-pam" "$stage/"
chmod 0644 "$stage/wsl-webauthn-pam"
( cd "$CASE/stage" && tar -czf "$CASE/rel/releases/download/vTEST/wsl-webauthn-pam-TEST-x86_64.tar.gz" wsl-webauthn-pam-TEST-x86_64 )
( cd "$CASE/rel/releases/download/vTEST" && sha256sum wsl-webauthn-pam-TEST-*.tar.gz >SHA256SUMS )
FIXTURE_ROOT_SAVED=$FIXTURE_ROOT
FIXTURE_ROOT="$CASE/rel"
run_case --version vTEST
FIXTURE_ROOT=$FIXTURE_ROOT_SAVED
assert_rc 1
assert_contains "$CASE/stderr" "did not contain an executable CLI"
assert_file_empty "$CASE/cli.log"

# 17. Missing required tool is named and fails closed.
begin missing-tool
PATH_DIR="$CASE/min"
run_case --version vTEST
assert_rc 1
assert_contains "$CASE/stderr" "required tool 'curl' not found"
assert_file_empty "$CASE/cli.log"

# 18. Fetch failure (asset missing server-side) fails closed.
begin fetch-failure
run_case --version vMISSING
assert_rc_nonzero
assert_file_empty "$CASE/cli.log"

# 19. The installer's exit status is propagated.
begin exit-propagation
K_CLI_EXIT=7
run_case --version vTEST
assert_rc 7
assert_contains "$CASE/cli.log" "install"

# 20. The documented invocation (`cat bootstrap.sh | bash`) behaves identically.
begin piped
ln -sf "$SHIM/gh" "$CASE/shim/gh"
set +e
"$ENV_BIN" -i \
    PATH="$PATH_DIR" \
    HOME="$CASE/home" \
    TMPDIR="$CASE/tmp" \
    BOOTSTRAP_TEST_REPO="$REPO" \
    BOOTSTRAP_TEST_ROOT="$FIXTURE_ROOT" \
    BOOTSTRAP_TEST_CLI_LOG="$CASE/cli.log" \
    BOOTSTRAP_TEST_SUDO_LOG="$CASE/sudo.log" \
    BOOTSTRAP_TEST_UNAME="$K_UNAME" \
    BOOTSTRAP_TEST_UID="$K_UID" \
    BOOTSTRAP_TEST_GH="$K_GH" \
    BOOTSTRAP_TEST_LATEST_URL="$K_LATEST" \
    BOOTSTRAP_TEST_CLI_EXIT="$K_CLI_EXIT" \
    WSL_WEBAUTHN_VERSION="$K_WSLVER" \
    "$SH_BIN" -c "\"$CAT_BIN\" \"$BOOTSTRAP\" | \"$BASH_BIN\" -s -- --version vTEST" \
    >"$CASE/stdout" 2>"$CASE/stderr"
RC=$?
set -e
if [ -n "$(find "$CASE/tmp" -mindepth 1 -print -quit 2>/dev/null)" ]; then
    bad "$CASE: TMPDIR was not cleaned"
fi
assert_rc 0
assert_contains "$CASE/cli.log" "install"
assert_contains "$CASE/stdout" "sha256:     OK"

# ---------------------------------------------------------------------------
check_naming_coherence

echo
if [ "$FAILS" -ne 0 ]; then
    printf '%d check(s) failed\n' "$FAILS" >&2
    exit 1
fi
printf 'all bootstrap checks passed\n'
