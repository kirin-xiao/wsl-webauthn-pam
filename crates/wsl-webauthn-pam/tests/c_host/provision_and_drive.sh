#!/bin/sh
# provision_and_drive.sh — give a real `pam_start`/libpam stack a provisioned
# store and a scripted fake bridge, then drive the built pam_wsl_webauthn.so
# through the compiled C host (`pam_host`).
#
# It is always executed inside a fresh **mount namespace**:
#
#   * unprivileged dev/CI:  unshare -rm /bin/sh provision_and_drive.sh …
#   * root-gated tier:      sudo -n unshare -m /bin/sh provision_and_drive.sh …
#
# Shadowing `/etc` with a private tmpfs means the store it creates is owned by
# the caller's mapped uid: uid 0 in a user namespace, or real root under the
# root-gated tier. Either way `Store::system()` (which expects files owned by
# uid 0 at modes 0600/0700) accepts it — no writes to the host `/etc`, and the
# tmpfs disappears with the mount namespace. A private tmpfs over
# `/proc/sys/fs` lets us plant the `WSLInterop` registration the runner's
# pre-flight checks.
#
# Everything is passed as **positional arguments** (not environment) so the same
# invocation works under `sudo`, which resets the environment. The bridge
# secrets are exported by this script just before it execs the C host.
#
# Usage:
#   provision_and_drive.sh <so> <pam_host> <bridge> <record_src> <config_src> \
#       <conf_dir> <expect> [require_conv] [mode] [nthreads] [secret_hex] \
#       [cred_id_b64] [echo]
#
#   expect       success | deny | failclosed
#   require_conv 0 | 1        (single mode)
#   mode         single | concurrent
#   nthreads     thread count (concurrent mode)
#
# `pam_host` is run with alice's provisioned credential; the bridge is invoked by
# the module with no argv, so its key material travels in its environment.

set -eu

if [ "$#" -lt 7 ]; then
    echo "usage: $0 <so> <pam_host> <bridge> <record_src> <config_src> <conf_dir> \\" >&2
    echo "          <expect> [require_conv] [mode] [nthreads] [secret_hex] [cred_id_b64] [echo]" >&2
    exit 2
fi

SO=$1
PAM_HOST=$2
BRIDGE=$3
RECORD_SRC=$4
CONFIG_SRC=$5
CONF_DIR=$6
EXPECT=$7
REQUIRE_CONV=${8:-0}
MODE=${9:-single}
NTHREADS=${10:-8}
SECRET_HEX=${11:-}
CRED_ID_B64=${12:-}
ECHO=${13:-1}

# Private /etc and a private binfmt directory (mount namespace only). The tmpfs
# goes over /proc/sys/fs rather than `/proc/sys/fs/binfmt_misc` because the latter
# may not exist as a mount point on every host (it is created lazily by the binfmt
# kernel module); shadowing the parent works either way.
mount -t tmpfs none /etc
mount -t tmpfs none /proc/sys/fs
mkdir -p /proc/sys/fs/binfmt_misc
printf 'enabled\n' > /proc/sys/fs/binfmt_misc/WSLInterop

# The bridge lives outside /etc (a plain tmpfs, i.e. not DrvFs), so the module's
# trust check enforces the root-owned / not-group-writable rule on it.
#
# `/tmp` is *shared* with the host and with any concurrent test, so a naive
# `cp` into it races: two namespaces truncate-and-rewrite the same file while the
# module is hashing it, and the pin check intermittently sees a partial file and
# fails closed. Mount a private tmpfs over the bridge directory (visible only in
# this mount namespace) so every run gets its own race-free copy.
mkdir -p /tmp/wslwt-test
mount -t tmpfs none /tmp/wslwt-test
cp "$BRIDGE" /tmp/wslwt-test/bridge
chmod 0755 /tmp/wslwt-test /tmp/wslwt-test/bridge

# Production store layout: base 0755 root-owned, config 0600, credentials 0700,
# record 0600.
mkdir -p /etc/wsl_webauthn
chmod 0755 /etc/wsl_webauthn
cp "$CONFIG_SRC" /etc/wsl_webauthn/config
chmod 0600 /etc/wsl_webauthn/config
mkdir -p /etc/wsl_webauthn/credentials
chmod 0700 /etc/wsl_webauthn/credentials
cp "$RECORD_SRC" /etc/wsl_webauthn/credentials/alice.json
chmod 0600 /etc/wsl_webauthn/credentials/alice.json

if [ "${WSLWT_TEST_DEBUG:-0}" = "1" ]; then
    echo "--- namespace diagnostics (uid=$(id -u)) ---" >&2
    ls -la /etc/wsl_webauthn >&2 || true
    stat -c '%n uid=%u mode=%a' /etc /etc/wsl_webauthn \
        /etc/wsl_webauthn/config \
        /etc/wsl_webauthn/credentials/alice.json \
        /tmp/wslwt-test/bridge >&2 || true
fi

# The service files are on the host (readable in this namespace) and point libpam
# at $SO. `wslwt-test`/`wslwt-test-debug` are private confdir services, so no host
# /etc/pam.d is touched.
export WSLWT_TEST_SIGNING_KEY="$SECRET_HEX"
export WSLWT_TEST_CRED_ID="$CRED_ID_B64"
export WSLWT_TEST_ECHO="$ECHO"
# This script only ever drives the module in a test, so opt the module into its
# in-process audit recorder: otherwise the C host's synthetic authentication events
# would be written to the real journal under the production `pam_wsl_webauthn` tag.
export WSL_WEBAUTHN_TEST_CAPTURE=1

case "$MODE" in
    single)
        exec "$PAM_HOST" libpam "$CONF_DIR" wslwt-test alice "$EXPECT" "$REQUIRE_CONV"
        ;;
    concurrent)
        # Alternate between a no-arg service and one with a `debug` module
        # argument, driving distinct per-handle verbosity concurrently.
        exec "$PAM_HOST" concurrent "$CONF_DIR" wslwt-test wslwt-test-debug \
            alice "$NTHREADS" "$EXPECT"
        ;;
    *)
        echo "unknown mode=$MODE" >&2
        exit 2
        ;;
esac
