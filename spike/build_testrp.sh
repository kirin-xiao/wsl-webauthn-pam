#!/usr/bin/env bash
# Build a bridge that pins a *different* RP ID, for the D2 robustness experiment
# in SPIKE.md (does the platform accept RP IDs of the pinned shape?).
#
# The RP ID is a compile-time constant in `wsl-webauthn-protocol`, so the only
# way to test a second RP ID without touching the protocol crate is to patch the
# constant, build, and restore. This script does exactly that and never leaves
# the source modified. It is spike-only tooling.
#
# Usage: spike/build_testrp.sh [test-rp-id]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_RP_ID="${1:-io.github.kirin-xiao.wsl-webauthn-pam-test}"
LIB="$REPO_ROOT/crates/wsl-webauthn-protocol/src/lib.rs"
OUT="$REPO_ROOT/spike/WSLWebAuthnBridge-testrp.exe"
BACKUP="$(mktemp)"
trap 'cp "$BACKUP" "$LIB"; rm -f "$BACKUP"' EXIT

cp "$LIB" "$BACKUP"
sed -i "s|pub const RP_ID: &str = \"[^\"]*\";|pub const RP_ID: \&str = \"$TEST_RP_ID\";|" "$LIB"
grep -n 'pub const RP_ID' "$LIB"

cd "$REPO_ROOT"
cargo build --release -p wsl-webauthn-bridge --target x86_64-pc-windows-gnu --locked
cp "$REPO_ROOT/target/x86_64-pc-windows-gnu/release/WSLWebAuthnBridge.exe" "$OUT"

echo "built $OUT with RP_ID=$TEST_RP_ID"
echo "run: python3 spike/harness.py --exe $OUT --rp-id $TEST_RP_ID <subcommand>"
