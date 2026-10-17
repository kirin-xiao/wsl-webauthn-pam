#!/bin/sh
# Build the Debian/Ubuntu package for one architecture with nfpm.
#
# Usage: build-deb.sh <arch> <version> <linux-dir> <bridge-exe> <out-dir>
#   arch        x86_64 | aarch64 (the release labels; amd64/arm64 also accepted)
#   version     Debian version string; a pre-release dash must already be a `~`
#               (e.g. 0.2.0~rc1), because a deb version may not contain `-`
#   linux-dir   directory holding libpam_wsl_webauthn.so and wsl-webauthn-pam
#   bridge-exe  path to WSLWebAuthnBridge.exe
#   out-dir     directory for wsl-webauthn-pam_<version>_<deb-arch>.deb
#
# The package layout and dependency set live in packaging/nfpm.yaml; this wrapper
# only maps the release arch labels to the deb architecture and the multiarch
# security-directory triplet, checks the inputs, and calls nfpm.
set -eu

arch=${1:?usage: build-deb.sh <arch> <version> <linux-dir> <bridge-exe> <out-dir>}
version=${2:?usage: build-deb.sh <arch> <version> <linux-dir> <bridge-exe> <out-dir>}
linux_dir=${3:?usage: build-deb.sh <arch> <version> <linux-dir> <bridge-exe> <out-dir>}
bridge=${4:?usage: build-deb.sh <arch> <version> <linux-dir> <bridge-exe> <out-dir>}
out_dir=${5:?usage: build-deb.sh <arch> <version> <linux-dir> <bridge-exe> <out-dir>}

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

case "$arch" in
    x86_64 | amd64) deb_arch=amd64; pam_triplet=x86_64-linux-gnu ;;
    aarch64 | arm64) deb_arch=arm64; pam_triplet=aarch64-linux-gnu ;;
    *) echo "build-deb: unsupported arch '$arch' (expected x86_64|aarch64)" >&2; exit 2 ;;
esac

case "$version" in
    *-*)
        echo "build-deb: version '$version' contains '-'; map a pre-release to '~' first (0.2.0~rc1)" >&2
        exit 2
        ;;
esac

for required in "$linux_dir/libpam_wsl_webauthn.so" "$linux_dir/wsl-webauthn-pam" "$bridge"; do
    [ -f "$required" ] || { echo "build-deb: missing $required" >&2; exit 1; }
done

# nfpm reads the contents' `src` paths from the working directory, so resolve
# them to absolute paths before handing them over.
linux_dir=$(CDPATH='' cd -- "$linux_dir" && pwd)
bridge=$(CDPATH='' cd -- "$(dirname -- "$bridge")" && pwd)/$(basename -- "$bridge")
mkdir -p "$out_dir"
out_dir=$(CDPATH='' cd -- "$out_dir" && pwd)

command -v nfpm >/dev/null 2>&1 || {
    echo "build-deb: nfpm not on PATH (pinned version in CONTRIBUTING.md)" >&2
    exit 1
}

DEB_ARCH=$deb_arch \
DEB_VERSION=$version \
LINUX_DIR=$linux_dir \
BRIDGE=$bridge \
PAM_TRIPLET=$pam_triplet \
    nfpm pkg --packager deb -f packaging/nfpm.yaml \
        --target "$out_dir/wsl-webauthn-pam_${version}_${deb_arch}.deb"

echo "build-deb: wrote $out_dir/wsl-webauthn-pam_${version}_${deb_arch}.deb"
