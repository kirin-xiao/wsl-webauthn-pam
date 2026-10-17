#!/bin/sh
# Build (and GPG-sign) the static apt repository that GitHub Pages serves.
#
# Usage: build-apt-repo.sh <site-dir> [component]
#
#   <site-dir>   tree to publish; must already contain the packages under
#                pool/<component>/w/wsl-webauthn-pam/*.deb (the workflow
#                downloads every released .deb there before calling this)
#   [component]  apt component (default: main)
#
# Env:
#   GPG_KEY_ID       key id or fingerprint of the already-imported signing key
#   GPG_PASSPHRASE   passphrase for that key (omit for a passphrase-less key)
#   APT_SUITE        suite/codename (default: stable)
#   APT_ORIGIN       Origin and Label (default: wsl-webauthn-pam)
#
# No `Valid-Until` is emitted: the repository is republished only when a release
# is cut, so a short expiry would make `apt update` start failing between
# releases (the metadata itself is immutable, since the .deb assets are).
#
# Writes dists/<suite>/{Release,InRelease,Release.gpg} and the per-arch
# Packages(.gz) indexes, exports the public keyring as
# <site-dir>/wsl-webauthn-pam-archive-keyring.gpg, and fails closed if the
# generated InRelease does not verify.
#
# The repository is a pure function of the pool: every run re-indexes every .deb
# present, so the metadata can never drift from the packages it advertises.
set -eu

site=${1:?usage: build-apt-repo.sh <site-dir> [component]}
component=${2:-main}
suite=${APT_SUITE:-stable}
origin=${APT_ORIGIN:-wsl-webauthn-pam}
: "${GPG_KEY_ID:?build-apt-repo: GPG_KEY_ID is required}"

site=$(CDPATH='' cd -- "$site" && pwd)
cd "$site"

# --- discover the packages and the architectures they carry -------------------
debs=$(find "pool/$component" -type f -name '*.deb' 2>/dev/null | sort || true)
if [ -z "$debs" ]; then
    echo "build-apt-repo: no .deb found under pool/$component" >&2
    exit 1
fi

arches=$(for deb in $debs; do dpkg-deb -f "$deb" Architecture; done | sort -u)
arches_space=
for arch in $arches; do
    arches_space="${arches_space}${arches_space:+ }${arch}"
done
echo "build-apt-repo: architectures: $arches_space"

# --- per-architecture indexes -------------------------------------------------
# apt's binary-<arch>/Packages advertises only packages of that architecture, so
# filter the full pool listing into one stanza list per arch. `RS=''` is awk's
# paragraph mode: one record per package stanza.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

apt-ftparchive packages "pool/$component" > "$tmp/all"
for arch in $arches; do
    dir="dists/$suite/$component/binary-$arch"
    mkdir -p "$dir"
    awk -v RS='' -v ORS='\n\n' -v want="$arch" '
        {
            for (i = 1; i < NF; i++)
                if ($i == "Architecture:" && $(i + 1) == want) { print; break }
        }
    ' "$tmp/all" > "$dir/Packages"
    # `-n` drops the name/timestamp so the index is byte-reproducible.
    gzip -9nf -k "$dir/Packages"
    count=$(grep -c '^Package:' "$dir/Packages" || true)
    echo "build-apt-repo: $dir/Packages ($count package(s))"
done

# --- Release + signatures -----------------------------------------------------
apt-ftparchive \
    -o "APT::FTPArchive::Release::Origin=$origin" \
    -o "APT::FTPArchive::Release::Label=$origin" \
    -o "APT::FTPArchive::Release::Suite=$suite" \
    -o "APT::FTPArchive::Release::Codename=$suite" \
    -o "APT::FTPArchive::Release::Architectures=$arches_space" \
    -o "APT::FTPArchive::Release::Components=$component" \
    release "dists/$suite" > "$tmp/Release"
mv "$tmp/Release" "dists/$suite/Release"

sign() {
    if [ -n "${GPG_PASSPHRASE:-}" ]; then
        gpg --batch --yes --pinentry-mode loopback --passphrase "$GPG_PASSPHRASE" "$@"
    else
        gpg --batch --yes "$@"
    fi
}

sign --local-user "$GPG_KEY_ID" --clearsign -o "dists/$suite/InRelease" "dists/$suite/Release"
sign --local-user "$GPG_KEY_ID" --detach-sign -o "dists/$suite/Release.gpg" "dists/$suite/Release"

# The public keyring users install into /etc/apt/keyrings and reference from
# `Signed-By:`.
sign --export "$GPG_KEY_ID" > wsl-webauthn-pam-archive-keyring.gpg

# Fail closed: never publish an index apt would reject.
gpg --verify "dists/$suite/InRelease"

# GitHub Pages would otherwise run Jekyll over the pool.
: > .nojekyll

echo "build-apt-repo: wrote dists/$suite/{Release,InRelease,Release.gpg} + keyring"
