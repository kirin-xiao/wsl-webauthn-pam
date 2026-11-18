#!/bin/sh
# Assemble the single tree GitHub Pages serves: the documentation site *and* the
# signed apt repository.
#
# Usage: publish-pages.sh [site-dir]
#
#   [site-dir]  output root (default: site/apt). It must already contain the
#               released packages under pool/main/w/wsl-webauthn-pam/*.deb; the
#               callers (release.yaml, pages.yaml) download every released
#               stable .deb there before calling this.
#
# Env:
#   GPG_KEY_ID       key id or fingerprint of the already-imported signing key
#   GPG_PASSPHRASE   passphrase for that key (omit for a passphrase-less key)
#   APT_SUITE        suite/codename (default: stable)
#   APT_ORIGIN       Origin and Label (default: wsl-webauthn-pam)
#   MAKE             make program (default: make)
#
# Why one script: the site and the repository share an origin — `/` is the apt
# root, so `dists/`, `pool/` and the archive keyring sit next to the landing page
# and the docs live under `/docs/`. Exactly one place must decide what that tree
# looks like, otherwise the release path and the manual republish (pages.yaml)
# drift apart. Both call this script; a PR runs the same link checker it runs
# here, so a broken link cannot reach a deployment.
#
# The two trees may not collide. `dists/`, `pool/` and the archive keyring are
# owned by build-apt-repo.sh; everything else (`index.html`, `/docs/`, assets) is
# owned by the site. `index.html` is the one permitted overlap and the site's
# copy wins, because the site is copied last. A `web/static/` file that landed on
# an apt path would otherwise silently replace a signed index, so this fails
# closed here — and check-site-links.py fails on it in CI, before it can ship.
set -eu

site=${1:-site/apt}
make=${MAKE:-make}
public=web/public

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

die() {
    echo "publish-pages: $*" >&2
    exit 1
}

[ -d "$site/pool" ] ||
    die "$site/pool is missing; download the released .deb files there first"
debs=$(find "$site/pool" -type f -name '*.deb' | sort)
[ -n "$debs" ] || die "no .deb under $site/pool; refusing to publish an empty repository"

# --- build the documentation site --------------------------------------------
# `web/public` is git-ignored build output: drop it first, because `zola build`
# only writes — it never prunes. Without this, a page that was renamed or
# deleted since the last run would survive as a stale HTML file in the
# published tree (and its links would keep "working").
rm -rf "$public"
"$make" site

[ -f "$public/index.html" ] || die "$public/index.html was not produced by '$make site'"

# --- fail closed on a site/apt path collision --------------------------------
for reserved in dists pool; do
    [ ! -e "$public/$reserved" ] ||
        die "$public/$reserved collides with the apt repository's /$reserved/"
done
for keyring in "$public"/*.gpg; do
    [ ! -e "$keyring" ] || die "$keyring collides with the archive keyring path"
done

# The same guard CI runs on every PR (internal links, #fragments, the seven docs
# pages, apt-path shadowing, the security page's link to SECURITY.md). Running
# it here too means a release or a manual republish cannot publish a tree that
# CI would have rejected.
python3 .github/scripts/check-site-links.py "$public"

# --- assemble the published tree ---------------------------------------------
# Copy after the pool was populated: `index.html` is the one path both owners
# care about, and the site's landing page is authoritative (it overwrites any
# file left at that path by an earlier run).
#
# `cp -R` overwrites but never prunes, so remove each site-owned top-level entry
# first: a page or directory that a later build no longer emits would otherwise
# survive as a stale file in the published tree. The apt namespace is below and
# is explicitly refused here, so a bug in the site build cannot delete a signed
# index or the pool.
# Refuse an apt-owned path from the site build before touching the tree.
for entry in "$public"/*; do
    name=$(basename "$entry")
    case "$name" in
        dists | pool | *.gpg)
            die "the site build produced /$name, which the apt repository owns"
            ;;
    esac
done

# Remove everything an earlier publish left, except the apt-owned paths. `$site`
# is a dedicated publish root, not the repository: the only things in it this
# script did not write are the pool (pre-populated by the caller) and the
# metadata, keyring and `.nojekyll` that build-apt-repo.sh emits. Pruning the
# rest is what stops a renamed or deleted page — or a whole top-level directory
# dropped from `web/static` — from surviving a local republish.
mkdir -p "$site"
for entry in "$site"/* "$site"/.nojekyll; do
    [ -e "$entry" ] || continue
    name=$(basename "$entry")
    case "$name" in
        dists | pool | wsl-webauthn-pam-archive-keyring.gpg | .nojekyll) continue ;;
    esac
    rm -rf "${site:?}/$name"
done
cp -R "$public"/. "$site"/

# --- build + sign the apt repository in place --------------------------------
# build-apt-repo.sh re-indexes every .deb in the pool, writes dists/<suite>/ and
# the exported keyring, drops `.nojekyll`, and fails closed if the generated
# InRelease does not verify.
sh .github/scripts/build-apt-repo.sh "$site" main

# --- assert the published root is the tree we promised -----------------------
suite=${APT_SUITE:-stable}
[ -f "$site/index.html" ] || die "$site/index.html is missing from the published tree"
[ -d "$site/dists/$suite" ] || die "$site/dists/$suite is missing from the published tree"
[ -f "$site/dists/$suite/InRelease" ] ||
    die "$site/dists/$suite/InRelease is missing from the published tree"
[ -d "$site/pool" ] || die "$site/pool is missing from the published tree"
[ -f "$site/wsl-webauthn-pam-archive-keyring.gpg" ] ||
    die "$site/wsl-webauthn-pam-archive-keyring.gpg is missing from the published tree"

# The docs set is the site's contract with the install instructions; a missing
# page is a 404 from the published origin, not a build error Zola would report.
for slug in install how-it-works security usage troubleshooting faq prior-art; do
    [ -f "$site/docs/$slug/index.html" ] ||
        die "docs page /docs/$slug/ is missing from the published tree"
done

count=$(printf '%s\n' "$debs" | wc -l | tr -d ' ')
echo "publish-pages: $site ready (dists/$suite, $count package(s), landing page + 7 docs pages)"
