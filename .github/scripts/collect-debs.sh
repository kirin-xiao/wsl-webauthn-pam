#!/bin/sh
# Download every released stable .deb into the apt pool that Pages will serve.
#
# Usage: collect-debs.sh <pool-dir>
#
#   <pool-dir>  destination, normally
#               site/apt/pool/main/w/wsl-webauthn-pam. Created if absent.
#
# Env:
#   GITHUB_REPOSITORY  owner/repo to read releases from (omit to use the
#                      repository of the current git checkout)
#   GH_TOKEN           token for gh (set by the workflows as ${{ github.token }})
#
# Why this is not an inline loop: a missing historical version is a silent
# downgrade for anyone pinning it, and a transient `gh release download` failure
# used to be swallowed by `|| true`, so a release or a manual republish could
# publish a pool that was quietly incomplete. Here a release that advertises a
# `wsl-webauthn-pam_*.deb` must yield every advertised file; a failed download or
# a still-absent file fails the job and names the tag.
#
# Releases that predate .deb packaging have no matching asset and are skipped:
# they are listed in the closing summary, so an unexpected skip is visible. The
# caller still owns the policy check (release.yaml asserts its own tag landed;
# pages.yaml asserts the pool is non-empty).
#
# Pre-releases are excluded: the `stable` suite must never serve an `~rc`
# package.
set -eu

pool=${1:?usage: collect-debs.sh <pool-dir>}

die() {
    echo "collect-debs: $*" >&2
    exit 1
}

# `gh -R` only when the caller supplies a repository, so a local run uses the
# checkout's own remote.
ghr() {
    if [ -n "${GITHUB_REPOSITORY:-}" ]; then
        gh -R "$GITHUB_REPOSITORY" "$@"
    else
        gh "$@"
    fi
}

mkdir -p "$pool"

tags=$(ghr release list --limit 1000 --exclude-pre-releases \
    --json tagName -q '.[].tagName') ||
    die "cannot list releases (is gh authenticated? see GH_TOKEN)"

releases=0
fetched=0
skipped=
for tag in $tags; do
    [ -n "$tag" ] || continue
    releases=$((releases + 1))

    assets=$(ghr release view "$tag" --json assets -q '.assets[].name') ||
        die "release $tag: cannot list assets"

    wanted=
    for name in $assets; do
        case $name in
            wsl-webauthn-pam_*.deb)
                wanted="$wanted $name"
                ;;
        esac
    done

    if [ -z "$wanted" ]; then
        skipped="$skipped $tag"
        continue
    fi

    for name in $wanted; do
        ghr release download "$tag" -p "$name" -D "$pool" --clobber ||
            die "release $tag: failed to download $name"
        [ -f "$pool/$name" ] ||
            die "release $tag: $name is missing from $pool after the download"
        fetched=$((fetched + 1))
    done
done

echo "collect-debs: fetched $fetched package(s) from $releases stable release(s) into $pool"
if [ -n "$skipped" ]; then
    echo "collect-debs: no .deb asset (predates packaging), skipped:$skipped"
else
    echo "collect-debs: every stable release advertised a .deb"
fi
