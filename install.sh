#!/bin/sh
set -eu
exec sudo "$(dirname "$0")/wsl-webauthn-pam" install "$@"
