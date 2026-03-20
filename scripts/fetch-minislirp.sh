#!/bin/sh
# SPDX-License-Identifier: MIT
# Fetch minislirp via shallow clone for SLIRP networking support.
#
# Usage: ./scripts/fetch-minislirp.sh
#   Override SLIRP_DIR to change output directory.
#   Override MINISLIRP_REPO to use a fork.

set -eu

SLIRP_DIR="${SLIRP_DIR:-externals/minislirp}"
REPO="${MINISLIRP_REPO:-https://github.com/sysprog21/minislirp}"

# Validate SLIRP_DIR to prevent rm -rf on unintended paths.
case "$SLIRP_DIR" in
    /*|""|.|..|*/..*) echo "error: SLIRP_DIR must be a relative sub-path without .." >&2; exit 1 ;;
esac

if [ -f "${SLIRP_DIR}/src/libslirp.h" ]; then
    echo "minislirp already present at ${SLIRP_DIR}"
    exit 0
fi

echo "Fetching minislirp from ${REPO} ..."
rm -rf "${SLIRP_DIR}"
git clone --depth=1 "${REPO}" "${SLIRP_DIR}"

# Strip git metadata -- we don't need history.
rm -rf "${SLIRP_DIR}/.git"

echo "minislirp ready at ${SLIRP_DIR}"
