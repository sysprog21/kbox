#!/bin/sh
# SPDX-License-Identifier: MIT
# Build a static netperf binary for rootfs construction.
#
# Usage: ./scripts/fetch-netperf.sh [ARCH]
#   ARCH defaults to x86_64.

set -eu

. "$(cd "$(dirname "$0")" && pwd)/common.sh"

NETPERF_VERSION="${NETPERF_VERSION:-2.7.0}"
URL="https://github.com/HewlettPackard/netperf/archive/refs/tags/netperf-${NETPERF_VERSION}.tar.gz"
OUTDIR="deps"
OUTFILE="${OUTDIR}/netperf"
SRCDIR="${OUTDIR}/netperf-src"

if [ -x "$OUTFILE" ]; then
    echo "netperf already exists at ${OUTFILE}, skipping build."
    exit 0
fi

echo "Downloading and building netperf ${NETPERF_VERSION}..."
mkdir -p "$OUTDIR"
mkdir -p "$SRCDIR"

TARBALL="${OUTDIR}/netperf-${NETPERF_VERSION}.tar.gz"
if [ ! -f "$TARBALL" ]; then
    download_file "$URL" "$TARBALL"
fi

tar -xzf "$TARBALL" -C "$SRCDIR" --strip-components=1

echo "Configuring netperf..."
cd "$SRCDIR"
./configure CFLAGS="-fcommon" LDFLAGS="-static" > /dev/null 2>&1

echo "Compiling netperf..."
make -j"$(nproc 2>/dev/null || echo 1)" > /dev/null 2>&1

cd - > /dev/null
cp "${SRCDIR}/src/netperf" "$OUTFILE"
rm -rf "$SRCDIR" "$TARBALL"

chmod +x "$OUTFILE"
echo "OK: ${OUTFILE}"

# Verify it's actually a static binary.
if command -v file > /dev/null 2>&1; then
    file "$OUTFILE"
fi
