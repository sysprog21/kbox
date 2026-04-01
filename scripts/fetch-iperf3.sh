#!/bin/sh
# SPDX-License-Identifier: MIT
# Download a static iperf3 binary for rootfs construction.
#
# Usage: ./scripts/fetch-iperf3.sh [ARCH]
#   ARCH defaults to x86_64.
set -eu

. "$(cd "$(dirname "$0")" && pwd)/common.sh"

ARCH="${1:-x86_64}"
IPERF3_VERSION="${IPERF3_VERSION:-3.17.1}"
OUTDIR="deps"
OUTFILE="${OUTDIR}/iperf3"

case "$ARCH" in
    x86_64)
        URL="https://github.com/userdocs/iperf3-static/releases/download/${IPERF3_VERSION}/iperf3-amd64"
        ;;
    aarch64)
        URL="https://github.com/userdocs/iperf3-static/releases/download/${IPERF3_VERSION}/iperf3-aarch64"
        ;;
    *)
        die "Unsupported architecture: ${ARCH}"
        ;;
esac

mkdir -p "$OUTDIR"

if [ -x "$OUTFILE" ]; then
    echo "iperf3 already exists at ${OUTFILE}, skipping download."
    exit 0
fi

echo "Downloading iperf3 ${IPERF3_VERSION} (${ARCH})..."
download_file "$URL" "$OUTFILE"

chmod +x "$OUTFILE"
echo "OK: ${OUTFILE}"

# Verify it's actually a static binary.
if command -v file > /dev/null 2>&1; then
    file "$OUTFILE"
fi
