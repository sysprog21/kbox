#!/bin/sh
# SPDX-License-Identifier: MIT
# Build an ext4 rootfs image from Alpine minirootfs for kbox.
#
# Usage: ./scripts/mkrootfs.sh [SIZE_MB]
#   SIZE_MB defaults to 128.
#
# Prerequisites:
#   - mke2fs (e2fsprogs) with -d support (e2fsprogs >= 1.43)
#   - curl or wget (for downloading Alpine minirootfs)
#   - sha256sum
#
# The script builds the rootfs without requiring root privileges by using
# mke2fs -d to populate the image from a staging directory.

set -eu

. "$(cd "$(dirname "$0")" && pwd)/common.sh"

SIZE_MB="${1:-128}"
OUTFILE="${ROOTFS:-alpine.ext4}"
GUEST_DIR="tests/guest"
STRESS_DIR="tests/stress"
CACHE_DIR="deps"
STAGING=""

ALPINE_VERSION="3.21"
if [ -z "${ALPINE_ARCH:-}" ]; then
    detect_arch
    ALPINE_ARCH="$ARCH"
fi
ALPINE_TARBALL="alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/${ALPINE_ARCH}/${ALPINE_TARBALL}"
ALPINE_SHA256_FILE="scripts/alpine-sha256.txt"

cleanup()
{
    if [ -n "$STAGING" ] && [ -d "$STAGING" ]; then
        rm -rf "$STAGING"
    fi
}
trap cleanup EXIT

command -v mke2fs > /dev/null 2>&1 || die "mke2fs not found. Install e2fsprogs."
command -v sha256sum > /dev/null 2>&1 || die "sha256sum not found."

# Download Alpine minirootfs (cached in deps/).
mkdir -p "$CACHE_DIR"
TARBALL_PATH="${CACHE_DIR}/${ALPINE_TARBALL}"

if [ ! -f "$TARBALL_PATH" ]; then
    echo "Downloading Alpine minirootfs ${ALPINE_VERSION} (${ALPINE_ARCH})..."
    download_file "$ALPINE_URL" "$TARBALL_PATH"
fi

verify_sha256 "$TARBALL_PATH" "$ALPINE_SHA256_FILE" "$ALPINE_TARBALL"

# Create staging directory and extract Alpine rootfs.
STAGING=$(mktemp -d)
echo "Extracting Alpine minirootfs into staging..."
tar xzf "$TARBALL_PATH" -C "$STAGING"

# Ensure key directories exist.
for d in bin sbin usr/bin usr/sbin lib lib64 etc tmp home root \
    var var/tmp dev proc sys run opt opt/stress; do
    mkdir -p "${STAGING}/${d}"
done

# Inject /etc/passwd and /etc/group if not present (Alpine has them).
if [ ! -f "${STAGING}/etc/passwd" ]; then
    cat > "${STAGING}/etc/passwd" << 'EOF'
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
EOF
fi

if [ ! -f "${STAGING}/etc/group" ]; then
    cat > "${STAGING}/etc/group" << 'EOF'
root:x:0:
tty:x:5:
nogroup:x:65534:
EOF
fi

# Shell profile.
cat > "${STAGING}/root/.profile" << 'EOF'
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export HOME=/root
export PS1='kbox# '
EOF
chmod 644 "${STAGING}/root/.profile"

# Inject guest test programs (pre-compiled static binaries).
if [ -d "$GUEST_DIR" ]; then
    mkdir -p "${STAGING}/opt/tests"
    for prog in "$GUEST_DIR"/*-test; do
        if [ -x "$prog" ]; then
            cp "$prog" "${STAGING}/opt/tests/"
        fi
    done
fi

# Inject stress test programs (pre-compiled static binaries).
if [ -d "$STRESS_DIR" ]; then
    mkdir -p "${STAGING}/opt/stress"
    for prog in "$STRESS_DIR"/*; do
        case "$prog" in *.c | *.h | *.o) continue ;; esac
        if [ -x "$prog" ]; then
            cp "$prog" "${STAGING}/opt/stress/"
        fi
    done
fi

# Inject external network testing binaries.
if [ -x "deps/iperf3" ]; then
    cp deps/iperf3 "${STAGING}/usr/bin/"
fi
if [ -x "deps/netperf" ]; then
    cp deps/netperf "${STAGING}/usr/bin/"
fi

echo "Creating ${SIZE_MB}MB ext4 image at ${OUTFILE}..."

# Create the ext4 image from the staging directory.
# mke2fs -d populates the image without requiring root.
mke2fs -t ext4 -d "$STAGING" -L kbox-rootfs \
    -b 4096 -r 1 -N 0 \
    "$OUTFILE" "${SIZE_MB}M" 2> /dev/null

echo "OK: ${OUTFILE} ($(du -h "$OUTFILE" | cut -f1))"
