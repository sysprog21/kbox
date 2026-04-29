#!/bin/sh
# SPDX-License-Identifier: MIT
# Build an ext4 rootfs image for kbox from Alpine minirootfs (default) or
# an OCI image pulled from a v2 registry.
#
# Usage:
#   ./scripts/mkrootfs.sh [--image=docker://IMAGE[:TAG]] [--size=MB] [SIZE_MB]
#
# Prerequisites:
#   - mke2fs (e2fsprogs) with -d support (e2fsprogs >= 1.43)
#   - curl or wget (for the default Alpine path)
#   - python3 (for --image)
#   - sha256sum
#
# The script builds the rootfs without requiring root privileges by using
# mke2fs -d to populate the image from a staging directory.

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

SIZE_MB=128
IMAGE=""
REWRITE_UID=0

# Validate that the size argument is a non-empty digit-only string.
# Applied at all three entry points (--size=N, --size N, bare positional)
# so a typo like `--size=abc` fails loudly instead of being assigned and
# blowing up much later inside mke2fs.
validate_size()
{
    case "$1" in
        '' | *[!0-9]*) die "invalid size: ${1:-(empty)} (expected integer MB)" ;;
    esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --image=*) IMAGE="${1#--image=}" ;;
        --image)
            shift
            [ $# -gt 0 ] || die "--image requires an argument"
            IMAGE="$1"
            ;;
        --size=*)
            SIZE_MB="${1#--size=}"
            validate_size "$SIZE_MB"
            ;;
        --size)
            shift
            [ $# -gt 0 ] || die "--size requires an argument"
            validate_size "$1"
            SIZE_MB="$1"
            ;;
        --rewrite-uid) REWRITE_UID=1 ;;
        -h | --help)
            cat << EOF
Usage: $0 [--image=docker://IMAGE[:TAG]] [--size=MB] [--rewrite-uid] [SIZE_MB]
  Build an ext4 rootfs at \$ROOTFS (default: alpine.ext4).
  Without --image, fetch the Alpine minirootfs (default behavior).
  With --image, pull the image from a v2 registry instead.
  With --rewrite-uid (requires --image), restore OCI tar-header
  uid/gid/mode into ext4 inodes via tools/oci-chown. Required when
  the rootfs will be used with kbox --root-id.
EOF
            exit 0
            ;;
        -*) die "unknown option: $1 (try --help)" ;;
        *)
            # Backward compat: bare positional is SIZE_MB.
            validate_size "$1"
            SIZE_MB="$1"
            ;;
    esac
    shift
done

if [ "$REWRITE_UID" = 1 ] && [ -z "$IMAGE" ]; then
    die "--rewrite-uid requires --image"
fi

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

STAGING=$(mktemp -d)

if [ -n "$IMAGE" ]; then
    command -v python3 > /dev/null 2>&1 \
        || die "python3 not found (required for --image)."
    echo "Pulling OCI image ${IMAGE}..."
    MANIFEST_FLAG=""
    OCI_MANIFEST=""
    if [ "$REWRITE_UID" = 1 ]; then
        OCI_MANIFEST=$(mktemp)
        MANIFEST_FLAG="--manifest=${OCI_MANIFEST}"
    fi
    python3 "${SCRIPT_DIR}/oci-pull.py" pull \
        --image="$IMAGE" \
        --output="$STAGING" \
        --arch="$ALPINE_ARCH" \
        ${MANIFEST_FLAG}
else
    # Download Alpine minirootfs (cached in deps/).
    mkdir -p "$CACHE_DIR"
    TARBALL_PATH="${CACHE_DIR}/${ALPINE_TARBALL}"

    if [ ! -f "$TARBALL_PATH" ]; then
        echo "Downloading Alpine minirootfs ${ALPINE_VERSION} (${ALPINE_ARCH})..."
        download_file "$ALPINE_URL" "$TARBALL_PATH"
    fi

    verify_sha256 "$TARBALL_PATH" "$ALPINE_SHA256_FILE" "$ALPINE_TARBALL"

    echo "Extracting Alpine minirootfs into staging..."
    tar xzf "$TARBALL_PATH" -C "$STAGING"
fi

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

echo "Creating ${SIZE_MB}MB ext4 image at ${OUTFILE}..."

# Create the ext4 image from the staging directory.
# mke2fs -d populates the image without requiring root.
mke2fs -t ext4 -d "$STAGING" -L kbox-rootfs \
    -b 4096 -r 1 -N 0 \
    "$OUTFILE" "${SIZE_MB}M" 2> /dev/null

# Restore OCI tar-header uid/gid/mode in the ext4 inodes. mke2fs -d inherits
# the invoking user's UID; with --root-id the guest would otherwise see its
# own files owned by a non-root UID. Build the helper on demand.
if [ "$REWRITE_UID" = 1 ]; then
    OCI_CHOWN="${SCRIPT_DIR}/../tools/oci-chown/oci-chown"
    if [ ! -x "$OCI_CHOWN" ]; then
        echo "Building tools/oci-chown..."
        ${MAKE:-make} -C "${SCRIPT_DIR}/../tools/oci-chown" > /dev/null \
            || die "tools/oci-chown build failed (need libext2fs-dev?)"
    fi
    echo "Rewriting inode uid/gid/mode from OCI manifest..."
    "$OCI_CHOWN" "$OUTFILE" "$OCI_MANIFEST"
    rm -f "$OCI_MANIFEST"
fi

echo "OK: ${OUTFILE} ($(du -h "$OUTFILE" | cut -f1))"
