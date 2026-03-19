#!/bin/sh
# SPDX-License-Identifier: MIT
# Fetch prebuilt liblkl.a from the lkl-nightly release on sysprog21/kbox.
#
# Usage: ./scripts/fetch-lkl.sh [ARCH]
#   ARCH defaults to the host architecture (x86_64 or aarch64).
#   Override LKL_DIR to change output directory.
#
# Download order:
#   1. lkl-nightly release on sysprog21/kbox (curl, no auth)
#   2. GitHub CLI (gh) -- same release, authenticated
#   3. Manual instructions

set -eu

# Auto-detect architecture.
case "${1:-$(uname -m)}" in
x86_64 | amd64) ARCH="x86_64" ;;
aarch64 | arm64) ARCH="aarch64" ;;
*)
	echo "error: unsupported architecture: ${1:-$(uname -m)}" >&2
	exit 1
	;;
esac

LKL_DIR="${LKL_DIR:-lkl-${ARCH}}"
REPO="${KBOX_REPO:-sysprog21/kbox}"
NIGHTLY_TAG="${KBOX_LKL_TAG:-lkl-nightly}"
ASSET="liblkl-${ARCH}.tar.gz"
SHA256_FILE="scripts/lkl-sha256.txt"

die() {
	echo "error: $*" >&2
	exit 1
}

mkdir -p "$LKL_DIR"

# Already present?
if [ -f "${LKL_DIR}/liblkl.a" ]; then
	echo "OK: ${LKL_DIR}/liblkl.a (already exists)"
	exit 0
fi

# --- Method 1: GitHub Releases (curl, no auth) ---
try_release() {
	if ! command -v curl >/dev/null 2>&1; then
		return 1
	fi

	URL="https://github.com/${REPO}/releases/download/${NIGHTLY_TAG}/${ASSET}"
	echo "Downloading ${URL}..."
	curl -fSL -o "${LKL_DIR}/${ASSET}" "$URL" || return 1

	# Verify SHA256 if pinfile has an entry for this asset.
	if [ -f "$SHA256_FILE" ]; then
		EXPECTED=$(grep "$ASSET" "$SHA256_FILE" | awk '{print $1}')
		if [ -n "$EXPECTED" ]; then
			ACTUAL=$(sha256sum "${LKL_DIR}/${ASSET}" | awk '{print $1}')
			if [ "$ACTUAL" != "$EXPECTED" ]; then
				rm -f "${LKL_DIR}/${ASSET}"
				die "SHA256 mismatch for ${ASSET}"
			fi
			echo "SHA256 verified."
		fi
	fi

	tar xzf "${LKL_DIR}/${ASSET}" -C "$LKL_DIR"
	rm -f "${LKL_DIR}/${ASSET}"
	return 0
}

# --- Method 2: gh CLI ---
try_gh() {
	if ! command -v gh >/dev/null 2>&1; then
		return 1
	fi

	echo "Fetching ${ASSET} via gh CLI..."
	TMPDIR=$(mktemp -d)
	gh release download "$NIGHTLY_TAG" \
		--repo "$REPO" \
		--pattern "$ASSET" \
		--dir "$TMPDIR" 2>/dev/null || {
		rm -rf "$TMPDIR"
		return 1
	}

	tar xzf "${TMPDIR}/${ASSET}" -C "$LKL_DIR"
	rm -rf "$TMPDIR"
	return 0
}

# Try methods in order.
if try_release; then
	:
elif try_gh; then
	:
else
	cat >&2 <<EOF
Cannot fetch liblkl.a automatically.

Manual download:
  https://github.com/${REPO}/releases/tag/${NIGHTLY_TAG}
  Download ${ASSET}, then: tar xzf ${ASSET} -C ${LKL_DIR}/

Or build from source:
  git clone https://github.com/lkl/linux.git
  cd linux && make ARCH=lkl defconfig && make ARCH=lkl -j\$(nproc)
  cp tools/lkl/liblkl.a ${LKL_DIR}/

EOF
	exit 1
fi

if [ -f "${LKL_DIR}/liblkl.a" ]; then
	echo "OK: ${LKL_DIR}/liblkl.a"
else
	die "Download succeeded but liblkl.a not found in ${LKL_DIR}/"
fi
