#!/bin/sh
# SPDX-License-Identifier: MIT
# Build liblkl.a from source (lkl/linux) and populate lkl-<ARCH>/.
#
# Usage: ./scripts/build-lkl.sh [ARCH]
#   ARCH defaults to the host architecture (x86_64 or aarch64).
#   Override LKL_DIR   to change the output directory.
#   Override LKL_SRC   to reuse an existing source tree (skip clone).
#   Override LKL_REF   to check out a specific branch/tag/commit
#                      (default: HEAD of master).

set -eu

. "$(cd "$(dirname "$0")" && pwd)/common.sh"

detect_arch "${1:-}"

LKL_DIR="${LKL_DIR:-lkl-${ARCH}}"
LKL_SRC="${LKL_SRC:-build/lkl-src}"
LKL_UPSTREAM="https://github.com/lkl/linux"

is_commit_sha()
{
    case "$1" in
        [0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]*)
            case "$1" in
                *[!0-9a-fA-F]*)
                    return 1
                    ;;
            esac
            return 0
            ;;
    esac

    return 1
}

checkout_lkl_ref()
{
    ref="$1"

    echo "  CHECKOUT ${ref}"
    if is_commit_sha "$ref"; then
        # Bare commit SHAs are not advertised as remote refs, so a shallow
        # ref fetch is not reliable. Ensure full history before checkout.
        if git -C "${LKL_SRC}" rev-parse --is-shallow-repository > /dev/null 2>&1 \
            && [ "$(git -C "${LKL_SRC}" rev-parse --is-shallow-repository)" = "true" ]; then
            git -C "${LKL_SRC}" fetch --unshallow origin
        else
            git -C "${LKL_SRC}" fetch origin
        fi
        git -C "${LKL_SRC}" checkout "${ref}"
    else
        git -C "${LKL_SRC}" fetch --depth=1 origin "${ref}"
        git -C "${LKL_SRC}" checkout FETCH_HEAD
    fi
}

# ---- Clone or update source tree ----------------------------------------

if [ -d "${LKL_SRC}/.git" ]; then
    echo "  SRC     ${LKL_SRC} (exists, skipping clone)"
    if [ -n "${LKL_REF:-}" ]; then
        checkout_lkl_ref "${LKL_REF}"
    fi
else
    echo "  CLONE   ${LKL_UPSTREAM} -> ${LKL_SRC}"
    mkdir -p "$(dirname "${LKL_SRC}")"

    if [ -n "${LKL_REF:-}" ] && is_commit_sha "${LKL_REF}"; then
        # Commit SHAs require full history because remotes typically do not
        # advertise arbitrary object IDs as shallow-fetchable refs.
        git clone "${LKL_UPSTREAM}" "${LKL_SRC}"
        checkout_lkl_ref "${LKL_REF}"
    else
        # Shallow clone of default branch, then checkout specific branch/tag if
        # requested. git clone --branch does not accept bare commit SHAs.
        git clone --depth=1 "${LKL_UPSTREAM}" "${LKL_SRC}"
        if [ -n "${LKL_REF:-}" ]; then
            checkout_lkl_ref "${LKL_REF}"
        fi
    fi
fi

# ---- Configure -----------------------------------------------------------

if [ ! -f "${LKL_SRC}/.config" ]; then
    echo "  CONFIG  ARCH=lkl defconfig"
    make -C "${LKL_SRC}" ARCH=lkl defconfig

    # Enable features required by kbox (mirrors build-lkl.yml).
    for opt in \
        CONFIG_DEVTMPFS \
        CONFIG_DEVTMPFS_MOUNT \
        CONFIG_DEVPTS_FS \
        CONFIG_DEBUG_INFO \
        CONFIG_GDB_SCRIPTS \
        CONFIG_SCHED_DEBUG \
        CONFIG_PROC_SYSCTL \
        CONFIG_PRINTK \
        CONFIG_TRACEPOINTS \
        CONFIG_FTRACE \
        CONFIG_DEBUG_FS; do
        "${LKL_SRC}/scripts/config" --file "${LKL_SRC}/.config" --enable "${opt}"
    done

    "${LKL_SRC}/scripts/config" --file "${LKL_SRC}/.config" \
        --set-val CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT y

    for opt in \
        CONFIG_MODULES \
        CONFIG_SOUND \
        CONFIG_USB_SUPPORT \
        CONFIG_INPUT \
        CONFIG_NFS_FS \
        CONFIG_CIFS; do
        "${LKL_SRC}/scripts/config" --file "${LKL_SRC}/.config" --disable "${opt}"
    done

    make -C "${LKL_SRC}" ARCH=lkl olddefconfig
fi

# ---- Build ---------------------------------------------------------------

NPROC=$(nproc 2> /dev/null || echo 1)

echo "  BUILD   ARCH=lkl kernel (-j${NPROC})"
make -C "${LKL_SRC}" ARCH=lkl -j"${NPROC}"

echo "  BUILD   tools/lkl (-j${NPROC})"
make -C "${LKL_SRC}/tools/lkl" -j"${NPROC}"

# ---- Verify --------------------------------------------------------------

test -f "${LKL_SRC}/tools/lkl/liblkl.a" \
    || die "build succeeded but liblkl.a not found"

echo "  VERIFY  symbols"
for sym in lkl_init lkl_start_kernel lkl_cleanup lkl_syscall \
    lkl_strerror lkl_disk_add lkl_mount_dev \
    lkl_host_ops lkl_dev_blk_ops; do
    if ! nm "${LKL_SRC}/tools/lkl/liblkl.a" 2> /dev/null \
        | awk -v s="$sym" '$3==s && $2~/^[TtDdBbRr]$/{found=1} END{exit !found}'; then
        die "MISSING symbol: ${sym}"
    fi
done

# ---- Install into lkl-<ARCH>/ -------------------------------------------

echo "  INSTALL ${LKL_DIR}/"
mkdir -p "${LKL_DIR}"

cp "${LKL_SRC}/tools/lkl/liblkl.a" "${LKL_DIR}/"
cp "${LKL_SRC}/tools/lkl/include/lkl.h" "${LKL_DIR}/" 2> /dev/null || true
cp "${LKL_SRC}/tools/lkl/include/lkl/autoconf.h" "${LKL_DIR}/" 2> /dev/null || true
cp "${LKL_SRC}/scripts/gdb/vmlinux-gdb.py" "${LKL_DIR}/" 2> /dev/null || true

printf 'commit=%s\ndate=%s\narch=%s\n' \
    "$(git -C "${LKL_SRC}" rev-parse HEAD)" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${ARCH}" \
    > "${LKL_DIR}/BUILD_INFO"

(cd "${LKL_DIR}" && sha256sum ./* > sha256sums.txt)

echo "OK: ${LKL_DIR}/liblkl.a"
