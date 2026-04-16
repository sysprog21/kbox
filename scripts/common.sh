#!/usr/bin/env bash

# shared helpers for kbox scripts and git hooks.
#
# All functions use portable shell (dash/ash/bash).  `local` is not
# strictly POSIX but is supported by every sh implementation we target.
# Source via:   . "$(cd "$(dirname "$0")" && pwd)/common.sh"

# --- Terminal colors ---
# Call set_colors before using RED/GREEN/YELLOW/NC etc.

set_colors()
{
    if [ -t 1 ]; then
        RED='\033[1;31m'
        GREEN='\033[1;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[1;34m'
        WHITE='\033[1;37m'
        CYAN='\033[1;36m'
        NC='\033[0m'
    else
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        WHITE=''
        CYAN=''
        NC=''
    fi
}

# --- Error handling ---

# Simple fatal error (no colors, works before set_colors).
die()
{
    echo "error: $*" >&2
    exit 1
}

# Formatted fatal error (uses RED/NC from set_colors).
throw()
{
    local fmt="$1"
    shift
    # shellcheck disable=SC2059
    printf "\n${RED}[!] ${fmt}${NC}\n" "$@" >&2
    exit 1
}

# --- CI detection ---

check_ci()
{
    if [ -n "${CI:-}" ] || [ -d "/home/runner/work" ]; then
        exit 0
    fi
}

# --- Architecture detection ---
# Sets ARCH to x86_64 or aarch64.  Accepts an optional override argument;
# defaults to the host architecture via uname -m.

detect_arch()
{
    case "${1:-$(uname -m)}" in
        x86_64 | amd64) ARCH="x86_64" ;;
        aarch64 | arm64) ARCH="aarch64" ;;
        riscv64) ARCH="riscv64" ;;
        *) die "unsupported architecture: ${1:-$(uname -m)}" ;;
    esac
}

# --- Download helpers ---
# download_file URL OUTPUT -- fetch URL to OUTPUT via curl or wget.

download_file()
{
    local url="$1"
    local output="$2"

    if command -v curl > /dev/null 2>&1; then
        curl -fSL -o "$output" "$url" || die "download failed: $url"
    elif command -v wget > /dev/null 2>&1; then
        wget -q -O "$output" "$url" || die "download failed: $url"
    else
        die "neither curl nor wget found"
    fi
}

# --- SHA256 verification ---
# verify_sha256 FILE SHA256_FILE [PATTERN]
# Looks up PATTERN (default: basename of FILE) in SHA256_FILE and
# verifies the hash.  Removes FILE on mismatch.  No-op if SHA256_FILE
# is missing or has no matching entry.

verify_sha256()
{
    local file="$1"
    local sha256_file="$2"
    local pattern="${3:-$(basename "$file")}"

    [ -f "$sha256_file" ] || return 0

    local expected
    expected=$(awk -v f="$pattern" '$2 == f { print $1 }' "$sha256_file")
    [ -n "$expected" ] || return 0

    local actual
    actual=$(sha256sum "$file" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        rm -f "$file"
        die "SHA256 mismatch for ${pattern}"
    fi
    echo "SHA256 verified."
}

# --- Timeout command detection ---
# Sets TIMEOUT_CMD to "timeout", "gtimeout", or "" (not available).

find_timeout_cmd()
{
    if command -v timeout > /dev/null 2>&1; then
        TIMEOUT_CMD="timeout"
    elif command -v gtimeout > /dev/null 2>&1; then
        TIMEOUT_CMD="gtimeout"
    else
        TIMEOUT_CMD=""
    fi
}
