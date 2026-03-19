#!/usr/bin/env bash
# common.sh -- shared helpers for kbox scripts and git hooks.

set_colors() {
	if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null)" -ge 8 ] 2>/dev/null; then
		RED='\033[0;31m'
		GREEN='\033[0;32m'
		YELLOW='\033[0;33m'
		CYAN='\033[0;36m'
		NC='\033[0m'
	else
		RED=''
		GREEN=''
		YELLOW=''
		CYAN=''
		NC=''
	fi
}
