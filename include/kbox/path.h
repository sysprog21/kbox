/* SPDX-License-Identifier: MIT */

#ifndef KBOX_PATH_H
#define KBOX_PATH_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* Path translation for the seccomp supervisor.
 *
 * Guest paths are translated to LKL paths (image mode) before forwarding
 * syscalls.
 *
 * Escape prevention: resolved paths must stay within the designated root.
 * Attempts to traverse above the root via ".." are blocked.
 */

#define KBOX_MAX_PATH 4096

/* Check if path refers to an LKL virtual filesystem (/proc, /sys, /dev). */
bool kbox_is_lkl_virtual_path(const char *path);

/* Check if path uses a /proc magic symlink that escapes the sandbox.
 *
 * Detects /proc/self/{root,cwd,exe} and /proc/<PID>/{root,cwd,exe} which are
 * kernel-internal symlinks pointing outside the guest root. These must NOT be
 * dispatched via CONTINUE to the host kernel.
 *
 * Returns true if the path is a proc escape path.
 */
bool kbox_is_proc_escape_path(const char *path);

/* Check if path is a TTY-like device. */
bool kbox_is_tty_like_path(const char *path);

/* Check if path is a loader/runtime path (ld.so.cache, /lib, etc.). */
bool kbox_is_loader_runtime_path(const char *path);

/* Check whether a relative path contains ".." as a standalone component. */
bool kbox_relative_path_has_dotdot(const char *path);

/* Check if a relative lookup under a /proc-based host dirfd would resolve
 * through a magic proc escape entry.
 *
 * This covers lookups rooted at /proc, /proc/self, /proc/thread-self, or
 * /proc/<pid>, including task/<tid>/... relative paths under per-thread views.
 */
bool kbox_relative_proc_escape_path(const char *path);

/* Normalize path relative to base, resolving . and .. lexically.
 * If @input is absolute, @base is ignored. Result is written to @out (must be
 * KBOX_MAX_PATH bytes).
 * Returns 0 on success, -1 on overflow.
 */
int kbox_normalize_join(const char *base,
                        const char *input,
                        char *out,
                        size_t out_size);

/* Translate a guest path for LKL syscalls (image mode).
 * - Virtual paths (/proc, /sys, /dev) pass through unchanged.
 * - Relative paths starting with proc/, sys/, dev/ are normalized.
 * - Other paths pass through (image mode has chroot'd into the mount).
 *
 * Returns 0 on success, -errno on error.
 * @out must be KBOX_MAX_PATH bytes.
 */
int kbox_translate_path_for_lkl(pid_t pid,
                                const char *path,
                                const char *host_root,
                                char *out,
                                size_t out_size);

/* Normalize a relative virtual path (e.g., "proc/self/status" ->
 * "/proc/self/status").
 *
 * Returns 1 if normalized, 0 if not a virtual relative path.
 */
int kbox_normalize_virtual_relative(const char *path,
                                    char *out,
                                    size_t out_size);

#endif /* KBOX_PATH_H */
