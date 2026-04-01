/* SPDX-License-Identifier: MIT */

/* Path translation for the seccomp supervisor.
 *
 * Guest paths must be translated to LKL paths (image mode) or host paths (host
 * mode) before forwarding syscalls. Escape prevention ensures resolved paths
 * stay within the designated root.
 *
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "kbox/path.h"
#include "syscall-nr.h"

/* Check if path starts with prefix, with proper boundary handling. */
static bool starts_with(const char *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    return strncmp(path, prefix, plen) == 0;
}

/* Check if path equals prefix exactly or starts with prefix + '/'. */
static bool is_prefix_dir(const char *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) != 0)
        return false;
    return path[plen] == '\0' || path[plen] == '/';
}

static const char *component_end(const char *s)
{
    while (*s && *s != '/')
        s++;
    return s;
}

static bool proc_escape_tail(const char *tail)
{
    if (is_prefix_dir(tail, "root"))
        return true;
    if (is_prefix_dir(tail, "cwd"))
        return true;
    if (is_prefix_dir(tail, "exe"))
        return true;
    if (is_prefix_dir(tail, "fd"))
        return true;
    if (is_prefix_dir(tail, "fdinfo"))
        return true;
    if (is_prefix_dir(tail, "map_files"))
        return true;
    return false;
}

/* Check if the string at @s is composed entirely of decimal digits.
 * Returns true for non-empty all-digit strings (i.e., a numeric PID).
 */
static bool is_numeric(const char *s, size_t len)
{
    if (len == 0)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
    }
    return true;
}

/* Check if a /proc path uses a magic symlink that escapes the sandbox.
 *
 * The kernel exposes /proc/<pid>/root, /proc/<pid>/cwd, and /proc/<pid>/exe
 * as magic symlinks. "root" points to the process's filesystem root, "cwd" to
 * its working directory, and "exe" to the main executable. If the host kernel
 * resolves these via CONTINUE, the guest escapes the sandbox because symlink
 * target is on the host filesystem, not inside the LKL image.
 *
 * Patterns detected:
 *   /proc/self/root[/...]
 *   /proc/self/cwd[/...]
 *   /proc/self/exe[/...]
 *   /proc/<N>/root[/...]   (N = numeric PID)
 *   /proc/<N>/cwd[/...]
 *   /proc/<N>/exe[/...]
 */
bool kbox_is_proc_escape_path(const char *path)
{
    const char *p;

    /* Must start with /proc/ */
    if (!starts_with(path, "/proc/"))
        return false;
    p = path + 6; /* skip "/proc/" */

    /* Find the end of the pid/self component. */
    const char *slash = p;
    while (*slash && *slash != '/')
        slash++;

    size_t comp_len = (size_t) (slash - p);
    if (comp_len == 0)
        return false;

    /* Must be "self", "thread-self", or a numeric PID. */
    bool is_self = (comp_len == 4 && !memcmp(p, "self", 4));
    bool is_thread_self = (comp_len == 11 && !memcmp(p, "thread-self", 11));
    if (!is_self && !is_thread_self && !is_numeric(p, comp_len))
        return false;

    /* Must have a '/' after the pid/self/thread-self component. */
    if (*slash != '/')
        return false;
    const char *tail = slash + 1;

    /* Handle task/<tid>/ subdirectory: /proc/<pid>/task/<tid>/root
     * Each thread has its own magic symlinks under task/<tid>/.
     */
    if (starts_with(tail, "task/")) {
        const char *tid_start = tail + 5;
        const char *tid_end = tid_start;
        while (*tid_end && *tid_end != '/')
            tid_end++;
        size_t tid_len = (size_t) (tid_end - tid_start);
        if (tid_len == 0 || !is_numeric(tid_start, tid_len))
            return false;
        if (*tid_end != '/')
            return false;
        tail = tid_end + 1;
    }

    /* Check for dangerous symlink/directory names.
     *
     * root, cwd, exe: magic symlinks that resolve to host filesystem locations.
     * fd, fdinfo: per-FD symlinks that resolve to host file objects.
     * map_files: memory-mapping symlinks that resolve to host file paths.
     */
    return proc_escape_tail(tail);
}

bool kbox_is_lkl_virtual_path(const char *path)
{
    if (is_prefix_dir(path, "/proc")) {
        /* Reject /proc paths that escape via magic symlinks. */
        if (kbox_is_proc_escape_path(path))
            return false;
        return true;
    }
    return is_prefix_dir(path, "/sys") || is_prefix_dir(path, "/dev");
}

bool kbox_is_tty_like_path(const char *path)
{
    if (strcmp(path, "/dev/tty") == 0)
        return true;
    if (starts_with(path, "/dev/tty"))
        return true;
    if (starts_with(path, "/dev/pts/"))
        return true;
    if (strcmp(path, "/dev/console") == 0)
        return true;
    return false;
}

bool kbox_is_loader_runtime_path(const char *path)
{
    if (strcmp(path, "/etc/ld.so.cache") == 0)
        return true;
    if (strcmp(path, "/etc/ld.so.preload") == 0)
        return true;
    if (starts_with(path, "/lib/"))
        return true;
    if (starts_with(path, "/lib64/"))
        return true;
    if (starts_with(path, "/usr/lib/"))
        return true;
    if (starts_with(path, "/usr/lib64/"))
        return true;
    return false;
}

bool kbox_relative_path_has_dotdot(const char *path)
{
    if (!path)
        return false;

    while (*path) {
        if (path[0] == '.' && path[1] == '.' &&
            (path[2] == '/' || path[2] == '\0'))
            return true;
        while (*path && *path != '/')
            path++;
        while (*path == '/')
            path++;
    }
    return false;
}

bool kbox_relative_proc_escape_path(const char *path)
{
    char probe[KBOX_MAX_PATH];
    const char *tail;
    const char *tid_end;
    size_t task_len;
    int n;

    if (!path || path[0] == '\0')
        return false;

    /* From a /proc dirfd, "self/root/..." and similar are already enough. */
    n = snprintf(probe, sizeof(probe), "/proc/%s", path);
    if (n > 0 && (size_t) n < sizeof(probe) && kbox_is_proc_escape_path(probe))
        return true;

    /* From /proc/self, /proc/thread-self, or /proc/<pid>, look for direct
     * magic entries like "root" plus task/<tid>/root escapes.
     */
    if (proc_escape_tail(path))
        return true;

    if (!starts_with(path, "task/"))
        return false;
    tail = path + 5;
    tid_end = component_end(tail);
    task_len = (size_t) (tid_end - tail);
    if (task_len == 0 || !is_numeric(tail, task_len) || *tid_end != '/')
        return false;
    return proc_escape_tail(tid_end + 1);
}

/* Lexical path normalization.
 *
 * Processes each component of input:
 *   "."   -> skip
 *   ".."  -> pop last component (don't go above root)
 *   other -> append
 *
 * If input is absolute, base is ignored and we start from "/".
 * Result is always absolute and written to out.
 */
int kbox_normalize_join(const char *base,
                        const char *input,
                        char *out,
                        size_t out_size)
{
    char work[KBOX_MAX_PATH];
    size_t wlen;
    const char *p;

    if (out_size == 0)
        return -1;

    /* Start with base or "/" depending on whether input is absolute. */
    if (input[0] == '/') {
        work[0] = '/';
        work[1] = '\0';
        wlen = 1;
    } else {
        size_t blen = strlen(base);
        if (blen == 0 || blen >= sizeof(work))
            return -1;
        memcpy(work, base, blen);
        work[blen] = '\0';
        wlen = blen;
    }

    p = input;
    while (*p) {
        const char *seg;
        size_t slen;

        /* Skip leading slashes. */
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        /* Find end of this component. */
        seg = p;
        while (*p && *p != '/')
            p++;
        slen = (size_t) (p - seg);

        if (slen == 1 && seg[0] == '.') {
            /* Current directory: skip. */
            continue;
        }

        if (slen == 2 && seg[0] == '.' && seg[1] == '.') {
            /* Parent directory: pop the last component.
             * Never go above root (wlen stays >= 1 for "/").
             */
            if (wlen > 1) {
                /* Remove trailing slash if present. */
                if (work[wlen - 1] == '/')
                    wlen--;
                /* Walk back to the previous '/'. */
                while (wlen > 1 && work[wlen - 1] != '/')
                    wlen--;
                /* Keep at least "/". */
                if (wlen == 0)
                    wlen = 1;
                work[wlen] = '\0';
            }
            continue;
        }

        /* Normal component: append "/component". */
        if (work[wlen - 1] != '/') {
            if (wlen + 1 >= sizeof(work))
                return -1;
            work[wlen++] = '/';
        }
        if (wlen + slen >= sizeof(work))
            return -1;
        memcpy(work + wlen, seg, slen);
        wlen += slen;
        work[wlen] = '\0';
    }

    /* Ensure we have at least "/". */
    if (wlen == 0) {
        work[0] = '/';
        work[1] = '\0';
        wlen = 1;
    }

    if (wlen + 1 > out_size)
        return -1;
    memcpy(out, work, wlen + 1);
    return 0;
}

int kbox_normalize_virtual_relative(const char *path,
                                    char *out,
                                    size_t out_size)
{
    const char *rest = path;
    const char *prefix;

    /* Strip optional "./" prefix. */
    if (rest[0] == '.' && rest[1] == '/')
        rest += 2;

    if (strcmp(rest, "proc") == 0) {
        prefix = "/proc";
        rest = NULL;
    } else if (strncmp(rest, "proc/", 5) == 0) {
        prefix = "/proc";
        rest += 5;
    } else if (strcmp(rest, "sys") == 0) {
        prefix = "/sys";
        rest = NULL;
    } else if (strncmp(rest, "sys/", 4) == 0) {
        prefix = "/sys";
        rest += 4;
    } else if (strcmp(rest, "dev") == 0) {
        prefix = "/dev";
        rest = NULL;
    } else if (strncmp(rest, "dev/", 4) == 0) {
        prefix = "/dev";
        rest += 4;
    } else {
        return 0; /* not a virtual relative path */
    }

    if (rest && *rest) {
        if (snprintf(out, out_size, "%s/%s", prefix, rest) >= (int) out_size)
            return -1;
    } else {
        if (snprintf(out, out_size, "%s", prefix) >= (int) out_size)
            return -1;
    }
    return 1;
}

static int kbox_read_proc_cwd(pid_t pid, char *out, size_t out_size)
{
    char link[64];
    ssize_t n;

    if (out_size == 0)
        return -EINVAL;

    snprintf(link, sizeof(link), "/proc/%d/cwd", (int) pid);
    n = readlink(link, out, out_size - 1);
    if (n < 0)
        return -errno;
    if ((size_t) n >= out_size - 1)
        return -ENAMETOOLONG;
    out[n] = '\0';
    return 0;
}

/* Translate a guest path for LKL syscalls (image mode).
 *
 * Virtual paths (/proc, /sys, /dev) pass through. Relative virtual paths
 * (proc/..., sys/..., dev/...) are normalized. Everything else passes
 * through because image mode has already chroot'd into the mount.
 */
int kbox_translate_path_for_lkl(pid_t pid,
                                const char *path,
                                const char *host_root,
                                char *out,
                                size_t out_size)
{
    /* Normalize absolute paths before the virtual-prefix check to prevent
     * escape via paths like /proc/../etc/passwd. Without normalization, the
     * prefix test sees "/proc" and returns CONTINUE, letting the host kernel
     * resolve ".." and reach outside /proc.
     */
    char norm[KBOX_MAX_PATH];
    const char *effective = path;

    if (path[0] == '/') {
        if (kbox_normalize_join("/", path, norm, sizeof(norm)) == 0)
            effective = norm;
    }

    if (kbox_is_lkl_virtual_path(effective)) {
        if (strlen(effective) >= out_size)
            return -ENAMETOOLONG;
        memcpy(out, effective, strlen(effective) + 1);
        return 0;
    }

    /* Relative virtual paths (e.g., "proc/self/status") get converted to
     * absolute form ("/proc/self/status"). However, we must verify the result
     * is still virtual after normalization to prevent escape via
     * "proc/../etc/passwd" -> "/proc/../etc/passwd" -> "/etc/passwd".
     */
    int vrel = kbox_normalize_virtual_relative(path, out, out_size);
    if (vrel < 0)
        return -ENAMETOOLONG;
    if (vrel > 0) {
        char virt_norm[KBOX_MAX_PATH];
        if (kbox_normalize_join("/", out, virt_norm, sizeof(virt_norm)) == 0 &&
            kbox_is_lkl_virtual_path(virt_norm)) {
            if (strlen(virt_norm) >= out_size)
                return -ENAMETOOLONG;
            memcpy(out, virt_norm, strlen(virt_norm) + 1);
            return 0;
        }
        /* Normalized result escapes virtual prefix; fall through. */
    }

    /* No host_root means pure image mode: path passes through unchanged because
     * we are already inside the LKL mount.
     */
    if (!host_root) {
        if (strlen(path) >= out_size)
            return -ENAMETOOLONG;
        memcpy(out, path, strlen(path) + 1);
        return 0;
    }

    /* Host root is set: resolve relative to root and verify we don't escape.
     * Absolute paths are re-rooted under host_root; relative paths resolve
     * against the tracee's cwd.
     */
    if (path[0] == '/') {
        /* Re-root: join host_root + path (skip leading '/') */
        if (kbox_normalize_join(host_root, path + 1, out, out_size) < 0)
            return -ENAMETOOLONG;
    } else {
        char cwd[KBOX_MAX_PATH];
        int rc = kbox_read_proc_cwd(pid, cwd, sizeof(cwd));
        if (rc < 0)
            return rc;
        if (kbox_normalize_join(cwd, path, out, out_size) < 0)
            return -ENAMETOOLONG;
    }

    /* Verify the resolved path stays within host_root. */
    if (!is_prefix_dir(out, host_root) && strcmp(out, host_root) != 0)
        return -EPERM;

    /* Convert the host-side resolved path to a guest-relative path.
     * Strip host_root prefix to get the path as seen inside the mount.
     */
    {
        size_t rlen = strlen(host_root);
        const char *tail = out + rlen;
        char tmp[KBOX_MAX_PATH];

        if (*tail == '\0') {
            /* Path equals host_root exactly -> "/" */
            out[0] = '/';
            out[1] = '\0';
        } else if (*tail == '/') {
            size_t tlen = strlen(tail);
            if (tlen >= out_size)
                return -ENAMETOOLONG;
            memcpy(tmp, tail, tlen + 1);
            memcpy(out, tmp, tlen + 1);
        } else {
            /* Shouldn't happen because is_prefix_dir already checked, but be
             * safe.
             */
            return -EPERM;
        }
    }

    return 0;
}
