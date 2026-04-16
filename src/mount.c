/* SPDX-License-Identifier: MIT */

/* Filesystem mount helpers for the LKL guest.
 *
 * Sets up the recommended virtual filesystems (proc, sysfs, devtmpfs, devpts,
 * tmpfs) and applies user-specified bind mounts. All operations go through LKL
 * syscall wrappers; nothing touches the host kernel.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "kbox/mount.h"
#include "lkl-wrap.h"
#include "syscall-nr.h"

/* MS_BIND from <linux/mount.h> without pulling the full header. */
#define KBOX_MS_BIND 0x1000

/* asm-generic O_* values for LKL openat (same on x86_64 and aarch64). */
#define LKL_O_CREAT 0100
#define LKL_O_EXCL 0200

/* Bind-mount spec parser. */

int kbox_parse_bind_spec(const char *spec, struct kbox_bind_spec *out)
{
    const char *colon;
    size_t src_len, dst_len;

    if (!spec || !out) {
        fprintf(stderr, "kbox_parse_bind_spec: NULL argument\n");
        return -1;
    }

    colon = strchr(spec, ':');
    if (!colon) {
        fprintf(stderr, "bind spec missing ':': %s\n", spec);
        return -1;
    }

    src_len = (size_t) (colon - spec);
    dst_len = strlen(colon + 1);

    if (src_len == 0 || dst_len == 0) {
        fprintf(stderr, "bind spec has empty component: %s\n", spec);
        return -1;
    }
    if (src_len >= sizeof(out->source)) {
        fprintf(stderr, "bind spec source too long: %s\n", spec);
        return -1;
    }
    if (dst_len >= sizeof(out->target)) {
        fprintf(stderr, "bind spec target too long: %s\n", spec);
        return -1;
    }

    memcpy(out->source, spec, src_len);
    out->source[src_len] = '\0';

    memcpy(out->target, colon + 1, dst_len);
    out->target[dst_len] = '\0';

    return 0;
}

/* Internal: mkdir + mount, tolerating EEXIST on mkdir. */

static int do_mkdir_mount(const struct kbox_sysnrs *s,
                          const char *target,
                          const char *fstype,
                          const char *source)
{
    long ret;

    ret = kbox_lkl_mkdir(s, target, 0755);
    if (ret < 0 && ret != -EEXIST) {
        fprintf(stderr, "mkdir(%s): %s\n", target, kbox_err_text(ret));
        return -1;
    }

    ret = kbox_lkl_mount(s, source, target, fstype, 0, NULL);
    if (ret < 0) {
        fprintf(stderr, "mount(%s on %s): %s\n", fstype, target,
                kbox_err_text(ret));
        return -1;
    }

    return 0;
}

/* Recommended mounts. */

int kbox_apply_recommended_mounts(const struct kbox_sysnrs *s,
                                  enum kbox_mount_profile profile)
{
    /* proc is always mounted; needed for /proc/self/fd, /proc/sys */
    if (do_mkdir_mount(s, "/proc", "proc", "proc") < 0)
        return -1;

    if (profile == KBOX_MOUNT_FULL) {
        if (do_mkdir_mount(s, "/sys", "sysfs", "sysfs") < 0)
            return -1;

        /* devtmpfs and devpts require CONFIG_DEVTMPFS / CONFIG_DEVPTS_FS
         * in the LKL kernel. Warn on failure instead of aborting; the guest
         * can operate without them.
         */
        if (do_mkdir_mount(s, "/dev", "devtmpfs", "devtmpfs") < 0)
            fprintf(stderr,
                    "warning: devtmpfs unavailable (CONFIG_DEVTMPFS?)\n");

        if (do_mkdir_mount(s, "/dev/pts", "devpts", "devpts") < 0)
            fprintf(stderr,
                    "warning: devpts unavailable (CONFIG_DEVPTS_FS?)\n");
    }

    /* tmpfs on /tmp is always useful */
    if (do_mkdir_mount(s, "/tmp", "tmpfs", "tmpfs") < 0)
        return -1;

    return 0;
}

/* Bind mounts.
 *
 * The source is a host path; stat it to determine whether the bind-mount
 * target inside LKL should be a directory or a regular file. Anything
 * other than a regular file or directory is rejected up front.
 */

/* Verify that the existing inode at target has the expected type. */
static int verify_existing_target(const struct kbox_sysnrs *s,
                                  const char *target,
                                  unsigned int expected_mode_type)
{
    struct kbox_lkl_stat lkl_st;
    long ret;

    ret = kbox_lkl_newfstatat(s, AT_FDCWD_LINUX, target, &lkl_st, 0);
    if (ret < 0) {
        fprintf(stderr, "stat(%s): %s\n", target, kbox_err_text(ret));
        return -1;
    }
    if ((lkl_st.st_mode & S_IFMT) != expected_mode_type) {
        fprintf(stderr,
                "bind mount: target %s exists but has wrong type "
                "(expected 0%o, got 0%o)\n",
                target, expected_mode_type, lkl_st.st_mode & S_IFMT);
        return -1;
    }
    return 0;
}

static int create_bind_target(const struct kbox_sysnrs *s,
                              const char *source,
                              const char *target)
{
    struct stat st;
    long ret;

    if (lstat(source, &st) < 0) {
        fprintf(stderr, "bind mount: cannot stat source %s: %s\n", source,
                strerror(errno));
        return -1;
    }

    if (S_ISLNK(st.st_mode)) {
        fprintf(stderr, "bind mount: source %s must not be a symlink\n",
                source);
        return -1;
    }

    if (S_ISDIR(st.st_mode)) {
        ret = kbox_lkl_mkdir(s, target, 0755);
        if (ret == -EEXIST)
            return verify_existing_target(s, target, S_IFDIR);
        if (ret < 0) {
            fprintf(stderr, "mkdir(%s): %s\n", target, kbox_err_text(ret));
            return -1;
        }
        return 0;
    }

    if (S_ISREG(st.st_mode)) {
        long cret;

        ret = kbox_lkl_openat(s, AT_FDCWD_LINUX, target,
                              LKL_O_CREAT | LKL_O_EXCL, 0644);
        if (ret == -EEXIST)
            return verify_existing_target(s, target, S_IFREG);
        if (ret < 0) {
            fprintf(stderr, "creat(%s): %s\n", target, kbox_err_text(ret));
            return -1;
        }
        cret = kbox_lkl_close(s, ret);
        if (cret < 0) {
            fprintf(stderr, "close(%s): %s\n", target, kbox_err_text(cret));
            return -1;
        }
        return 0;
    }

    fprintf(stderr,
            "bind mount: source %s is neither a regular file nor a directory\n",
            source);
    return -1;
}

int kbox_apply_bind_mounts(const struct kbox_sysnrs *s,
                           const struct kbox_bind_spec *specs,
                           int count)
{
    int i;
    long ret;

    if (!s || (!specs && count > 0) || count < 0)
        return -1;

    for (i = 0; i < count; i++) {
        if (create_bind_target(s, specs[i].source, specs[i].target) < 0)
            return -1;

        ret = kbox_lkl_mount(s, specs[i].source, specs[i].target, NULL,
                             KBOX_MS_BIND, NULL);
        if (ret < 0) {
            fprintf(stderr, "bind mount %s -> %s: %s\n", specs[i].source,
                    specs[i].target, kbox_err_text(ret));
            return -1;
        }
    }

    return 0;
}
