/* SPDX-License-Identifier: MIT */
/* Stubs for LKL functions referenced by mount.c but not exercised
 * in the unit tests (only kbox_parse_bind_spec is tested).
 */

#include <errno.h>

#include "lkl-wrap.h"
#include "syscall-nr.h"

long kbox_lkl_mkdir(const struct kbox_sysnrs *s, const char *path, int mode)
{
    (void) s;
    (void) path;
    (void) mode;
    return -ENOSYS;
}

long kbox_lkl_mount(const struct kbox_sysnrs *s,
                    const char *src,
                    const char *target,
                    const char *fstype,
                    long flags,
                    const void *data)
{
    (void) s;
    (void) src;
    (void) target;
    (void) fstype;
    (void) flags;
    (void) data;
    return -ENOSYS;
}

long kbox_lkl_openat(const struct kbox_sysnrs *s,
                     long dirfd,
                     const char *path,
                     long flags,
                     long mode)
{
    (void) s;
    (void) dirfd;
    (void) path;
    (void) flags;
    (void) mode;
    return -ENOSYS;
}

long kbox_lkl_close(const struct kbox_sysnrs *s, long fd)
{
    (void) s;
    (void) fd;
    return 0;
}

long kbox_lkl_newfstatat(const struct kbox_sysnrs *s,
                         long dirfd,
                         const char *path,
                         void *buf,
                         long flags)
{
    (void) s;
    (void) dirfd;
    (void) path;
    (void) buf;
    (void) flags;
    return -ENOSYS;
}

const char *kbox_err_text(long code)
{
    (void) code;
    return "stub";
}
