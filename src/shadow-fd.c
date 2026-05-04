/* SPDX-License-Identifier: MIT */
/* shadow-fd.c - Create host-visible memfd shadows of LKL files.
 *
 * When the guest opens a regular file O_RDONLY, we create a memfd
 * containing the file's contents and inject it into the tracee.
 * This lets the host kernel handle mmap natively; critical for
 * dynamic linkers that mmap .so files with MAP_PRIVATE.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#include "lkl-wrap.h"
#include "seccomp.h"
#include "shadow-fd.h"

/* Read chunk size: 128 KB, matches KBOX_IO_CHUNK_LEN. */
#define SHADOW_CHUNK_LEN (128 * 1024)

static uint64_t current_shadow_limit = DEFAULT_SHADOW_LIMIT;

int kbox_shadow_create(const struct kbox_sysnrs *s, long lkl_fd)
{
    /* Use kbox_lkl_stat (generic-arch layout) instead of struct stat
     * (x86_64 layout).  LKL always fills the buffer in generic-arch
     * format regardless of the host architecture.
     */
    struct kbox_lkl_stat kst;
    long ret;

    memset(&kst, 0, sizeof(kst));
    ret = kbox_lkl_fstat(s, lkl_fd, &kst);
    if (ret < 0)
        return (int) ret;

    if (!S_ISREG(kst.st_mode))
        return -ENODEV;

    if ((uint64_t) kst.st_size > current_shadow_limit)
        return -EFBIG;

    int memfd = memfd_create("kbox-shadow", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memfd < 0)
        return -errno;

    if (ftruncate(memfd, (off_t) kst.st_size) < 0) {
        int e = errno;
        close(memfd);
        return -e;
    }

    if (kst.st_size == 0)
        return memfd;

    /* Read from LKL in chunks via pread64 (position-independent)
     * and write to the memfd.
     */
    long off = 0;
    long remaining = (long) kst.st_size;
    /* Static buffer: supervisor is single-threaded, no re-entrancy. */
    static char buf[SHADOW_CHUNK_LEN];

    while (remaining > 0) {
        long chunk = remaining;
        if (chunk > SHADOW_CHUNK_LEN)
            chunk = SHADOW_CHUNK_LEN;

        ret = kbox_lkl_pread64(s, lkl_fd, buf, chunk, off);
        if (ret < 0) {
            close(memfd);
            return (int) ret;
        }
        if (ret == 0) {
            close(memfd);
            return -EIO; /* EOF before expected size: truncated file */
        }

        long written = 0;
        while (written < ret) {
            ssize_t w = write(memfd, buf + written, (size_t) (ret - written));
            if (w < 0) {
                int e = errno;
                close(memfd);
                return -e;
            }
            written += w;
        }

        off += ret;
        remaining -= ret;
    }

    if (lseek(memfd, 0, SEEK_SET) < 0) {
        int e = errno;
        close(memfd);
        return -e;
    }

    return memfd;
}

int kbox_shadow_seal(int memfd)
{
    if (memfd < 0)
        return -1;
    return fcntl(memfd, F_ADD_SEALS,
                 F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
}

void kbox_shadow_set_limit(uint64_t limit)
{
    if (limit > MAX_SHADOW_LIMIT) {
        current_shadow_limit = MAX_SHADOW_LIMIT;
    } else if (limit > 0) {
        current_shadow_limit = limit;
    }
}