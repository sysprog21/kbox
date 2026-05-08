/* SPDX-License-Identifier: MIT */
/* shadow-fd.c - Create host-visible memfd shadows of LKL files.
 *
 * When the guest opens a regular file O_RDONLY, we create a memfd
 * containing the file's contents and inject it into the tracee.
 * This lets the host kernel handle mmap natively; critical for
 * dynamic linkers that mmap .so files with MAP_PRIVATE.
 *
 * For read-only shadows, kbox_shadow_create_cached() reuses sealed
 * memfds across repeated opens of the same (inode, mtime, size)
 * tuple.  Hot files (ld-musl, libc.so ...) become a single dup()
 * instead of a full pread64 copy loop.
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

/* Array of KBOX_SHADOW_CACHE_MAX entries with an embedded LRU
 * doubly-linked list.
 */
struct shadow_cache_entry {
    int memfd; /* sealed read-only memfd, or -1 if free */
    uint64_t dev;
    uint64_t ino;
    int64_t mtime_sec;
    int64_t mtime_nsec;
    int64_t size;
    /* LRU list: lru_prev/lru_next are indices into cache.entries,
     * or -1 for list ends.  Free slots are not on the list.
     */
    int lru_prev;
    int lru_next;
};

static struct {
    struct shadow_cache_entry entries[KBOX_SHADOW_CACHE_MAX];
    int lru_head;  /* most recently used, -1 if empty */
    int lru_tail;  /* least recently used, -1 if empty */
    unsigned size; /* number of occupied slots */
    unsigned long hits;
    unsigned long misses;
    int initialised;
} cache;

static void cache_lazy_init(void)
{
    if (cache.initialised)
        return;
    for (int i = 0; i < KBOX_SHADOW_CACHE_MAX; i++) {
        cache.entries[i].memfd = -1;
        cache.entries[i].lru_prev = -1;
        cache.entries[i].lru_next = -1;
    }
    cache.lru_head = -1;
    cache.lru_tail = -1;
    cache.size = 0;
    cache.hits = 0;
    cache.misses = 0;
    cache.initialised = 1;
}

static void lru_unlink(int idx)
{
    struct shadow_cache_entry *e = &cache.entries[idx];
    if (e->lru_prev >= 0)
        cache.entries[e->lru_prev].lru_next = e->lru_next;
    else if (cache.lru_head == idx)
        cache.lru_head = e->lru_next;
    if (e->lru_next >= 0)
        cache.entries[e->lru_next].lru_prev = e->lru_prev;
    else if (cache.lru_tail == idx)
        cache.lru_tail = e->lru_prev;
    e->lru_prev = -1;
    e->lru_next = -1;
}

static void lru_push_front(int idx)
{
    struct shadow_cache_entry *e = &cache.entries[idx];
    e->lru_prev = -1;
    e->lru_next = cache.lru_head;
    if (cache.lru_head >= 0)
        cache.entries[cache.lru_head].lru_prev = idx;
    cache.lru_head = idx;
    if (cache.lru_tail < 0)
        cache.lru_tail = idx;
}

static void cache_evict_slot(int idx)
{
    struct shadow_cache_entry *e = &cache.entries[idx];
    if (e->memfd < 0)
        return;
    close(e->memfd);
    e->memfd = -1;
    lru_unlink(idx);
    cache.size--;
}

static int cache_lookup(uint64_t dev,
                        uint64_t ino,
                        int64_t mtime_sec,
                        int64_t mtime_nsec,
                        int64_t size)
{
    for (int i = 0; i < KBOX_SHADOW_CACHE_MAX; i++) {
        const struct shadow_cache_entry *e = &cache.entries[i];
        if (e->memfd < 0)
            continue;
        if (e->dev == dev && e->ino == ino && e->mtime_sec == mtime_sec &&
            e->mtime_nsec == mtime_nsec && e->size == size) {
            return i;
        }
    }
    return -1;
}

static int cache_find_free_slot(void)
{
    for (int i = 0; i < KBOX_SHADOW_CACHE_MAX; i++) {
        if (cache.entries[i].memfd < 0)
            return i;
    }
    return -1;
}

/* Insert (memfd, key) into cache and takes ownership of memfd. */
static int cache_insert(int memfd,
                        uint64_t dev,
                        uint64_t ino,
                        int64_t mtime_sec,
                        int64_t mtime_nsec,
                        int64_t size)
{
    int slot;

    /* If a stale entry for the same key still lingers (e.g. mtime
     * matched but content was replaced atomically with identical
     * stat), evict it first.
     */
    slot = cache_lookup(dev, ino, mtime_sec, mtime_nsec, size);
    if (slot >= 0)
        cache_evict_slot(slot);

    if (cache.size >= KBOX_SHADOW_CACHE_MAX) {
        if (cache.lru_tail < 0)
            return -1;
        cache_evict_slot(cache.lru_tail);
    }

    slot = cache_find_free_slot();
    if (slot < 0)
        return -1;

    struct shadow_cache_entry *e = &cache.entries[slot];
    e->memfd = memfd;
    e->dev = dev;
    e->ino = ino;
    e->mtime_sec = mtime_sec;
    e->mtime_nsec = mtime_nsec;
    e->size = size;
    lru_push_front(slot);
    cache.size++;
    return 0;
}

/* Evict any cached entry whose (dev, ino) matches but whose
 * (mtime, size) does not and called on cache miss for an in-use inode.
 */
static void cache_evict_stale(uint64_t dev,
                              uint64_t ino,
                              int64_t mtime_sec,
                              int64_t mtime_nsec,
                              int64_t size)
{
    for (int i = 0; i < KBOX_SHADOW_CACHE_MAX; i++) {
        struct shadow_cache_entry *e = &cache.entries[i];
        if (e->memfd < 0)
            continue;
        if (e->dev == dev && e->ino == ino &&
            (e->mtime_sec != mtime_sec || e->mtime_nsec != mtime_nsec ||
             e->size != size)) {
            cache_evict_slot(i);
        }
    }
}

void kbox_shadow_cache_reset(void)
{
    if (!cache.initialised)
        return;
    for (int i = 0; i < KBOX_SHADOW_CACHE_MAX; i++)
        cache_evict_slot(i);
    cache.lru_head = -1;
    cache.lru_tail = -1;
    cache.size = 0;
    cache.hits = 0;
    cache.misses = 0;
}


unsigned kbox_shadow_cache_size(void)
{
    return cache.size;
}
unsigned long kbox_shadow_cache_hits(void)
{
    return cache.hits;
}
unsigned long kbox_shadow_cache_misses(void)
{
    return cache.misses;
}


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

    if (kst.st_size > KBOX_SHADOW_MAX_SIZE)
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

int kbox_shadow_create_cached(const struct kbox_sysnrs *s, long lkl_fd)
{
    struct kbox_lkl_stat kst;
    long ret;

    cache_lazy_init();

    /* One fstat serves both the eligibility check and the cache key. */
    memset(&kst, 0, sizeof(kst));
    ret = kbox_lkl_fstat(s, lkl_fd, &kst);
    if (ret < 0)
        return (int) ret;

    if (!S_ISREG(kst.st_mode))
        return -ENODEV;
    if (kst.st_size > KBOX_SHADOW_MAX_SIZE)
        return -EFBIG;

    uint64_t dev = (uint64_t) kst.st_dev;
    uint64_t ino = (uint64_t) kst.st_ino;
    int64_t msec = (int64_t) kst.st_mtime_sec;
    int64_t mns = (int64_t) kst.st_mtime_nsec;
    int64_t sz = (int64_t) kst.st_size;

    /* Cache hit fast path. */
    int slot = cache_lookup(dev, ino, msec, mns, sz);
    if (slot >= 0) {
        int dup_fd = fcntl(cache.entries[slot].memfd, F_DUPFD_CLOEXEC, 0);
        if (dup_fd >= 0) {
            /* Promote to MRU. */
            lru_unlink(slot);
            lru_push_front(slot);
            cache.hits++;
            return dup_fd;
        }
        /* Fall through to miss path and keeping the cache entry
         * intact if dup failed. */
    }

    /* If cache miss. Evict any stale entry for this inode
     * before creating a new shadow. */
    cache_evict_stale(dev, ino, msec, mns, sz);
    cache.misses++;

    int memfd = kbox_shadow_create(s, lkl_fd);
    if (memfd < 0)
        return memfd;
    if (kbox_shadow_seal(memfd) < 0) {
        /* Sealing is required for safe sharing, if on failure,
         * return the unsealed fd and skip caching. */
        return memfd;
    }

    /* Hand out a dup so the caller's close() never affects the cache. */
    int dup_fd = fcntl(memfd, F_DUPFD_CLOEXEC, 0);
    if (dup_fd < 0) {
        /* Return the original fd uncached when dup failed. */
        return memfd;
    }

    if (cache_insert(memfd, dev, ino, msec, mns, sz) < 0) {
        /* Insertion failed: caller owns dup_fd, drop the original. */
        close(memfd);
    }
    return dup_fd;
}
