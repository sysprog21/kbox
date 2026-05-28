/* SPDX-License-Identifier: MIT */

/* Virtual FD table mapping guest FDs to LKL FDs.
 *
 * Three backing stores:
 *   - entries[]:  FDs in [KBOX_FD_BASE, KBOX_FD_BASE + KBOX_FD_TABLE_MAX)
 *   - low_fds[]:  FDs in [0, KBOX_LOW_FD_MAX); populated only by dup2/dup3
 *   - mid_fds[]:  real host FDs in [KBOX_LOW_FD_MAX, KBOX_FD_BASE)
 *
 * A slot is free when lkl_fd == -1.  All lookups go through fd_lookup() which
 * handles all ranges in O(1).
 */

#include <unistd.h>

#include "fd-table.h"
#include "lkl-wrap.h"

/* Unified entry lookup.
 * Returns a pointer to the kbox_fd_entry for the given FD, or NULL if the FD
 * is in neither range.
 */
static struct kbox_fd_entry *fd_lookup(const struct kbox_fd_table *t, long fd)
{
    if (fd >= 0 && fd < KBOX_LOW_FD_MAX)
        return (struct kbox_fd_entry *) &t->low_fds[fd];
    if (fd >= KBOX_LOW_FD_MAX && fd < KBOX_FD_BASE)
        return (struct kbox_fd_entry *) &t->mid_fds[fd - KBOX_LOW_FD_MAX];
    if (fd >= KBOX_FD_BASE && fd < KBOX_FD_BASE + KBOX_FD_TABLE_MAX)
        return (struct kbox_fd_entry *) &t->entries[fd - KBOX_FD_BASE];
    return NULL;
}

/* Reset a slot to its "free" state: lkl_fd == -1 acts as the free
 * sentinel for fd_lookup() callers, and every other field is cleared
 * so that a later insert starts from a known-zero baseline.
 */
static inline void clear_fd_entry(struct kbox_fd_entry *e)
{
    e->lkl_fd = -1;
    e->host_fd = -1;
    e->shadow_sp = -1;
    e->shadow_writeback = 0;
    e->mirror_tty = 0;
    e->cloexec = 0;
}

/* Populate an already-free slot with a fresh lkl_fd. All other fields
 * are reset to their default "no shadow / no host_fd / no cloexec"
 * state so callers never inherit stale bookkeeping from a previous
 * occupant. The caller is responsible for bumping the lkl_fd refcount.
 */
static inline void init_live_entry(struct kbox_fd_entry *e,
                                   long lkl_fd,
                                   int mirror_tty)
{
    e->lkl_fd = lkl_fd;
    e->host_fd = -1;
    e->shadow_sp = -1;
    e->shadow_writeback = 0;
    e->mirror_tty = mirror_tty;
    e->cloexec = 0;
}

/* Reverse-map and refcount maintenance helpers.
 *
 * The reverse map (host_to_vfd) gives O(1) find_by_host_fd. Each slot
 * holds one of:
 *   -1  (KBOX_HOST_VFD_NONE):  no entry currently has this host_fd.
 *   -2  (KBOX_HOST_VFD_MULTI): two or more entries share this host_fd;
 *                              exact holders unknown, fall through to
 *                              the linear scan.
 *   >=0:                       the unique vfd currently holding this
 *                              host_fd.
 *
 * Invariant: host_to_vfd[h] == KBOX_HOST_VFD_NONE implies no live
 * entry in any of the three ranges has host_fd == h. This lets
 * find_by_host_fd return -1 in O(1) without scanning (authoritative
 * miss), which is the common case for close() of a host fd that
 * isn't tracked in the fd_table at all (e.g. cached-shadow opens
 * that inject an ADDFD without ever creating an fd_table entry).
 *
 * Duplicate holders arise only from dup2/dup3-style operations; they
 * are rare and tracked with the MULTI sentinel so the common single-
 * or no-holder paths stay O(1). A MULTI slot is never downgraded back
 * to a single-holder value; it stays MULTI until the last duplicate
 * closes, at which point find_by_host_fd's slow-path scan leaves
 * matches to subsequent lookups or to a future set that overwrites
 * it.
 *
 * The lkl_fd refcount covers all three storage ranges. It lets
 * close-path callers replace their O(n) sibling scans with an O(1)
 * comparison.
 */
#define KBOX_HOST_VFD_NONE ((int32_t) -1)
#define KBOX_HOST_VFD_MULTI ((int32_t) -2)

static inline void rev_host_set(struct kbox_fd_table *t, long host_fd, long vfd)
{
    int32_t cur;

    if (host_fd < 0 || (uint64_t) host_fd >= KBOX_HOST_FD_REVERSE_MAX)
        return;

    t->host_fd_refs[host_fd]++;
    cur = t->host_to_vfd[host_fd];
    if (cur == KBOX_HOST_VFD_NONE || cur == (int32_t) vfd) {
        t->host_to_vfd[host_fd] = (int32_t) vfd;
        return;
    }
    /* A different vfd already claims this host_fd, OR the slot is
     * already MULTI. Either way we now have two or more holders.
     */
    t->host_to_vfd[host_fd] = KBOX_HOST_VFD_MULTI;
}

static inline void rev_host_clear(struct kbox_fd_table *t,
                                  long host_fd,
                                  long vfd)
{
    if (host_fd < 0 || (uint64_t) host_fd >= KBOX_HOST_FD_REVERSE_MAX ||
        t->host_fd_refs[host_fd] == 0)
        return;
    /* Only the single-holder case can be cleared authoritatively. If
     * the slot is MULTI, leave it: we cannot prove this is the last
     * holder without scanning, and the slow path will handle later
     * lookups correctly. If the slot is NONE or claims a different
     * vfd, we were not the indexed holder; nothing to do.
     */

    t->host_fd_refs[host_fd]--;
    if (t->host_fd_refs[host_fd] == 0) {
        t->host_to_vfd[host_fd] = KBOX_HOST_VFD_NONE;
    } else if (t->host_fd_refs[host_fd] == 1) {
        /* 1. Try a normal search first */
        long cur_vfd = kbox_fd_table_find_by_host_fd(t, host_fd);

        /* 2. If the search tripped over the dying slot, hide it and search
         * again */
        if (cur_vfd == vfd) {
            struct kbox_fd_entry *e = fd_lookup(t, vfd);
            e->host_fd = -1;
            cur_vfd = kbox_fd_table_find_by_host_fd(t, host_fd);
            e->host_fd = host_fd;
        }

        t->host_to_vfd[host_fd] = cur_vfd;
    }
}
static inline void lkl_ref_inc(struct kbox_fd_table *t, long lkl_fd)
{
    if (lkl_fd >= 0 && (uint64_t) lkl_fd < KBOX_LKL_FD_REFMAX &&
        t->lkl_fd_refs[lkl_fd] < UINT16_MAX) {
        t->lkl_fd_refs[lkl_fd]++;
    }
}

static inline void lkl_ref_dec(struct kbox_fd_table *t, long lkl_fd)
{
    if (lkl_fd >= 0 && (uint64_t) lkl_fd < KBOX_LKL_FD_REFMAX &&
        t->lkl_fd_refs[lkl_fd] > 0) {
        t->lkl_fd_refs[lkl_fd]--;
    }
}

void kbox_fd_table_init(struct kbox_fd_table *t)
{
    long i;

    for (i = 0; i < KBOX_FD_TABLE_MAX; i++)
        clear_fd_entry(&t->entries[i]);
    for (i = 0; i < KBOX_LOW_FD_MAX; i++)
        clear_fd_entry(&t->low_fds[i]);
    for (i = 0; i < KBOX_MID_FD_MAX; i++)
        clear_fd_entry(&t->mid_fds[i]);
    for (i = 0; i < KBOX_HOST_FD_REVERSE_MAX; i++) {
        t->host_to_vfd[i] = KBOX_HOST_VFD_NONE;
        t->host_fd_refs[i] = 0;
    }
    for (i = 0; i < KBOX_LKL_FD_REFMAX; i++)
        t->lkl_fd_refs[i] = 0;
    t->next_fd = KBOX_FD_BASE;
    t->next_fast_fd = KBOX_FD_FAST_BASE;
    t->next_hostonly_fd = KBOX_FD_HOSTONLY_BASE;
}

/* Auto-allocate: always from the high range (>= KBOX_FD_BASE).
 * Low FDs are only populated via insert_at (dup2/dup3).
 */
long kbox_fd_table_insert(struct kbox_fd_table *t, long lkl_fd, int mirror_tty)
{
    long start_idx = t->next_fd - KBOX_FD_BASE;
    long limit_idx = KBOX_FD_FAST_BASE - KBOX_FD_BASE;
    long idx;

    if (start_idx < 0)
        start_idx = 0;
    if (start_idx >= limit_idx)
        start_idx = 0;

    for (idx = start_idx; idx < limit_idx; idx++) {
        if (t->entries[idx].lkl_fd == -1) {
            long vfd = idx + KBOX_FD_BASE;
            init_live_entry(&t->entries[idx], lkl_fd, mirror_tty);
            lkl_ref_inc(t, lkl_fd);
            t->next_fd = vfd + 1;
            return vfd;
        }
    }

    /* Wrap around: scan from the beginning up to start_idx. */
    for (idx = 0; idx < start_idx; idx++) {
        if (t->entries[idx].lkl_fd == -1) {
            long vfd = idx + KBOX_FD_BASE;
            init_live_entry(&t->entries[idx], lkl_fd, mirror_tty);
            lkl_ref_inc(t, lkl_fd);
            t->next_fd = vfd + 1;
            return vfd;
        }
    }

    return -1; /* table truly full */
}

long kbox_fd_table_insert_fast(struct kbox_fd_table *t,
                               long lkl_fd,
                               int mirror_tty)
{
    long start_idx = t->next_fast_fd - KBOX_FD_BASE;
    long base_idx = KBOX_FD_FAST_BASE - KBOX_FD_BASE;
    long limit_idx = KBOX_FD_HOSTONLY_BASE - KBOX_FD_BASE;
    long idx;

    if (start_idx < base_idx)
        start_idx = base_idx;
    if (start_idx >= limit_idx)
        start_idx = base_idx;

    for (idx = start_idx; idx < limit_idx; idx++) {
        if (t->entries[idx].lkl_fd == -1) {
            long vfd = idx + KBOX_FD_BASE;
            init_live_entry(&t->entries[idx], lkl_fd, mirror_tty);
            lkl_ref_inc(t, lkl_fd);
            t->next_fast_fd = vfd + 1;
            return vfd;
        }
    }

    for (idx = base_idx; idx < start_idx; idx++) {
        if (t->entries[idx].lkl_fd == -1) {
            long vfd = idx + KBOX_FD_BASE;
            init_live_entry(&t->entries[idx], lkl_fd, mirror_tty);
            lkl_ref_inc(t, lkl_fd);
            t->next_fast_fd = vfd + 1;
            return vfd;
        }
    }

    return -1;
}

int kbox_fd_table_insert_at(struct kbox_fd_table *t,
                            long fd,
                            long lkl_fd,
                            int mirror_tty)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e)
        return -1;

    /* Replacing a live slot: release the previous lkl_fd ref and the
     * old reverse-map entry first. insert_at semantics permit reusing
     * an in-use slot (e.g. dup2 over an existing FD).
     */
    if (e->lkl_fd != -1) {
        lkl_ref_dec(t, e->lkl_fd);
        rev_host_clear(t, e->host_fd, fd);
    }

    init_live_entry(e, lkl_fd, mirror_tty);
    lkl_ref_inc(t, lkl_fd);

    /* Keep next_fd ahead of the highest occupied high-range slot. */
    if (fd >= KBOX_FD_BASE && fd >= t->next_fd)
        t->next_fd = fd + 1;

    return 0;
}

long kbox_fd_table_get_lkl(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e)
        return -1;
    return e->lkl_fd;
}

long kbox_fd_table_remove(struct kbox_fd_table *t, long fd)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    long old;

    if (!e)
        return -1;

    old = e->lkl_fd;
    /* Release reverse-map and refcount tracking before clobbering
     * the entry fields. rev_host_clear is safe for sentinel host_fd
     * values and for entries whose host_fd was not in the reverse
     * table. lkl_ref_dec is safe for KBOX_LKL_FD_SHADOW_ONLY and
     * other negative sentinels.
     */
    rev_host_clear(t, e->host_fd, fd);
    if (e->lkl_fd != -1)
        lkl_ref_dec(t, e->lkl_fd);
#ifndef KBOX_UNIT_TEST
    /* For shadow sockets (shadow_sp >= 0), host_fd is a tracee-namespace FD
     * number from ADDFD, NOT a supervisor-owned FD. Don't close it in the
     * supervisor; it would close an unrelated local FD.
     */
    if (e->host_fd >= 0 && e->shadow_sp < 0)
        close((int) e->host_fd);
    if (e->shadow_sp >= 0)
        close(e->shadow_sp);
#endif
    clear_fd_entry(e);
    if (fd >= KBOX_FD_HOSTONLY_BASE && fd < KBOX_FD_BASE + KBOX_FD_TABLE_MAX &&
        (t->next_hostonly_fd < KBOX_FD_HOSTONLY_BASE ||
         fd < t->next_hostonly_fd)) {
        t->next_hostonly_fd = fd;
    }
    if (fd >= KBOX_FD_FAST_BASE && fd < KBOX_FD_HOSTONLY_BASE &&
        (t->next_fast_fd < KBOX_FD_FAST_BASE || fd < t->next_fast_fd)) {
        t->next_fast_fd = fd;
    }
    if (fd >= KBOX_FD_BASE && fd < KBOX_FD_FAST_BASE &&
        (t->next_fd < KBOX_FD_BASE || fd < t->next_fd)) {
        t->next_fd = fd;
    }
    return old;
}

bool kbox_fd_table_mirror_tty(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return false;
    return e->mirror_tty != 0;
}

void kbox_fd_table_set_cloexec(struct kbox_fd_table *t, long fd, int val)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return;
    e->cloexec = val ? 1 : 0;
}

int kbox_fd_table_get_cloexec(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return 0;
    return e->cloexec;
}

#ifndef KBOX_UNIT_TEST
/* Is this entry the last reference to its lkl_fd? Uses the
 * maintained refcount; fd_table_refs[e->lkl_fd] counts the entry
 * itself, so "last reference" means refcount == 1.
 *
 * lkl_fds at or above KBOX_LKL_FD_REFMAX are tracked only with the
 * legacy scan because we cannot store a refcount for them. This path
 * is a safety net; real LKL kernels allocate small FDs.
 */
static int lkl_fd_is_sole_ref(const struct kbox_fd_table *t,
                              const struct kbox_fd_entry *skip,
                              long lkl_fd)
{
    if (lkl_fd < 0)
        return 1;
    if ((uint64_t) lkl_fd < KBOX_LKL_FD_REFMAX)
        return t->lkl_fd_refs[lkl_fd] <= 1;

    /* Fallback for out-of-range lkl_fd: the original O(n) scan. */
    long i;
    for (i = 0; i < KBOX_FD_TABLE_MAX; i++)
        if (&t->entries[i] != skip && t->entries[i].lkl_fd == lkl_fd)
            return 0;
    for (i = 0; i < KBOX_LOW_FD_MAX; i++)
        if (&t->low_fds[i] != skip && t->low_fds[i].lkl_fd == lkl_fd)
            return 0;
    for (i = 0; i < KBOX_MID_FD_MAX; i++)
        if (&t->mid_fds[i] != skip && t->mid_fds[i].lkl_fd == lkl_fd)
            return 0;
    return 1;
}

static void close_cloexec_entry(struct kbox_fd_table *t,
                                struct kbox_fd_entry *e,
                                long vfd,
                                const struct kbox_sysnrs *s)
{
    if (e->lkl_fd != -1 && e->cloexec) {
        /* Host-passthrough entries are shared across supervised processes,
         * but FD_CLOEXEC is per-process.  Clearing a passthrough slot here
         * on one process's exec would drop tracking for siblings/parent that
         * still hold the same FD number.  Leave the shared bookkeeping intact.
         */
        if (e->lkl_fd == KBOX_LKL_FD_SHADOW_ONLY)
            return;

        /* Only close real LKL FDs; sentinel values (e.g.
         * KBOX_LKL_FD_SHADOW_ONLY for host-passthrough pipes/eventfds) are not
         * LKL file descriptors.
         */
        if (e->lkl_fd >= 0 && lkl_fd_is_sole_ref(t, e, e->lkl_fd))
            kbox_lkl_close(s, e->lkl_fd);

        rev_host_clear(t, e->host_fd, vfd);
        if (e->lkl_fd != -1)
            lkl_ref_dec(t, e->lkl_fd);

        /* Shadow sockets: host_fd is tracee-namespace, don't close. */
        if (e->host_fd >= 0 && e->shadow_sp < 0) {
            close((int) e->host_fd);
            e->host_fd = -1;
        }
        if (e->shadow_sp >= 0) {
            close(e->shadow_sp);
            e->shadow_sp = -1;
        }
        clear_fd_entry(e);
    }
}

void kbox_fd_table_close_cloexec(struct kbox_fd_table *t,
                                 const struct kbox_sysnrs *s)
{
    long i;

    for (i = 0; i < KBOX_LOW_FD_MAX; i++)
        close_cloexec_entry(t, &t->low_fds[i], i, s);
    for (i = 0; i < KBOX_MID_FD_MAX; i++)
        close_cloexec_entry(t, &t->mid_fds[i], KBOX_LOW_FD_MAX + i, s);
    for (i = 0; i < KBOX_FD_TABLE_MAX; i++)
        close_cloexec_entry(t, &t->entries[i], KBOX_FD_BASE + i, s);
}
#endif

void kbox_fd_table_set_host_fd(struct kbox_fd_table *t, long fd, long host_fd)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return;
    /* Drop our claim on the old host_fd, then install the new one. */
    rev_host_clear(t, e->host_fd, fd);
    e->host_fd = host_fd;
    rev_host_set(t, host_fd, fd);
}

long kbox_fd_table_get_host_fd(const struct kbox_fd_table *t, long fd)
{
    const struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return -1;
    return e->host_fd;
}

long kbox_fd_table_find_by_host_fd(const struct kbox_fd_table *t, long host_fd)
{
    long i;

    if (host_fd < 0)
        return -1;

    /* Fast path: O(1) reverse-map lookup.
     *   NONE  -> authoritative miss (no holder).
     *   vfd   -> forward-check and return.
     *   MULTI -> fall through to the linear scan.
     */
    if ((uint64_t) host_fd < KBOX_HOST_FD_REVERSE_MAX) {
        int32_t slot = t->host_to_vfd[host_fd];
        if (slot == KBOX_HOST_VFD_NONE)
            return -1;
        if (slot != KBOX_HOST_VFD_MULTI) {
            long vfd = slot;
            const struct kbox_fd_entry *e = fd_lookup(t, vfd);
            if (e && e->lkl_fd != -1 && e->host_fd == host_fd)
                return vfd;
            /* Stale single-holder entry (e.g. host_fd rewritten
             * directly to a sentinel). Fall through to the linear
             * scan, which will still find any other holder that
             * exists.
             */
        }
    }

    /* Slow path: MULTI slot, stale single-holder, or out-of-range
     * host_fd. Preserves the original linear-scan semantics exactly.
     */
    for (i = 0; i < KBOX_LOW_FD_MAX; i++) {
        if (t->low_fds[i].lkl_fd != -1 && t->low_fds[i].host_fd == host_fd)
            return i;
    }
    for (i = 0; i < KBOX_MID_FD_MAX; i++) {
        if (t->mid_fds[i].lkl_fd != -1 && t->mid_fds[i].host_fd == host_fd)
            return i + KBOX_LOW_FD_MAX;
    }
    for (i = 0; i < KBOX_FD_TABLE_MAX; i++) {
        if (t->entries[i].lkl_fd != -1 && t->entries[i].host_fd == host_fd)
            return i + KBOX_FD_BASE;
    }
    return -1;
}

unsigned kbox_fd_table_lkl_ref_count(const struct kbox_fd_table *t, long lkl_fd)
{
    if (lkl_fd < 0)
        return 0;
    if ((uint64_t) lkl_fd < KBOX_LKL_FD_REFMAX)
        return t->lkl_fd_refs[lkl_fd];
    /* Out-of-range fallback: legacy O(n) scan. */
    unsigned count = 0;
    long i;
    for (i = 0; i < KBOX_FD_TABLE_MAX; i++)
        if (t->entries[i].lkl_fd == lkl_fd)
            count++;
    for (i = 0; i < KBOX_LOW_FD_MAX; i++)
        if (t->low_fds[i].lkl_fd == lkl_fd)
            count++;
    for (i = 0; i < KBOX_MID_FD_MAX; i++)
        if (t->mid_fds[i].lkl_fd == lkl_fd)
            count++;
    return count;
}

unsigned kbox_fd_table_count(const struct kbox_fd_table *t)
{
    unsigned n = 0;
    int i;

    for (i = 0; i < KBOX_LOW_FD_MAX; i++) {
        if (t->low_fds[i].lkl_fd != -1)
            n++;
    }
    for (i = 0; i < KBOX_MID_FD_MAX; i++) {
        if (t->mid_fds[i].lkl_fd != -1)
            n++;
    }
    for (i = 0; i < KBOX_FD_TABLE_MAX; i++) {
        if (t->entries[i].lkl_fd != -1)
            n++;
    }
    return n;
}
