/* SPDX-License-Identifier: MIT */
/*
 * fd-table.c - Virtual FD table mapping guest FDs to LKL FDs.
 *
 * Two backing stores:
 *   - entries[]:  FDs in [KBOX_FD_BASE, KBOX_FD_BASE + KBOX_FD_TABLE_MAX)
 *   - low_fds[]:  FDs in [0, KBOX_LOW_FD_MAX)  -- populated only by dup2/dup3
 *
 * A slot is free when lkl_fd == -1.  All lookups go through fd_lookup()
 * which handles both ranges in O(1).
 */

#include "kbox/fd-table.h"

#include "kbox/lkl-wrap.h"
#include "kbox/syscall-nr.h"

#include <unistd.h>

/*
 * Unified entry lookup.  Returns a pointer to the kbox_fd_entry for
 * the given FD, or NULL if the FD is in neither range.
 */
static struct kbox_fd_entry *fd_lookup(const struct kbox_fd_table *t, long fd)
{
    if (fd >= 0 && fd < KBOX_LOW_FD_MAX)
        return (struct kbox_fd_entry *) &t->low_fds[fd];
    if (fd >= KBOX_FD_BASE && fd < KBOX_FD_BASE + KBOX_FD_TABLE_MAX)
        return (struct kbox_fd_entry *) &t->entries[fd - KBOX_FD_BASE];
    return NULL;
}

void kbox_fd_table_init(struct kbox_fd_table *t)
{
    long i;

    for (i = 0; i < KBOX_FD_TABLE_MAX; i++) {
        t->entries[i].lkl_fd = -1;
        t->entries[i].host_fd = -1;
        t->entries[i].shadow_sp = -1;
        t->entries[i].mirror_tty = 0;
        t->entries[i].cloexec = 0;
    }
    for (i = 0; i < KBOX_LOW_FD_MAX; i++) {
        t->low_fds[i].lkl_fd = -1;
        t->low_fds[i].host_fd = -1;
        t->low_fds[i].shadow_sp = -1;
        t->low_fds[i].mirror_tty = 0;
        t->low_fds[i].cloexec = 0;
    }
    t->next_fd = KBOX_FD_BASE;
}

/*
 * Auto-allocate: always from the high range (>= KBOX_FD_BASE).
 * Low FDs are only populated via insert_at (dup2/dup3).
 */
long kbox_fd_table_insert(struct kbox_fd_table *t, long lkl_fd, int mirror_tty)
{
    long start_idx = t->next_fd - KBOX_FD_BASE;
    long idx;

    if (start_idx < 0)
        start_idx = 0;
    if (start_idx >= KBOX_FD_TABLE_MAX)
        start_idx = 0;

    for (idx = start_idx; idx < KBOX_FD_TABLE_MAX; idx++) {
        if (t->entries[idx].lkl_fd == -1) {
            long vfd = idx + KBOX_FD_BASE;

            t->entries[idx].lkl_fd = lkl_fd;
            t->entries[idx].host_fd = -1;
            t->entries[idx].shadow_sp = -1;
            t->entries[idx].mirror_tty = mirror_tty;
            t->entries[idx].cloexec = 0;
            t->next_fd = vfd + 1;
            return vfd;
        }
    }

    /* Wrap around: scan from the beginning up to start_idx. */
    for (idx = 0; idx < start_idx; idx++) {
        if (t->entries[idx].lkl_fd == -1) {
            long vfd = idx + KBOX_FD_BASE;

            t->entries[idx].lkl_fd = lkl_fd;
            t->entries[idx].host_fd = -1;
            t->entries[idx].shadow_sp = -1;
            t->entries[idx].mirror_tty = mirror_tty;
            t->entries[idx].cloexec = 0;
            t->next_fd = vfd + 1;
            return vfd;
        }
    }

    return -1; /* table truly full */
}

int kbox_fd_table_insert_at(struct kbox_fd_table *t,
                            long fd,
                            long lkl_fd,
                            int mirror_tty)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e)
        return -1;

    e->lkl_fd = lkl_fd;
    e->host_fd = -1;
    e->shadow_sp = -1;
    e->mirror_tty = mirror_tty;
    e->cloexec = 0;

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
#ifndef KBOX_UNIT_TEST
    /* For shadow sockets (shadow_sp >= 0), host_fd is a tracee-namespace
     * FD number from ADDFD, NOT a supervisor-owned FD.  Don't close it
     * in the supervisor -- it would close an unrelated local FD. */
    if (e->host_fd >= 0 && e->shadow_sp < 0)
        close((int) e->host_fd);
    if (e->shadow_sp >= 0)
        close(e->shadow_sp);
#endif
    e->host_fd = -1;
    e->shadow_sp = -1;
    e->lkl_fd = -1;
    e->mirror_tty = 0;
    e->cloexec = 0;
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

static void clear_entry(struct kbox_fd_entry *e)
{
    e->lkl_fd = -1;
    e->host_fd = -1;
    e->shadow_sp = -1;
    e->mirror_tty = 0;
    e->cloexec = 0;
}

#ifndef KBOX_UNIT_TEST
/* Check if any other entry in the table references the same lkl_fd. */
static int lkl_fd_has_other_ref(const struct kbox_fd_table *t,
                                const struct kbox_fd_entry *skip,
                                long lkl_fd)
{
    long i;
    for (i = 0; i < KBOX_FD_TABLE_MAX; i++)
        if (&t->entries[i] != skip && t->entries[i].lkl_fd == lkl_fd)
            return 1;
    for (i = 0; i < KBOX_LOW_FD_MAX; i++)
        if (&t->low_fds[i] != skip && t->low_fds[i].lkl_fd == lkl_fd)
            return 1;
    return 0;
}

static void close_cloexec_entry(struct kbox_fd_table *t,
                                struct kbox_fd_entry *e,
                                const struct kbox_sysnrs *s)
{
    if (e->lkl_fd != -1 && e->cloexec) {
        /* Only close the LKL socket if no other entry shares it
         * (handles dup'd shadow sockets where multiple entries
         * reference the same lkl_fd). */
        if (!lkl_fd_has_other_ref(t, e, e->lkl_fd))
            kbox_lkl_close(s, e->lkl_fd);
        /* Shadow sockets: host_fd is tracee-namespace, don't close. */
        if (e->host_fd >= 0 && e->shadow_sp < 0) {
            close((int) e->host_fd);
            e->host_fd = -1;
        }
        if (e->shadow_sp >= 0) {
            close(e->shadow_sp);
            e->shadow_sp = -1;
        }
        clear_entry(e);
    }
}

void kbox_fd_table_close_cloexec(struct kbox_fd_table *t,
                                 const struct kbox_sysnrs *s)
{
    long i;

    for (i = 0; i < KBOX_LOW_FD_MAX; i++)
        close_cloexec_entry(t, &t->low_fds[i], s);
    for (i = 0; i < KBOX_FD_TABLE_MAX; i++)
        close_cloexec_entry(t, &t->entries[i], s);
}
#endif

void kbox_fd_table_set_host_fd(struct kbox_fd_table *t, long fd, long host_fd)
{
    struct kbox_fd_entry *e = fd_lookup(t, fd);
    if (!e || e->lkl_fd == -1)
        return;
    e->host_fd = host_fd;
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

    /* Scan low FD redirect slots first. */
    for (i = 0; i < KBOX_LOW_FD_MAX; i++) {
        if (t->low_fds[i].lkl_fd != -1 && t->low_fds[i].host_fd == host_fd)
            return i;
    }

    /* Scan the main entries. */
    for (i = 0; i < KBOX_FD_TABLE_MAX; i++) {
        if (t->entries[i].lkl_fd != -1 && t->entries[i].host_fd == host_fd)
            return i + KBOX_FD_BASE;
    }
    return -1;
}
