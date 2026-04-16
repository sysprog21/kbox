/* SPDX-License-Identifier: MIT */

#ifndef KBOX_FD_TABLE_H
#define KBOX_FD_TABLE_H

#include <stdbool.h>
#include <stdint.h>

struct kbox_sysnrs; /* forward declaration */

/* Virtual FD table.
 *
 * Maps guest-visible FDs (starting at KBOX_FD_BASE) to LKL-internal FDs. Flat
 * array indexed by (vfd - KBOX_FD_BASE). O(1) lookup, zero allocator overhead,
 * cache-friendly.
 */

#define KBOX_FD_BASE 32768
#define KBOX_FD_TABLE_MAX 4096
#define KBOX_FD_FAST_BASE (KBOX_FD_BASE + (KBOX_FD_TABLE_MAX / 2))
#define KBOX_FD_HOSTONLY_BASE (KBOX_FD_BASE + ((KBOX_FD_TABLE_MAX * 3) / 4))
/* redirect slots for FDs 0..1023 (dup2 targets) */
#define KBOX_LOW_FD_MAX 1024
/* tracked host-passthrough FDs in the gap [1024, 32768) */
#define KBOX_MID_FD_MAX (KBOX_FD_BASE - KBOX_LOW_FD_MAX)
#define KBOX_FD_TABLE_CAPACITY \
    (KBOX_FD_TABLE_MAX + KBOX_LOW_FD_MAX + KBOX_MID_FD_MAX)

/* Reverse lookup for host_fd -> virtual fd. Sized to cover the
 * child's RLIMIT_NOFILE (65536). Host FDs at or above this bound
 * fall through to a slow linear scan.
 */
#define KBOX_HOST_FD_REVERSE_MAX 65536
/* Refcount array for lkl_fd. Sized to cover realistic LKL kernel FD
 * numbers; LKL is in-process and typically allocates low integers.
 * lkl_fds at or above this bound are tracked by a slow scan.
 */
#define KBOX_LKL_FD_REFMAX 16384

/* Sentinel lkl_fd value for host-passthrough FDs (pipes, eventfds, timerfds,
 * epoll FDs, stdio) that have no LKL backing.  Stored in kbox_fd_entry.lkl_fd
 * to mark the slot as occupied.  I/O handlers CONTINUE these to the host
 * kernel; untracked FDs (lkl_fd == -1) get EBADF instead.
 */
#define KBOX_LKL_FD_SHADOW_ONLY (-2)

struct kbox_fd_entry {
    long lkl_fd;   /* LKL-internal FD, -1 if slot is free */
    long host_fd;  /* host memfd shadow / tracee FD number, -1 if none */
    int shadow_sp; /* supervisor's dup of shadow socket sp[1], -1 if none.
                    * Kept alive so dup/dup2/dup3 can inject new copies into
                    * the tracee via ADDFD.
                    */
    int shadow_writeback; /* 1 if shadow_sp must be synced back to lkl_fd */
    int mirror_tty;       /* 1 if this FD mirrors a host TTY */
    int cloexec;          /* O_CLOEXEC tracking */
};

struct kbox_fd_table {
    struct kbox_fd_entry entries[KBOX_FD_TABLE_MAX];
    struct kbox_fd_entry low_fds[KBOX_LOW_FD_MAX]; /* dup2 redirect slots */
    struct kbox_fd_entry
        mid_fds[KBOX_MID_FD_MAX]; /* real host FDs 1024..32767 */
    /* Reverse host-fd map: host_to_vfd[h] = virtual fd currently
     * holding host_fd h, or -1 if none. Eliminates the O(n) scan in
     * kbox_fd_table_find_by_host_fd() on the close() hot path.
     */
    int32_t host_to_vfd[KBOX_HOST_FD_REVERSE_MAX];
    /* Refcount: how many virtual fds currently reference each
     * lkl_fd. Replaces the O(n) lkl_fd_has_other_ref scan and the
     * still_ref loop in forward_close.
     */
    uint16_t lkl_fd_refs[KBOX_LKL_FD_REFMAX];
    long next_fd;          /* Next virtual FD to allocate */
    long next_fast_fd;     /* Next host-shadow fast FD to allocate */
    long next_hostonly_fd; /* Next host-only cached-shadow FD to allocate */
};

void kbox_fd_table_init(struct kbox_fd_table *t);
long kbox_fd_table_insert(struct kbox_fd_table *t, long lkl_fd, int mirror_tty);
long kbox_fd_table_insert_fast(struct kbox_fd_table *t,
                               long lkl_fd,
                               int mirror_tty);
int kbox_fd_table_insert_at(struct kbox_fd_table *t,
                            long fd,
                            long lkl_fd,
                            int mirror_tty);
long kbox_fd_table_get_lkl(const struct kbox_fd_table *t, long fd);
long kbox_fd_table_remove(struct kbox_fd_table *t, long fd);
bool kbox_fd_table_mirror_tty(const struct kbox_fd_table *t, long fd);
void kbox_fd_table_set_cloexec(struct kbox_fd_table *t, long fd, int val);
int kbox_fd_table_get_cloexec(const struct kbox_fd_table *t, long fd);
void kbox_fd_table_close_cloexec(struct kbox_fd_table *t,
                                 const struct kbox_sysnrs *s);
void kbox_fd_table_set_host_fd(struct kbox_fd_table *t, long fd, long host_fd);
long kbox_fd_table_get_host_fd(const struct kbox_fd_table *t, long fd);
long kbox_fd_table_find_by_host_fd(const struct kbox_fd_table *t, long host_fd);
/* Return the number of virtual FDs currently referencing @lkl_fd. */
unsigned kbox_fd_table_lkl_ref_count(const struct kbox_fd_table *t,
                                     long lkl_fd);
unsigned kbox_fd_table_count(const struct kbox_fd_table *t);

#endif /* KBOX_FD_TABLE_H */
