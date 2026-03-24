/* SPDX-License-Identifier: MIT */

#ifndef KBOX_FD_TABLE_H
#define KBOX_FD_TABLE_H

#include <stdbool.h>

struct kbox_sysnrs; /* forward declaration */

/* Virtual FD table.
 *
 * Maps guest-visible FDs (starting at KBOX_FD_BASE) to LKL-internal FDs. Flat
 * array indexed by (vfd - KBOX_FD_BASE). O(1) lookup, zero allocator overhead,
 * cache-friendly.
 */

#define KBOX_FD_BASE 32768
#define KBOX_FD_TABLE_MAX 4096
/* redirect slots for FDs 0..32767 (dup2 targets) */
#define KBOX_LOW_FD_MAX 32768
#define KBOX_FD_TABLE_CAPACITY (KBOX_FD_TABLE_MAX + KBOX_LOW_FD_MAX)

struct kbox_fd_entry {
    long lkl_fd;    /* LKL-internal FD, -1 if slot is free */
    long host_fd;   /* host memfd shadow / tracee FD number, -1 if none */
    int shadow_sp;  /* supervisor's dup of shadow socket sp[1], -1 if none.
                     * Kept alive so dup/dup2/dup3 can inject new copies into
                     * the tracee via ADDFD.
                     */
    int mirror_tty; /* 1 if this FD mirrors a host TTY */
    int cloexec;    /* O_CLOEXEC tracking */
};

struct kbox_fd_table {
    struct kbox_fd_entry entries[KBOX_FD_TABLE_MAX];
    struct kbox_fd_entry low_fds[KBOX_LOW_FD_MAX]; /* dup2 redirect slots */
    long next_fd; /* Next virtual FD to allocate */
};

void kbox_fd_table_init(struct kbox_fd_table *t);
long kbox_fd_table_insert(struct kbox_fd_table *t, long lkl_fd, int mirror_tty);
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
unsigned kbox_fd_table_count(const struct kbox_fd_table *t);

#endif /* KBOX_FD_TABLE_H */
