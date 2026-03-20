/* SPDX-License-Identifier: MIT */
#ifndef KBOX_FD_TABLE_H
#define KBOX_FD_TABLE_H

#include <stdbool.h>

struct kbox_sysnrs; /* forward declaration */

/*
 * Virtual FD table.
 *
 * Maps guest-visible FDs (starting at KBOX_FD_BASE) to LKL-internal
 * FDs.  Flat array indexed by (vfd - KBOX_FD_BASE).  O(1) lookup,
 * zero allocator overhead, cache-friendly.
 *
 * This replaces the Rust HashMap<c_long, c_long>.
 */

#define KBOX_FD_BASE 32768
#define KBOX_FD_TABLE_MAX 4096
#define KBOX_LOW_FD_MAX                                   \
    1024 /* redirect slots for FDs 0..1023 (dup2 targets) \
          */

struct kbox_fd_entry {
    long lkl_fd;    /* LKL-internal FD, -1 if slot is free */
    long host_fd;   /* host memfd shadow / tracee FD number, -1 if none */
    int shadow_sp;  /* supervisor's dup of shadow socket sp[1], -1 if none.
                     * Kept alive so dup/dup2/dup3 can inject new copies
                     * into the tracee via ADDFD. */
    int mirror_tty; /* 1 if this FD mirrors a host TTY */
    int cloexec;    /* O_CLOEXEC tracking */
};

struct kbox_fd_table {
    struct kbox_fd_entry entries[KBOX_FD_TABLE_MAX];
    struct kbox_fd_entry low_fds[KBOX_LOW_FD_MAX]; /* dup2 redirect slots */
    long next_fd; /* Next virtual FD to allocate */
};

/* Initialize the table.  All slots marked free. */
void kbox_fd_table_init(struct kbox_fd_table *t);

/*
 * Insert a new LKL FD.  Returns the allocated virtual FD,
 * or -1 if the table is full.
 */
long kbox_fd_table_insert(struct kbox_fd_table *t, long lkl_fd, int mirror_tty);

/*
 * Insert at a specific virtual FD (for dup2/dup3).
 * Overwrites any existing entry at that slot.
 * Returns 0 on success, -1 if fd is out of range.
 */
int kbox_fd_table_insert_at(struct kbox_fd_table *t,
                            long fd,
                            long lkl_fd,
                            int mirror_tty);

/*
 * Look up the LKL FD for a virtual FD.
 * Returns the LKL FD, or -1 if not found.
 */
long kbox_fd_table_get_lkl(const struct kbox_fd_table *t, long fd);

/*
 * Remove a virtual FD from the table.
 * Returns the LKL FD that was stored, or -1 if not found.
 */
long kbox_fd_table_remove(struct kbox_fd_table *t, long fd);

/*
 * Check if a virtual FD should mirror writes to a host TTY.
 */
bool kbox_fd_table_mirror_tty(const struct kbox_fd_table *t, long fd);

/*
 * Set/clear the cloexec flag for a virtual FD.
 */
void kbox_fd_table_set_cloexec(struct kbox_fd_table *t, long fd, int val);

/*
 * Get the cloexec flag for a virtual FD.  Returns 0 if not set or not found.
 */
int kbox_fd_table_get_cloexec(const struct kbox_fd_table *t, long fd);

/*
 * Close all entries with cloexec set (for execve).
 * Calls kbox_lkl_close for each.
 */
void kbox_fd_table_close_cloexec(struct kbox_fd_table *t,
                                 const struct kbox_sysnrs *s);

/*
 * Set the host-side shadow FD for a virtual FD.
 */
void kbox_fd_table_set_host_fd(struct kbox_fd_table *t, long fd, long host_fd);

/*
 * Get the host-side shadow FD for a virtual FD.
 * Returns -1 if not found or no shadow.
 */
long kbox_fd_table_get_host_fd(const struct kbox_fd_table *t, long fd);

/*
 * Reverse lookup: find the virtual FD that has a given host_fd.
 * Returns the virtual FD, or -1 if not found.
 * Linear scan -- only used on close/mmap paths (cold).
 */
long kbox_fd_table_find_by_host_fd(const struct kbox_fd_table *t, long host_fd);

#endif /* KBOX_FD_TABLE_H */
