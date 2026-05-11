/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SHADOW_FD_H
#define KBOX_SHADOW_FD_H

struct kbox_sysnrs;

#define KBOX_SHADOW_MAX_SIZE (256L * 1024 * 1024)

/* Maximum number of memfds the shadow cache will retain. */
#define KBOX_SHADOW_CACHE_MAX 64

int kbox_shadow_create(const struct kbox_sysnrs *s, long lkl_fd);
int kbox_shadow_seal(int memfd);

/* Cached variant for read-only shadow promotion. */
int kbox_shadow_create_cached(const struct kbox_sysnrs *s, long lkl_fd);

/* Drop all cached entries and close their memfds. */
void kbox_shadow_cache_reset(void);

/* Create for make check-unit */
unsigned kbox_shadow_cache_size(void);
unsigned long kbox_shadow_cache_hits(void);
unsigned long kbox_shadow_cache_misses(void);

#endif /* KBOX_SHADOW_FD_H */
