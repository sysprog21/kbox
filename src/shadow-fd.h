/* SPDX-License-Identifier: MIT */
#ifndef KBOX_SHADOW_FD_H
#define KBOX_SHADOW_FD_H

struct kbox_sysnrs;


#define DEFAULT_SHADOW_LIMIT (256ULL * 1024 * 1024)
#define MAX_SHADOW_LIMIT (512ULL * 1024 * 1024)
void kbox_shadow_set_limit(uint64_t limit);
int kbox_shadow_create(const struct kbox_sysnrs *s, long lkl_fd);
int kbox_shadow_seal(int memfd);

#endif /* KBOX_SHADOW_FD_H */
