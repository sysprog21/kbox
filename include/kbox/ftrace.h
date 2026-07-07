/* SPDX-License-Identifier: MIT */
#ifndef KBOX_FTRACE_H
#define KBOX_FTRACE_H
struct kbox_sysnrs;
struct kbox_image_args;
int kbox_ftrace_enable(const struct kbox_sysnrs *s,
                       const struct kbox_image_args *args);
void kbox_ftrace_dump(const struct kbox_sysnrs *s,
                      const struct kbox_image_args *args);
#endif /* KBOX_FTRACE_H */
