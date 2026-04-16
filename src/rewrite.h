/* SPDX-License-Identifier: MIT */
#ifndef KBOX_REWRITE_H
#define KBOX_REWRITE_H

#include <stddef.h>
#include <stdint.h>

#include "kbox/cli.h"
#include "kbox/elf.h"
#include "loader-launch.h"
#include "seccomp.h"

enum kbox_rewrite_arch {
    KBOX_REWRITE_ARCH_UNKNOWN = 0,
    KBOX_REWRITE_ARCH_X86_64,
    KBOX_REWRITE_ARCH_AARCH64,
};

#define KBOX_REWRITE_MAX_PATCH_BYTES 8

/* Site classification for caller-aware rewrite dispatch.
 *
 * WRAPPER: the syscall site is inside a simple libc-style wrapper function
 *   (pattern: [mov NR], syscall, ret). The syscall result is returned
 *   directly to the caller with no side effects. Safe for expanded
 *   fast-path dispatch (host-semantic forwarding of process-info,
 *   simple I/O, etc.).
 *
 * COMPLEX: the site is inside a larger function where the syscall result
 *   may be consumed internally (e.g., raise() -> gettid -> tgkill, or
 *   pthread_create -> clone). Must use full dispatch to preserve the
 *   virtualization layer's invariants.
 *
 * UNKNOWN: classification could not be determined (e.g., insufficient
 *   context, non-standard calling convention). Treated as COMPLEX.
 */
enum kbox_rewrite_site_class {
    KBOX_REWRITE_SITE_UNKNOWN = 0,
    KBOX_REWRITE_SITE_WRAPPER,
    KBOX_REWRITE_SITE_COMPLEX,
};

struct kbox_rewrite_report {
    enum kbox_rewrite_arch arch;
    size_t exec_segment_count;
    size_t candidate_count;
};

struct kbox_rewrite_site {
    uint64_t file_offset;
    uint64_t vaddr;
    uint64_t segment_vaddr;
    uint64_t segment_mem_size;
    unsigned char width;
    unsigned char original[KBOX_REWRITE_MAX_PATCH_BYTES];
    enum kbox_rewrite_site_class site_class;
};

struct kbox_rewrite_patch {
    unsigned char width;
    unsigned char bytes[KBOX_REWRITE_MAX_PATCH_BYTES];
};

struct kbox_rewrite_runtime_trampoline_region {
    void *mapping;
    size_t size;
};

struct kbox_rewrite_trampoline_probe {
    enum kbox_rewrite_arch arch;
    int feasible;
    uint64_t trampoline_addr;
    const char *reason;
};

struct kbox_rewrite_trampoline_layout {
    enum kbox_rewrite_arch arch;
    uint64_t base_addr;
    uint64_t slot_size;
};

struct kbox_rewrite_planned_site {
    struct kbox_rewrite_site site;
    uint64_t trampoline_addr;
    struct kbox_rewrite_patch patch;
};

struct kbox_rewrite_origin_entry {
    uint64_t origin;
    enum kbox_loader_mapping_source source;
    enum kbox_rewrite_site_class site_class;
};

struct kbox_rewrite_origin_map {
    enum kbox_rewrite_arch arch;
    struct kbox_rewrite_origin_entry *entries;
    size_t count;
    size_t cap;
    size_t mapping_size;
    int sealed;
};

struct kbox_rewrite_runtime {
    struct kbox_supervisor_ctx *ctx;
    struct kbox_rewrite_origin_map origin_map;
    enum kbox_rewrite_arch arch;
    struct kbox_rewrite_runtime_trampoline_region
        trampoline_regions[KBOX_LOADER_MAX_MAPPINGS];
    size_t trampoline_region_count;
    int installed;
    /* Set during install if the main binary contains no fork-family syscall
     * sites. Gates promotion of cancel-style BL wrapper sites: bypassing
     * __syscall_cancel skips pthread cancellation point checks, which is only
     * safe when the program is single-threaded.
     */
    int cancel_promote_allowed;
};

enum kbox_rewrite_wrapper_family_mask {
    KBOX_REWRITE_WRAPPER_FAMILY_PROCINFO = 1u << 0,
    KBOX_REWRITE_WRAPPER_FAMILY_STAT = 1u << 1,
    KBOX_REWRITE_WRAPPER_FAMILY_OPEN = 1u << 2,
};

enum kbox_rewrite_wrapper_candidate_kind {
    KBOX_REWRITE_WRAPPER_CANDIDATE_DIRECT = 0,
    KBOX_REWRITE_WRAPPER_CANDIDATE_SYSCALL_CANCEL,
};

struct kbox_rewrite_wrapper_candidate {
    enum kbox_rewrite_arch arch;
    enum kbox_rewrite_wrapper_candidate_kind kind;
    uint64_t file_offset;
    uint64_t vaddr;
    uint64_t nr;
    uint32_t family_mask;
};

typedef int (*kbox_rewrite_site_cb)(const struct kbox_rewrite_site *site,
                                    void *opaque);
typedef int (*kbox_rewrite_planned_site_cb)(
    const struct kbox_rewrite_planned_site *planned,
    void *opaque);
typedef int (*kbox_rewrite_wrapper_candidate_cb)(
    const struct kbox_rewrite_wrapper_candidate *candidate,
    void *opaque);

const char *kbox_syscall_mode_name(enum kbox_syscall_mode mode);
int kbox_parse_syscall_mode(const char *value, enum kbox_syscall_mode *out);

const char *kbox_rewrite_arch_name(enum kbox_rewrite_arch arch);
int kbox_rewrite_analyze_elf(const unsigned char *buf,
                             size_t buf_len,
                             struct kbox_rewrite_report *report);
int kbox_rewrite_analyze_memfd(int fd, struct kbox_rewrite_report *report);
int kbox_rewrite_visit_elf_sites(const unsigned char *buf,
                                 size_t buf_len,
                                 kbox_rewrite_site_cb cb,
                                 void *opaque,
                                 struct kbox_rewrite_report *report);
int kbox_rewrite_visit_memfd_sites(int fd,
                                   kbox_rewrite_site_cb cb,
                                   void *opaque,
                                   struct kbox_rewrite_report *report);
int kbox_rewrite_visit_elf_planned_sites(const unsigned char *buf,
                                         size_t buf_len,
                                         kbox_rewrite_planned_site_cb cb,
                                         void *opaque,
                                         struct kbox_rewrite_report *report);
int kbox_rewrite_visit_memfd_planned_sites(int fd,
                                           kbox_rewrite_planned_site_cb cb,
                                           void *opaque,
                                           struct kbox_rewrite_report *report);
int kbox_rewrite_apply_elf(unsigned char *buf,
                           size_t buf_len,
                           size_t *applied_count,
                           struct kbox_rewrite_report *report);
int kbox_rewrite_apply_memfd(int fd,
                             size_t *applied_count,
                             struct kbox_rewrite_report *report);
int kbox_rewrite_apply_virtual_procinfo_elf(unsigned char *buf,
                                            size_t buf_len,
                                            size_t *applied_count,
                                            struct kbox_rewrite_report *report);
int kbox_rewrite_apply_virtual_procinfo_memfd(
    int fd,
    size_t *applied_count,
    struct kbox_rewrite_report *report);
void kbox_rewrite_origin_map_init(struct kbox_rewrite_origin_map *map,
                                  enum kbox_rewrite_arch arch);
void kbox_rewrite_origin_map_reset(struct kbox_rewrite_origin_map *map);
int kbox_rewrite_origin_map_add_site_source(
    struct kbox_rewrite_origin_map *map,
    const struct kbox_rewrite_site *site,
    enum kbox_loader_mapping_source source);
int kbox_rewrite_origin_map_add_classified(
    struct kbox_rewrite_origin_map *map,
    const struct kbox_rewrite_site *site,
    enum kbox_loader_mapping_source source,
    enum kbox_rewrite_site_class site_class);
static inline int kbox_rewrite_origin_map_add_site(
    struct kbox_rewrite_origin_map *map,
    const struct kbox_rewrite_site *site)
{
    return kbox_rewrite_origin_map_add_site_source(map, site,
                                                   KBOX_LOADER_MAPPING_MAIN);
}
int kbox_rewrite_origin_map_contains(const struct kbox_rewrite_origin_map *map,
                                     uint64_t origin_addr);
int kbox_rewrite_origin_map_find(const struct kbox_rewrite_origin_map *map,
                                 uint64_t origin_addr,
                                 struct kbox_rewrite_origin_entry *out);
int kbox_rewrite_origin_map_build_elf(struct kbox_rewrite_origin_map *map,
                                      const unsigned char *buf,
                                      size_t buf_len,
                                      struct kbox_rewrite_report *report);
int kbox_rewrite_origin_map_build_memfd(struct kbox_rewrite_origin_map *map,
                                        int fd,
                                        struct kbox_rewrite_report *report);
int kbox_rewrite_origin_map_seal(struct kbox_rewrite_origin_map *map);
int kbox_rewrite_encode_patch(const struct kbox_rewrite_site *site,
                              uint64_t trampoline_addr,
                              struct kbox_rewrite_patch *patch);
int kbox_rewrite_encode_x86_64_page_zero_trampoline(unsigned char *buf,
                                                    size_t buf_len,
                                                    uint64_t entry_addr);
int kbox_rewrite_init_trampoline_layout(
    enum kbox_rewrite_arch arch,
    const struct kbox_elf_exec_segment *seg,
    struct kbox_rewrite_trampoline_layout *layout);
int kbox_rewrite_plan_site(const struct kbox_rewrite_site *site,
                           const struct kbox_rewrite_trampoline_layout *layout,
                           size_t slot_index,
                           struct kbox_rewrite_planned_site *planned);
int kbox_rewrite_probe_x86_64_page_zero(
    uint64_t mmap_min_addr,
    struct kbox_rewrite_trampoline_probe *probe);
int kbox_rewrite_probe_trampoline(enum kbox_rewrite_arch arch,
                                  struct kbox_rewrite_trampoline_probe *probe);
int kbox_rewrite_is_fast_host_syscall0(const struct kbox_host_nrs *host_nrs,
                                       uint64_t nr);
int kbox_rewrite_wrapper_syscall_nr(const struct kbox_rewrite_site *site,
                                    enum kbox_rewrite_arch arch,
                                    uint64_t *out_nr);
enum kbox_rewrite_site_class kbox_rewrite_classify_x86_64_site(
    const unsigned char *segment_bytes,
    size_t segment_size,
    size_t site_offset,
    unsigned char site_width);
enum kbox_rewrite_site_class kbox_rewrite_classify_aarch64_site(
    const unsigned char *segment_bytes,
    size_t segment_size,
    size_t site_offset);
int kbox_rewrite_origin_map_find_class(
    const struct kbox_rewrite_origin_map *map,
    uint64_t origin_addr,
    enum kbox_rewrite_site_class *out);
int kbox_rewrite_is_site_fast_eligible(
    const struct kbox_rewrite_origin_map *map,
    uint64_t origin_addr,
    const struct kbox_host_nrs *host_nrs,
    uint64_t nr);
int kbox_rewrite_has_fork_sites(const unsigned char *buf,
                                size_t buf_len,
                                const struct kbox_host_nrs *host_nrs);
int kbox_rewrite_has_fork_sites_memfd(int fd,
                                      const struct kbox_host_nrs *host_nrs);
int kbox_rewrite_has_wrapper_syscalls(const unsigned char *buf,
                                      size_t buf_len,
                                      enum kbox_rewrite_arch arch,
                                      const uint64_t *nrs,
                                      size_t nr_count);
int kbox_rewrite_has_wrapper_syscalls_memfd(int fd,
                                            const uint64_t *nrs,
                                            size_t nr_count);
int kbox_rewrite_wrapper_family_mask_memfd(int fd,
                                           const struct kbox_host_nrs *host_nrs,
                                           uint32_t *out_mask);
int kbox_rewrite_visit_memfd_wrapper_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask,
    kbox_rewrite_wrapper_candidate_cb cb,
    void *opaque);
int kbox_rewrite_collect_memfd_wrapper_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask,
    struct kbox_rewrite_wrapper_candidate *out,
    size_t out_cap,
    size_t *out_count);
int kbox_rewrite_collect_memfd_wrapper_candidates_by_kind(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    uint32_t family_mask,
    enum kbox_rewrite_wrapper_candidate_kind kind,
    struct kbox_rewrite_wrapper_candidate *out,
    size_t out_cap,
    size_t *out_count);

int kbox_rewrite_collect_memfd_phase1_path_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    struct kbox_rewrite_wrapper_candidate *out,
    size_t out_cap,
    size_t *out_count);
int kbox_rewrite_apply_memfd_phase1_path_candidates(
    int fd,
    const struct kbox_host_nrs *host_nrs,
    size_t *applied_count,
    struct kbox_rewrite_report *report);
void kbox_rewrite_runtime_reset(struct kbox_rewrite_runtime *runtime);
struct kbox_rewrite_runtime *kbox_rewrite_runtime_active(void);
int kbox_rewrite_runtime_install(struct kbox_rewrite_runtime *runtime,
                                 struct kbox_supervisor_ctx *ctx,
                                 struct kbox_loader_launch *launch);
int kbox_rewrite_runtime_promote_exec_region(
    struct kbox_rewrite_runtime *runtime,
    uint64_t addr,
    uint64_t len);

#endif /* KBOX_REWRITE_H */
