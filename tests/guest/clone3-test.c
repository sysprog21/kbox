/* SPDX-License-Identifier: MIT */
/* Guest test: verify that clone3 namespace-flag sanitization blocks
 * CLONE_NEW* flags, and that an unreadable clone_args struct triggers the
 * fail-closed EPERM path.
 *
 * The guest-side assertions intentionally stay within behavior visible inside
 * the sandbox. The integration harness runs this binary with verbose seccomp
 * mode and matches kbox's "clone3 denied: namespace flags" log line, so the
 * regression check does not rely on host-specific CLONE_NEWUSER policy.
 */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, msg)                                    \
    do {                                                    \
        if (!(cond)) {                                      \
            fprintf(stderr, "FAIL: %s (%s)\n", msg, #cond); \
            exit(1);                                        \
        }                                                   \
    } while (0)

/* Linux struct clone_args (UAPI, 11 fields, 88 bytes). kbox requires
 * kernel >= 5.13 for seccomp USER_NOTIF, so this layout is always valid.
 */
struct clone3_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

_Static_assert(sizeof(struct clone3_args) == 88,
               "clone3_args must match kernel CLONE_ARGS_SIZE_VER2 (88 bytes)");

#define CLONE3_ARGS_SIZE sizeof(struct clone3_args)

static long do_clone3(struct clone3_args *args, size_t size)
{
    return syscall(__NR_clone3, args, size);
}

static void reap_child(pid_t pid)
{
    int status;
    pid_t wp;
    while ((wp = waitpid(pid, &status, 0)) < 0 && errno == EINTR)
        ;
    if (wp < 0)
        fprintf(stderr, "warning: waitpid(%d) failed: %s\n", pid,
                strerror(errno));
}

/* Each CLONE_NEW* flag that the supervisor must block. */
struct flag_case {
    uint64_t flag;
    const char *name;
};

static const struct flag_case namespace_flags[] = {
    {0x10000000ULL, "CLONE_NEWUSER"},   {0x00020000ULL, "CLONE_NEWNS"},
    {0x20000000ULL, "CLONE_NEWPID"},    {0x40000000ULL, "CLONE_NEWNET"},
    {0x04000000ULL, "CLONE_NEWUTS"},    {0x08000000ULL, "CLONE_NEWIPC"},
    {0x02000000ULL, "CLONE_NEWCGROUP"}, {0x00000080ULL, "CLONE_NEWTIME"},
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static void test_namespace_flags(void)
{
    for (size_t i = 0; i < ARRAY_SIZE(namespace_flags); i++) {
        struct clone3_args args;
        memset(&args, 0, sizeof(args));
        args.flags = namespace_flags[i].flag;
        args.exit_signal = SIGCHLD;

        errno = 0;
        long rc = do_clone3(&args, CLONE3_ARGS_SIZE);
        if (rc == 0)
            _exit(0);
        if (rc > 0) {
            reap_child(rc);
            fprintf(stderr, "FAIL: clone3(%s) succeeded (child %ld)\n",
                    namespace_flags[i].name, rc);
            exit(1);
        }
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "clone3(%s) should return EPERM, got rc=%ld errno=%d",
                 namespace_flags[i].name, rc, errno);
        CHECK(rc < 0, msg);
        snprintf(msg, sizeof(msg),
                 "clone3(%s) errno should be EPERM (%d), got %d",
                 namespace_flags[i].name, EPERM, errno);
        CHECK(errno == EPERM, msg);
        printf("  ok: clone3(%s) -> EPERM\n", namespace_flags[i].name);
    }
}

static void test_combined_namespace_flags(void)
{
    struct clone3_args args;
    memset(&args, 0, sizeof(args));
    args.flags = 0x10000000ULL | 0x00020000ULL | 0x20000000ULL;
    args.exit_signal = SIGCHLD;

    errno = 0;
    long rc = do_clone3(&args, CLONE3_ARGS_SIZE);
    if (rc == 0)
        _exit(0);
    if (rc > 0) {
        reap_child(rc);
        fprintf(stderr, "FAIL: clone3(combined) succeeded (child %ld)\n", rc);
        exit(1);
    }
    CHECK(rc < 0, "clone3(NEWUSER|NEWNS|NEWPID) should fail");
    CHECK(errno == EPERM, "clone3(NEWUSER|NEWNS|NEWPID) errno should be EPERM");
    printf("  ok: clone3(combined namespace flags) -> EPERM\n");
}

static void test_unreadable_clone_args(void)
{
    /* Pass a bogus pointer that guest_mem_read (process_vm_readv) cannot
     * dereference. The supervisor must fail closed with EPERM rather than
     * falling through to CONTINUE.
     */
    errno = 0;
    /* cppcheck-suppress intToPointerCast */
    long rc = syscall(__NR_clone3, (void *) 1, CLONE3_ARGS_SIZE);
    if (rc == 0)
        _exit(0);
    CHECK(rc < 0, "clone3(bogus pointer) should fail");
    char msg[128];
    snprintf(msg, sizeof(msg),
             "clone3(bogus pointer) errno should be EPERM, got %d", errno);
    CHECK(errno == EPERM, msg);
    printf("  ok: clone3(unreadable clone_args) -> EPERM\n");
}

static void test_valid_clone3_succeeds(void)
{
    /* Sanity: plain fork via clone3 (no namespace flags) must succeed. */
    struct clone3_args args;
    memset(&args, 0, sizeof(args));
    args.exit_signal = SIGCHLD;

    long rc = do_clone3(&args, CLONE3_ARGS_SIZE);
    if (rc == 0)
        _exit(0);
    CHECK(rc > 0, "clone3(plain fork) should succeed and return child pid");
    int status = -1;
    pid_t wp;
    while ((wp = waitpid(rc, &status, 0)) < 0 && errno == EINTR)
        ;
    CHECK(wp == rc, "waitpid should return child pid");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child should exit normally with status 0");
    printf("  ok: clone3(plain fork) -> pid %ld\n", rc);
}

int main(void)
{
    printf("--- clone3 namespace-flag regression tests ---\n");

    test_namespace_flags();
    test_combined_namespace_flags();
    test_unreadable_clone_args();
    test_valid_clone3_succeeds();

    printf("PASS: clone3_test\n");
    return 0;
}
