/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "kbox/path.h"
#include "test-runner.h"

static void test_is_virtual_proc(void)
{
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/proc"));
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/proc/self"));
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/proc/1/status"));
}

static void test_is_virtual_sys(void)
{
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/sys"));
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/sys/class/net"));
}

static void test_is_virtual_dev(void)
{
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/dev"));
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/dev/null"));
}

static void test_is_not_virtual(void)
{
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/home"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/etc/passwd"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/processor"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/system"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/devices"));
}

static void test_is_tty_like(void)
{
    ASSERT_TRUE(kbox_is_tty_like_path("/dev/tty"));
    ASSERT_TRUE(kbox_is_tty_like_path("/dev/tty0"));
    ASSERT_TRUE(kbox_is_tty_like_path("/dev/pts/0"));
    ASSERT_TRUE(kbox_is_tty_like_path("/dev/console"));
    ASSERT_TRUE(!kbox_is_tty_like_path("/dev/null"));
    ASSERT_TRUE(!kbox_is_tty_like_path("/dev/sda"));
}

static void test_is_loader_runtime(void)
{
    ASSERT_TRUE(kbox_is_loader_runtime_path("/etc/ld.so.cache"));
    ASSERT_TRUE(kbox_is_loader_runtime_path("/etc/ld.so.preload"));
    ASSERT_TRUE(kbox_is_loader_runtime_path("/lib/x86_64-linux-gnu/libc.so.6"));
    ASSERT_TRUE(kbox_is_loader_runtime_path("/usr/lib64/libm.so"));
    ASSERT_TRUE(!kbox_is_loader_runtime_path("/etc/passwd"));
    ASSERT_TRUE(!kbox_is_loader_runtime_path("/home/user/lib/foo"));
}

static void test_normalize_join_absolute(void)
{
    char out[KBOX_MAX_PATH];
    kbox_normalize_join("/base", "/absolute/path", out, sizeof(out));
    ASSERT_STREQ(out, "/absolute/path");
}

static void test_normalize_join_relative(void)
{
    char out[KBOX_MAX_PATH];
    kbox_normalize_join("/base/dir", "sub/file", out, sizeof(out));
    ASSERT_STREQ(out, "/base/dir/sub/file");
}

static void test_normalize_join_dotdot(void)
{
    char out[KBOX_MAX_PATH];
    kbox_normalize_join("/base/dir", "../sibling", out, sizeof(out));
    ASSERT_STREQ(out, "/base/sibling");
}

static void test_normalize_join_dotdot_above_root(void)
{
    char out[KBOX_MAX_PATH];
    kbox_normalize_join("/", "../../escape", out, sizeof(out));
    ASSERT_STREQ(out, "/escape");
}

static void test_normalize_join_dot(void)
{
    char out[KBOX_MAX_PATH];
    kbox_normalize_join("/base", "./file", out, sizeof(out));
    ASSERT_STREQ(out, "/base/file");
}

static void test_normalize_virtual_relative_proc(void)
{
    char out[KBOX_MAX_PATH];
    ASSERT_EQ(
        kbox_normalize_virtual_relative("proc/self/status", out, sizeof(out)),
        1);
    ASSERT_STREQ(out, "/proc/self/status");
}

static void test_normalize_virtual_relative_sys(void)
{
    char out[KBOX_MAX_PATH];
    ASSERT_EQ(kbox_normalize_virtual_relative("sys/class", out, sizeof(out)),
              1);
    ASSERT_STREQ(out, "/sys/class");
}

static void test_normalize_virtual_relative_dev(void)
{
    char out[KBOX_MAX_PATH];
    ASSERT_EQ(kbox_normalize_virtual_relative("dev/null", out, sizeof(out)), 1);
    ASSERT_STREQ(out, "/dev/null");
}

static void test_normalize_virtual_relative_with_dot(void)
{
    char out[KBOX_MAX_PATH];
    ASSERT_EQ(
        kbox_normalize_virtual_relative("./proc/cpuinfo", out, sizeof(out)), 1);
    ASSERT_STREQ(out, "/proc/cpuinfo");
}

static void test_normalize_virtual_relative_not_virtual(void)
{
    char out[KBOX_MAX_PATH];
    ASSERT_EQ(kbox_normalize_virtual_relative("home/user", out, sizeof(out)),
              0);
    ASSERT_EQ(kbox_normalize_virtual_relative("etc/passwd", out, sizeof(out)),
              0);
}

/* Verify that /proc/../etc/passwd normalizes to /etc/passwd (not virtual). */
static void test_normalize_join_virtual_escape(void)
{
    char out[KBOX_MAX_PATH];
    int rc;

    /* /proc/../etc/passwd -> /etc/passwd (escapes /proc) */
    rc = kbox_normalize_join("/", "/proc/../etc/passwd", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/etc/passwd");
    ASSERT_TRUE(!kbox_is_lkl_virtual_path(out));

    /* /sys/../tmp/evil -> /tmp/evil (escapes /sys) */
    rc = kbox_normalize_join("/", "/sys/../tmp/evil", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/tmp/evil");
    ASSERT_TRUE(!kbox_is_lkl_virtual_path(out));

    /* /dev/../../../etc/shadow -> /etc/shadow (clamped at root) */
    rc = kbox_normalize_join("/", "/dev/../../../etc/shadow", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/etc/shadow");
    ASSERT_TRUE(!kbox_is_lkl_virtual_path(out));

    /* /proc/self/status stays virtual after normalization */
    rc = kbox_normalize_join("/", "/proc/self/status", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/proc/self/status");
    ASSERT_TRUE(kbox_is_lkl_virtual_path(out));

    /* /dev/null stays virtual */
    rc = kbox_normalize_join("/", "/dev/null", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/dev/null");
    ASSERT_TRUE(kbox_is_lkl_virtual_path(out));
}

/* Verify that normalize_virtual_relative + normalize_join catches
 * the relative path escape variant: "proc/../etc/passwd".
 */
static void test_normalize_virtual_relative_escape(void)
{
    char out[KBOX_MAX_PATH];
    char norm[KBOX_MAX_PATH];
    int rc;

    /* "proc/../etc/passwd" matches proc/ prefix but escapes after normalization
     */
    rc =
        kbox_normalize_virtual_relative("proc/../etc/passwd", out, sizeof(out));
    ASSERT_EQ(rc, 1);                         /* it DID match proc/ prefix */
    ASSERT_STREQ(out, "/proc/../etc/passwd"); /* raw output still has .. */

    /* After normalization the path escapes /proc */
    rc = kbox_normalize_join("/", out, norm, sizeof(norm));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(norm, "/etc/passwd");
    ASSERT_TRUE(!kbox_is_lkl_virtual_path(norm));

    /* "sys/../../etc/shadow" escapes /sys */
    rc = kbox_normalize_virtual_relative("sys/../../etc/shadow", out,
                                         sizeof(out));
    ASSERT_EQ(rc, 1);
    rc = kbox_normalize_join("/", out, norm, sizeof(norm));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(norm, "/etc/shadow");
    ASSERT_TRUE(!kbox_is_lkl_virtual_path(norm));

    /* "dev/null" stays virtual after normalization */
    rc = kbox_normalize_virtual_relative("dev/null", out, sizeof(out));
    ASSERT_EQ(rc, 1);
    rc = kbox_normalize_join("/", out, norm, sizeof(norm));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(norm, "/dev/null");
    ASSERT_TRUE(kbox_is_lkl_virtual_path(norm));
}

/* Additional edge cases: deeper escapes, dots within virtual, double slashes,
 * false virtual prefixes, empty/root paths.
 */
static void test_normalize_edge_cases(void)
{
    char out[KBOX_MAX_PATH];
    int rc;

    /* Deeper escape: /proc/self/../../etc/shadow -> /etc/shadow */
    rc = kbox_normalize_join("/", "/proc/self/../../etc/shadow", out,
                             sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/etc/shadow");
    ASSERT_TRUE(!kbox_is_lkl_virtual_path(out));

    /* Dots within virtual path: /proc/./self/./status -> /proc/self/status */
    rc = kbox_normalize_join("/", "/proc/./self/./status", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/proc/self/status");
    ASSERT_TRUE(kbox_is_lkl_virtual_path(out));

    /* Double slashes: /proc//self//status -> /proc/self/status */
    rc = kbox_normalize_join("/", "/proc//self//status", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/proc/self/status");
    ASSERT_TRUE(kbox_is_lkl_virtual_path(out));

    /* False virtual prefix: /processor is NOT virtual */
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/processor"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/system"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/devices"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/devious"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/syslog"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/procfs"));

    /* Root path. */
    rc = kbox_normalize_join("/", "/", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/");

    /* Many levels of dotdot clamped at root. */
    rc = kbox_normalize_join("/", "/../../../../../..", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/");

    /* Trailing slash stripped. */
    rc = kbox_normalize_join("/", "/proc/self/", out, sizeof(out));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(out, "/proc/self");
}

/* /proc magic symlink escape detection. */
static void test_proc_escape_self_root(void)
{
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/root"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/root/etc/shadow"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/root/"));
}

static void test_proc_escape_self_cwd(void)
{
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/cwd"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/cwd/some/path"));
}

static void test_proc_escape_self_exe(void)
{
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/exe"));
}

static void test_proc_escape_numeric_pid(void)
{
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/1/root"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/1/root/etc/passwd"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/42/cwd"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/12345/exe"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/999/root/bin/sh"));
}

static void test_proc_escape_thread_self(void)
{
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/thread-self/root"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/thread-self/root/etc/shadow"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/thread-self/cwd"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/thread-self/exe"));
}

static void test_proc_escape_task_tid(void)
{
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/task/1/root"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/task/42/root/etc/passwd"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/1/task/1/cwd"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/123/task/456/exe"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/thread-self/task/1/root"));
    /* Safe task paths */
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/self/task/1/status"));
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/self/task/1/maps"));
    /* Non-numeric tid */
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/self/task/abc/root"));
}

static void test_proc_escape_fd_paths(void)
{
    /* fd, fdinfo, map_files are magic symlink directories. */
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/fd"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/fd/3"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/1/fd/0"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/fdinfo"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/fdinfo/3"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/1/map_files"));
    ASSERT_TRUE(
        kbox_is_proc_escape_path("/proc/self/map_files/7f000000-7f001000"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/thread-self/fd/0"));
    ASSERT_TRUE(kbox_is_proc_escape_path("/proc/self/task/1/fd/0"));
    /* "fds" is not "fd" */
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/self/fds"));
}

static void test_proc_escape_not_escape(void)
{
    /* Safe /proc paths must NOT be flagged. */
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/self/status"));
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/self/maps"));
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/1/status"));
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/cpuinfo"));
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/meminfo"));
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc"));
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/"));
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/self"));
    /* "rootfs" is not "root" */
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/self/rootfs"));
    /* Non-numeric, non-self component */
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/abc/root"));
    ASSERT_TRUE(!kbox_is_proc_escape_path("/proc/self1/root"));
}

/* Verify kbox_is_lkl_virtual_path rejects proc escape paths. */
static void test_virtual_path_rejects_proc_escape(void)
{
    /* These should NOT be treated as virtual (must go through LKL). */
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/self/root"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/self/root/etc/shadow"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/self/cwd"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/self/exe"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/1/root"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/42/cwd/foo"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/self/fd"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/self/fd/3"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/1/fdinfo/0"));
    ASSERT_TRUE(!kbox_is_lkl_virtual_path("/proc/self/map_files/7f-7f"));

    /* Safe /proc paths still treated as virtual. */
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/proc/self/status"));
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/proc/cpuinfo"));
    ASSERT_TRUE(kbox_is_lkl_virtual_path("/proc/1/maps"));
}

static void test_relative_path_has_dotdot(void)
{
    ASSERT_TRUE(kbox_relative_path_has_dotdot(".."));
    ASSERT_TRUE(kbox_relative_path_has_dotdot("../status"));
    ASSERT_TRUE(kbox_relative_path_has_dotdot("proc/../../status"));
    ASSERT_TRUE(kbox_relative_path_has_dotdot("proc/../status"));
    ASSERT_TRUE(kbox_relative_path_has_dotdot("./../status"));

    ASSERT_TRUE(!kbox_relative_path_has_dotdot(""));
    ASSERT_TRUE(!kbox_relative_path_has_dotdot("."));
    ASSERT_TRUE(!kbox_relative_path_has_dotdot("proc/self/status"));
    ASSERT_TRUE(!kbox_relative_path_has_dotdot("proc/..hidden/status"));
    ASSERT_TRUE(!kbox_relative_path_has_dotdot("proc/.../status"));
    ASSERT_TRUE(!kbox_relative_path_has_dotdot("proc/..status"));
}

static void test_relative_proc_escape_path(void)
{
    ASSERT_TRUE(kbox_relative_proc_escape_path("self/root"));
    ASSERT_TRUE(kbox_relative_proc_escape_path("thread-self/cwd"));
    ASSERT_TRUE(kbox_relative_proc_escape_path("123/exe"));
    ASSERT_TRUE(kbox_relative_proc_escape_path("root"));
    ASSERT_TRUE(kbox_relative_proc_escape_path("fd/3"));
    ASSERT_TRUE(kbox_relative_proc_escape_path("task/1/root"));
    ASSERT_TRUE(kbox_relative_proc_escape_path("task/42/fd/7"));
    ASSERT_TRUE(kbox_relative_proc_escape_path("task/9/map_files/7f-8f"));

    ASSERT_TRUE(!kbox_relative_proc_escape_path(""));
    ASSERT_TRUE(!kbox_relative_proc_escape_path("self/status"));
    ASSERT_TRUE(!kbox_relative_proc_escape_path("status"));
    ASSERT_TRUE(!kbox_relative_proc_escape_path("task/1/status"));
    ASSERT_TRUE(!kbox_relative_proc_escape_path("task/abc/root"));
    ASSERT_TRUE(!kbox_relative_proc_escape_path("tasks/1/root"));
}

void test_path_init(void)
{
    TEST_REGISTER(test_is_virtual_proc);
    TEST_REGISTER(test_is_virtual_sys);
    TEST_REGISTER(test_is_virtual_dev);
    TEST_REGISTER(test_is_not_virtual);
    TEST_REGISTER(test_is_tty_like);
    TEST_REGISTER(test_is_loader_runtime);
    TEST_REGISTER(test_normalize_join_absolute);
    TEST_REGISTER(test_normalize_join_relative);
    TEST_REGISTER(test_normalize_join_dotdot);
    TEST_REGISTER(test_normalize_join_dotdot_above_root);
    TEST_REGISTER(test_normalize_join_dot);
    TEST_REGISTER(test_normalize_virtual_relative_proc);
    TEST_REGISTER(test_normalize_virtual_relative_sys);
    TEST_REGISTER(test_normalize_virtual_relative_dev);
    TEST_REGISTER(test_normalize_virtual_relative_with_dot);
    TEST_REGISTER(test_normalize_virtual_relative_not_virtual);
    TEST_REGISTER(test_normalize_join_virtual_escape);
    TEST_REGISTER(test_normalize_virtual_relative_escape);
    TEST_REGISTER(test_normalize_edge_cases);
    TEST_REGISTER(test_proc_escape_self_root);
    TEST_REGISTER(test_proc_escape_self_cwd);
    TEST_REGISTER(test_proc_escape_self_exe);
    TEST_REGISTER(test_proc_escape_numeric_pid);
    TEST_REGISTER(test_proc_escape_thread_self);
    TEST_REGISTER(test_proc_escape_task_tid);
    TEST_REGISTER(test_proc_escape_fd_paths);
    TEST_REGISTER(test_proc_escape_not_escape);
    TEST_REGISTER(test_virtual_path_rejects_proc_escape);
    TEST_REGISTER(test_relative_path_has_dotdot);
    TEST_REGISTER(test_relative_proc_escape_path);
}
