/* SPDX-License-Identifier: MIT */

#include "syscall-nr.h"
#include "test-runner.h"

static void test_x86_64_openat(void)
{
    ASSERT_EQ(SYSNRS_X86_64.openat, 257);
}

static void test_x86_64_read(void)
{
    ASSERT_EQ(SYSNRS_X86_64.read, 0);
}

static void test_x86_64_write(void)
{
    ASSERT_EQ(SYSNRS_X86_64.write, 1);
}

static void test_x86_64_close(void)
{
    ASSERT_EQ(SYSNRS_X86_64.close, 3);
}

static void test_x86_64_execve(void)
{
    ASSERT_EQ(SYSNRS_X86_64.execve, 59);
}

static void test_x86_64_mkdirat_style(void)
{
    ASSERT_TRUE(!SYSNRS_X86_64.mkdirat_style);
}

static void test_generic_openat(void)
{
    ASSERT_EQ(SYSNRS_GENERIC.openat, 56);
}

static void test_generic_read(void)
{
    ASSERT_EQ(SYSNRS_GENERIC.read, 63);
}

static void test_generic_write(void)
{
    ASSERT_EQ(SYSNRS_GENERIC.write, 64);
}

static void test_generic_close(void)
{
    ASSERT_EQ(SYSNRS_GENERIC.close, 57);
}

static void test_generic_mkdirat_style(void)
{
    ASSERT_TRUE(SYSNRS_GENERIC.mkdirat_style);
}

static void test_generic_getdents_unavailable(void)
{
    /* aarch64/generic has no legacy getdents, only getdents64 */
    ASSERT_EQ(SYSNRS_GENERIC.getdents, -1);
    ASSERT_EQ(SYSNRS_GENERIC.getdents64, 61);
}

static void test_host_x86_64_sendmsg(void)
{
    ASSERT_EQ(HOST_NRS_X86_64.sendmsg, 46);
}

static void test_host_aarch64_gettimeofday(void)
{
    ASSERT_EQ(HOST_NRS_GENERIC.gettimeofday, 169);
}

static void test_host_aarch64_no_open(void)
{
    /* aarch64 has no legacy open syscall */
    ASSERT_EQ(HOST_NRS_GENERIC.open, -1);
    ASSERT_EQ(HOST_NRS_GENERIC.stat, -1);
    ASSERT_EQ(HOST_NRS_GENERIC.lstat, -1);
}

static void test_at_fdcwd(void)
{
    ASSERT_EQ(AT_FDCWD_LINUX, -100L);
}

void test_syscall_nr_init(void)
{
    TEST_REGISTER(test_x86_64_openat);
    TEST_REGISTER(test_x86_64_read);
    TEST_REGISTER(test_x86_64_write);
    TEST_REGISTER(test_x86_64_close);
    TEST_REGISTER(test_x86_64_execve);
    TEST_REGISTER(test_x86_64_mkdirat_style);
    TEST_REGISTER(test_generic_openat);
    TEST_REGISTER(test_generic_read);
    TEST_REGISTER(test_generic_write);
    TEST_REGISTER(test_generic_close);
    TEST_REGISTER(test_generic_mkdirat_style);
    TEST_REGISTER(test_generic_getdents_unavailable);
    TEST_REGISTER(test_host_x86_64_sendmsg);
    TEST_REGISTER(test_host_aarch64_gettimeofday);
    TEST_REGISTER(test_host_aarch64_no_open);
    TEST_REGISTER(test_at_fdcwd);
}
