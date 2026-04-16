/* SPDX-License-Identifier: MIT */
#include <string.h>

#include "kbox/mount.h"
#include "test-runner.h"

static void fill_char(char *buf, size_t len, char c)
{
    memset(buf, c, len);
    buf[len] = '\0';
}

/* --- kbox_parse_bind_spec tests --- */

static void test_parse_basic(void)
{
    struct kbox_bind_spec spec;
    ASSERT_EQ(kbox_parse_bind_spec("/host/dir:/guest/dir", &spec), 0);
    ASSERT_STREQ(spec.source, "/host/dir");
    ASSERT_STREQ(spec.target, "/guest/dir");
}

static void test_parse_null_spec(void)
{
    struct kbox_bind_spec spec;
    ASSERT_EQ(kbox_parse_bind_spec(NULL, &spec), -1);
}

static void test_parse_null_out(void)
{
    ASSERT_EQ(kbox_parse_bind_spec("/a:/b", NULL), -1);
}

static void test_parse_no_colon(void)
{
    struct kbox_bind_spec spec;
    ASSERT_EQ(kbox_parse_bind_spec("/no/colon/here", &spec), -1);
}

static void test_parse_empty_source(void)
{
    struct kbox_bind_spec spec;
    ASSERT_EQ(kbox_parse_bind_spec(":/guest", &spec), -1);
}

static void test_parse_empty_target(void)
{
    struct kbox_bind_spec spec;
    ASSERT_EQ(kbox_parse_bind_spec("/host:", &spec), -1);
}

static void test_parse_colon_in_middle(void)
{
    struct kbox_bind_spec spec;
    ASSERT_EQ(kbox_parse_bind_spec("a:b", &spec), 0);
    ASSERT_STREQ(spec.source, "a");
    ASSERT_STREQ(spec.target, "b");
}

static void test_parse_multiple_colons(void)
{
    struct kbox_bind_spec spec;
    ASSERT_EQ(kbox_parse_bind_spec("/a:/b:c", &spec), 0);
    ASSERT_STREQ(spec.source, "/a");
    ASSERT_STREQ(spec.target, "/b:c");
}

static void test_parse_source_too_long(void)
{
    struct kbox_bind_spec spec;
    /* source component >= sizeof(spec.source) must be rejected */
    char big[4096 + 1 + 2]; /* 4096 'x' + ':' + '/' + NUL */
    fill_char(big, 4096, 'x');
    big[4096] = ':';
    big[4097] = '/';
    big[4098] = '\0';
    ASSERT_EQ(kbox_parse_bind_spec(big, &spec), -1);
}

static void test_parse_target_too_long(void)
{
    struct kbox_bind_spec spec;
    /* target component >= sizeof(spec.target) must be rejected */
    char big[2 + 4096 + 1]; /* '/' + ':' + 4096 'y' + NUL */
    big[0] = '/';
    big[1] = ':';
    fill_char(big + 2, 4096, 'y');
    ASSERT_EQ(kbox_parse_bind_spec(big, &spec), -1);
}

void test_mount_init(void)
{
    TEST_REGISTER(test_parse_basic);
    TEST_REGISTER(test_parse_null_spec);
    TEST_REGISTER(test_parse_null_out);
    TEST_REGISTER(test_parse_no_colon);
    TEST_REGISTER(test_parse_empty_source);
    TEST_REGISTER(test_parse_empty_target);
    TEST_REGISTER(test_parse_colon_in_middle);
    TEST_REGISTER(test_parse_multiple_colons);
    TEST_REGISTER(test_parse_source_too_long);
    TEST_REGISTER(test_parse_target_too_long);
}
