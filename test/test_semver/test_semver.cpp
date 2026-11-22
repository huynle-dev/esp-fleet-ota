// Semver parsing and precedence, the basis of "version > running" and the anti-downgrade floor.
#include <unity.h>
#include "fota_semver.h"

using namespace fota;

void setUp() {}
void tearDown() {}

static int cmp(const char* a, const char* b) {
    int c = 99;
    TEST_ASSERT_TRUE_MESSAGE(compareVersions(a, b, c), a);
    return c;
}

static void test_parses_plain_version() {
    SemVer v;
    TEST_ASSERT_TRUE(parseSemVer("1.22.333", v));
    TEST_ASSERT_EQUAL_UINT32(1, v.major);
    TEST_ASSERT_EQUAL_UINT32(22, v.minor);
    TEST_ASSERT_EQUAL_UINT32(333, v.patch);
    TEST_ASSERT_EQUAL_STRING("", v.pre);
}

static void test_parses_prerelease_and_build() {
    SemVer v;
    TEST_ASSERT_TRUE(parseSemVer("1.0.0-rc.1+build.5", v));
    TEST_ASSERT_EQUAL_STRING("rc.1", v.pre);
    TEST_ASSERT_TRUE(parseSemVer("1.0.0+exp.sha.5114f85", v));
    TEST_ASSERT_EQUAL_STRING("", v.pre);
    TEST_ASSERT_TRUE(parseSemVer("1.0.0-x-y-z.--", v));
}

static void test_rejects_invalid() {
    SemVer v;
    const char* bad[] = {"", "1", "1.2", "1.2.3.4", "v1.2.3", " 1.2.3", "1.2.3 ", "01.2.3", "1.02.3", "1.2.03",
                         "1.2.3-", "1.2.3-01", "1.2.3-a..b", "1.2.3-a_b", "1.2.3+", "1.2.3+a..b", "1.2.-3",
                         "4294967296.0.0", "1.2.3-α", "a.b.c", "1..3", "1.2.3-rc.1+", nullptr};
    for (int i = 0; bad[i]; i++) TEST_ASSERT_FALSE_MESSAGE(parseSemVer(bad[i], v), bad[i]);
    TEST_ASSERT_FALSE(parseSemVer(nullptr, v));
    TEST_ASSERT_TRUE(parseSemVer("4294967295.0.0", v));
    TEST_ASSERT_TRUE(parseSemVer("0.0.0", v));
    TEST_ASSERT_TRUE(parseSemVer("1.2.3-0", v));
    TEST_ASSERT_TRUE(parseSemVer("1.2.3-0a", v));        // alphanumeric identifiers may start with 0
}

static void test_rejects_too_long() {
    SemVer v;
    char s[80] = "1.0.0-";
    for (int i = 6; i < 70; i++) s[i] = 'a';
    s[70] = 0;
    TEST_ASSERT_FALSE(parseSemVer(s, v));
}

static void test_numeric_precedence() {
    TEST_ASSERT_TRUE(cmp("1.0.0", "2.0.0") < 0);
    TEST_ASSERT_TRUE(cmp("2.0.0", "2.1.0") < 0);
    TEST_ASSERT_TRUE(cmp("2.1.0", "2.1.1") < 0);
    TEST_ASSERT_TRUE(cmp("1.10.0", "1.9.0") > 0);    // numeric, not lexical
    TEST_ASSERT_EQUAL_INT(0, cmp("1.2.3", "1.2.3"));
}

static void test_prerelease_precedence_spec_example() {
    // semver.org §11: 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta < 1.0.0-beta.2 < 1.0.0-beta.11
    //                  < 1.0.0-rc.1 < 1.0.0
    const char* order[] = {"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
                           "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"};
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) {
            int c = cmp(order[i], order[j]);
            if (i < j) TEST_ASSERT_TRUE_MESSAGE(c < 0, order[i]);
            if (i == j) TEST_ASSERT_EQUAL_INT(0, c);
            if (i > j) TEST_ASSERT_TRUE_MESSAGE(c > 0, order[i]);
        }
}

static void test_numeric_identifiers_lower_than_alphanumeric() {
    TEST_ASSERT_TRUE(cmp("1.0.0-1", "1.0.0-a") < 0);
    TEST_ASSERT_TRUE(cmp("1.0.0-999", "1.0.0-a") < 0);
    TEST_ASSERT_TRUE(cmp("1.0.0-0a", "1.0.0-1") > 0);  // "0a" is alphanumeric
}

static void test_build_metadata_ignored() {
    TEST_ASSERT_EQUAL_INT(0, cmp("1.0.0+a", "1.0.0+b"));
    TEST_ASSERT_EQUAL_INT(0, cmp("1.0.0-rc.1+a", "1.0.0-rc.1"));
}

static void test_compare_rejects_invalid() {
    int c = 5;
    TEST_ASSERT_FALSE(compareVersions("1.0", "1.0.0", c));
    TEST_ASSERT_FALSE(compareVersions("1.0.0", "x", c));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_parses_plain_version);
    RUN_TEST(test_parses_prerelease_and_build);
    RUN_TEST(test_rejects_invalid);
    RUN_TEST(test_rejects_too_long);
    RUN_TEST(test_numeric_precedence);
    RUN_TEST(test_prerelease_precedence_spec_example);
    RUN_TEST(test_numeric_identifiers_lower_than_alphanumeric);
    RUN_TEST(test_build_metadata_ignored);
    RUN_TEST(test_compare_rejects_invalid);
    return UNITY_END();
}
