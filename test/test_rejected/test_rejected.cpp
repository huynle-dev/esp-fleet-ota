// Rejected-version memory (fota_rejected.h): bounded list, oldest evicted, semver comparison, persistence.
#include <unity.h>
#include <cstring>
#include <string>
#include "fota_fakes.h"
#include "fota_rejected.h"

using namespace fota;

void setUp() {}
void tearDown() {}

static std::string text(const RejectedVersions& r) {
    char buf[kRejectedTextMax];
    formatRejected(r, buf, sizeof(buf));
    return buf;
}

static void test_empty_by_default_and_missing_key() {
    RejectedVersions r;
    TEST_ASSERT_EQUAL_UINT8(0, r.count);
    TEST_ASSERT_FALSE(r.contains("1.4.0"));
    TEST_ASSERT_EQUAL_STRING("", text(r).c_str());
    fakes::Store store;
    TEST_ASSERT_EQUAL_UINT8(0, loadRejected(store).count);
}

static void test_add_and_contains_by_version() {
    RejectedVersions r;
    TEST_ASSERT_TRUE(r.add("1.4.0"));
    TEST_ASSERT_TRUE(r.contains("1.4.0"));
    TEST_ASSERT_TRUE(r.contains("1.4.0+rebuild.2"));      // same precedence: build metadata does not bypass it
    TEST_ASSERT_FALSE(r.contains("1.4.1"));
    TEST_ASSERT_FALSE(r.contains("1.4.0-rc.1"));
    TEST_ASSERT_FALSE(r.contains(""));
    TEST_ASSERT_FALSE(r.contains(nullptr));
    TEST_ASSERT_FALSE(r.add("not-a-version"));
    TEST_ASSERT_FALSE(r.add(nullptr));
    TEST_ASSERT_EQUAL_STRING("1.4.0", text(r).c_str());
}

static void test_add_again_moves_to_newest_without_duplicating() {
    RejectedVersions r;
    r.add("1.4.0"); r.add("1.5.0"); r.add("1.4.0");
    TEST_ASSERT_EQUAL_UINT8(2, r.count);
    TEST_ASSERT_EQUAL_STRING("1.5.0,1.4.0", text(r).c_str());
}

static void test_bounded_oldest_evicted() {
    RejectedVersions r;
    for (int i = 0; i < 10; i++) r.add(("1." + std::to_string(i) + ".0").c_str());
    TEST_ASSERT_EQUAL_UINT8(kMaxRejected, r.count);
    TEST_ASSERT_FALSE(r.contains("1.0.0"));
    TEST_ASSERT_FALSE(r.contains("1.1.0"));
    TEST_ASSERT_TRUE(r.contains("1.2.0"));
    TEST_ASSERT_TRUE(r.contains("1.9.0"));
    TEST_ASSERT_EQUAL_STRING("1.2.0,1.3.0,1.4.0,1.5.0,1.6.0,1.7.0,1.8.0,1.9.0", text(r).c_str());
}

static void test_clear_up_to() {
    RejectedVersions r;
    r.add("1.6.0"); r.add("1.4.0"); r.add("1.5.0-rc.1"); r.add("1.5.0");
    TEST_ASSERT_TRUE(r.clearUpTo("1.5.0"));
    TEST_ASSERT_EQUAL_STRING("1.6.0", text(r).c_str());
    TEST_ASSERT_FALSE(r.clearUpTo("1.5.9"));
    TEST_ASSERT_FALSE(r.clearUpTo("garbage"));
    TEST_ASSERT_TRUE(r.clearUpTo("1.6.0"));
    TEST_ASSERT_EQUAL_UINT8(0, r.count);
}

static void test_parse_is_lenient_and_bounded() {
    TEST_ASSERT_EQUAL_STRING("", text(parseRejected(nullptr)).c_str());
    TEST_ASSERT_EQUAL_STRING("", text(parseRejected("")).c_str());
    TEST_ASSERT_EQUAL_STRING("1.4.0,2.0.0-rc.1", text(parseRejected("1.4.0,,x,2.0.0-rc.1,1.4")).c_str());
    TEST_ASSERT_EQUAL_STRING("1.4.0", text(parseRejected("1.4.0,1.4.0")).c_str());
    std::string many;
    for (int i = 0; i < 12; i++) many += (i ? "," : "") + std::to_string(i) + ".0.0";
    RejectedVersions r = parseRejected(many.c_str());
    TEST_ASSERT_EQUAL_UINT8(kMaxRejected, r.count);
    TEST_ASSERT_EQUAL_STRING("4.0.0", r.version[0]);           // the newest 8 are kept
    std::string tooLong(40, '1');
    TEST_ASSERT_EQUAL_STRING("1.0.0", text(parseRejected((tooLong + ",1.0.0").c_str())).c_str());
}

static void test_save_and_load_round_trip() {
    fakes::Store store;
    RejectedVersions r;
    for (size_t i = 0; i < kMaxRejected; i++) r.add(("10.20." + std::to_string(100 + i) + "-rc.12345678901").c_str());
    TEST_ASSERT_TRUE(saveRejected(store, r));
    RejectedVersions back = loadRejected(store);
    TEST_ASSERT_EQUAL_STRING(text(r).c_str(), text(back).c_str());
    TEST_ASSERT_EQUAL_UINT8(kMaxRejected, back.count);
    TEST_ASSERT_TRUE(saveRejected(store, RejectedVersions()));
    TEST_ASSERT_EQUAL_INT(0, (int)store.kv.count("rejected"));
}

static void test_format_respects_cap() {
    RejectedVersions r;
    r.add("1.4.0"); r.add("1.5.0");
    char small[4];
    formatRejected(r, small, sizeof(small));
    TEST_ASSERT_EQUAL_STRING("", small);                         // never a truncated list
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_empty_by_default_and_missing_key);
    RUN_TEST(test_add_and_contains_by_version);
    RUN_TEST(test_add_again_moves_to_newest_without_duplicating);
    RUN_TEST(test_bounded_oldest_evicted);
    RUN_TEST(test_clear_up_to);
    RUN_TEST(test_parse_is_lenient_and_bounded);
    RUN_TEST(test_save_and_load_round_trip);
    RUN_TEST(test_format_respects_cap);
    return UNITY_END();
}
