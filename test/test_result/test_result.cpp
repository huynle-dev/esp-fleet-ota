// last_result persistence round trip and corruption handling.
#include <unity.h>
#include <cstring>
#include "fota_fakes.h"
#include "fota_result.h"

using namespace fota;

void setUp() {}
void tearDown() {}

static LastResult make(ResultKind k, Reason r, const char* v) {
    LastResult x;
    x.kind = k; x.reason = r;
    strncpy(x.version, v, sizeof(x.version) - 1);
    return x;
}

static void test_format() {
    char buf[kLastResultTextMax];
    formatLastResult(make(ResultKind::rolled_back, Reason::self_test_failed, "1.4.0"), buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("rolled_back|self_test_failed|1.4.0", buf);
    formatLastResult(make(ResultKind::ok, Reason::none, "1.4.0-rc.1+b5"), buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("ok|none|1.4.0-rc.1+b5", buf);
    formatLastResult(LastResult(), buf, sizeof(buf));
    TEST_ASSERT_EQUAL_STRING("none|none|", buf);
}

static void test_round_trip_all_kinds_and_reasons() {
    for (int k = 0; k <= (int)ResultKind::failed; k++)
        for (int r = 0; r < (int)Reason::_count; r++) {
            LastResult in = make((ResultKind)k, (Reason)r, "12.34.56-beta.7");
            char buf[kLastResultTextMax];
            formatLastResult(in, buf, sizeof(buf));
            LastResult out;
            TEST_ASSERT_TRUE_MESSAGE(parseLastResult(buf, out), buf);
            TEST_ASSERT_EQUAL_INT(k, (int)out.kind);
            TEST_ASSERT_EQUAL_INT(r, (int)out.reason);
            TEST_ASSERT_EQUAL_STRING("12.34.56-beta.7", out.version);
        }
}

static void test_rejects_corrupt() {
    const char* bad[] = {"", "ok", "ok|none", "bogus|none|1.0.0", "ok|bogus|1.0.0", "ok|none|1.0.0|x",
                         "ok|none|not a version", nullptr};
    for (int i = 0; bad[i]; i++) {
        LastResult r = make(ResultKind::ok, Reason::busy, "1.0.0");
        TEST_ASSERT_FALSE_MESSAGE(parseLastResult(bad[i], r), bad[i]);
        TEST_ASSERT_EQUAL_INT((int)ResultKind::none, (int)r.kind);
    }
    LastResult r;
    TEST_ASSERT_FALSE(parseLastResult(nullptr, r));
}

static void test_store_round_trip() {
    fakes::Store s;
    TEST_ASSERT_EQUAL_INT((int)ResultKind::none, (int)loadLastResult(s).kind);
    TEST_ASSERT_TRUE(saveLastResult(s, make(ResultKind::failed, Reason::hash_mismatch, "2.0.0")));
    TEST_ASSERT_EQUAL_STRING("failed|hash_mismatch|2.0.0", s.kv["last_result"].c_str());
    LastResult r = loadLastResult(s);
    TEST_ASSERT_EQUAL_INT((int)ResultKind::failed, (int)r.kind);
    TEST_ASSERT_EQUAL_INT((int)Reason::hash_mismatch, (int)r.reason);
    s.kv["last_result"] = "garbage";
    TEST_ASSERT_EQUAL_INT((int)ResultKind::none, (int)loadLastResult(s).kind);
    s.failPut = true;
    TEST_ASSERT_FALSE(saveLastResult(s, make(ResultKind::ok, Reason::none, "2.0.0")));
}

static void test_kind_names() {
    TEST_ASSERT_EQUAL_STRING("rolled_back", resultKindName(ResultKind::rolled_back));
    TEST_ASSERT_EQUAL_STRING("refused", resultKindName(ResultKind::refused));
}

// Reason codes are persisted and reported by number and name: new ones are appended, existing ones never move.
static void test_reason_codes_append_only() {
    TEST_ASSERT_EQUAL_STRING("none", reasonName((Reason)0));
    TEST_ASSERT_EQUAL_STRING("unknown_key_id", reasonName((Reason)5));
    TEST_ASSERT_EQUAL_STRING("wrong_channel", reasonName((Reason)11));
    TEST_ASSERT_EQUAL_STRING("boot_failed", reasonName((Reason)32));
    TEST_ASSERT_EQUAL_STRING("crypto_self_check_failed", reasonName((Reason)34));
    TEST_ASSERT_EQUAL_STRING("rejected", reasonName((Reason)35));
    Reason r = Reason::none;
    TEST_ASSERT_TRUE(reasonFromName("rejected", r));
    TEST_ASSERT_EQUAL_INT(35, (int)r);
    LastResult x;
    TEST_ASSERT_TRUE(parseLastResult("refused|rejected|1.4.0", x));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_format);
    RUN_TEST(test_round_trip_all_kinds_and_reasons);
    RUN_TEST(test_rejects_corrupt);
    RUN_TEST(test_store_round_trip);
    RUN_TEST(test_kind_names);
    RUN_TEST(test_reason_codes_append_only);
    return UNITY_END();
}
