// Policy checks before download: product, chip, board, channel, https + host allow-list, newer, floor, size.
#include <unity.h>
#include <cstring>
#include "fota_checks.h"

using namespace fota;

static const char* kHosts[] = {"fw.example.com"};
static Manifest M;
static DeviceIdentity D;
static CheckConfig C;

static void setStr(char* dst, size_t cap, const char* s) { strncpy(dst, s, cap - 1); dst[cap - 1] = 0; }
#define SET(field, s) setStr(M.field, sizeof(M.field), s)

void setUp() {
    M = Manifest();
    M.schema = 1;
    SET(product, "example-psu");
    SET(chip, "esp32c3");
    SET(channel, "stable");
    SET(version, "1.4.0");
    SET(min_version, "1.2.0");
    SET(url, "https://fw.example.com/example-psu/1.4.0/esp32c3/firmware.bin");
    M.size = 1000000;
    SET(sha256, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    SET(key_id, "test-only-esp-fleet-ota");
    SET(released_at, "2026-11-22T10:00:00Z");
    D = DeviceIdentity{"example-psu", "esp32c3", "esp32-c3-devkitm-1", "1.3.2"};
    C = CheckConfig{"stable", kHosts, 1};
}
void tearDown() {}

static const char* check(const char* floor = "", uint32_t slot = 0x1E0000) {
    return reasonName(checkManifest(M, D, C, floor, slot));
}

static void test_accepts_good_manifest() { TEST_ASSERT_EQUAL_STRING("none", check()); }

static void test_product_must_match() {
    SET(product, "other-device");
    TEST_ASSERT_EQUAL_STRING("wrong_product", check());
}

static void test_chip_must_match() {
    SET(chip, "esp32s3");
    TEST_ASSERT_EQUAL_STRING("wrong_chip", check());
    setUp();
    D.chip = "esp32s3";
    TEST_ASSERT_EQUAL_STRING("wrong_chip", check());
}

static void test_board_matches_when_manifest_names_one() {
    SET(board, "esp32-c3-devkitm-1");
    TEST_ASSERT_EQUAL_STRING("none", check());
    SET(board, "xiao-esp32c3");
    TEST_ASSERT_EQUAL_STRING("wrong_board", check());
    D.board = "";                                       // a device that does not know its board refuses board builds
    TEST_ASSERT_EQUAL_STRING("wrong_board", check());
    D.board = nullptr;
    TEST_ASSERT_EQUAL_STRING("wrong_board", check());
    SET(board, "");                                     // a manifest without board fits every board
    TEST_ASSERT_EQUAL_STRING("none", check());
}

static void test_channel_must_match() {
    SET(channel, "beta");
    TEST_ASSERT_EQUAL_STRING("wrong_channel", check());
    C.channel = "beta";
    TEST_ASSERT_EQUAL_STRING("none", check());
}

static void test_url_must_be_https_on_allowed_host() {
    SET(url, "http://fw.example.com/x.bin");
    TEST_ASSERT_EQUAL_STRING("url_not_https", check());
    SET(url, "https://evil.example.org/x.bin");
    TEST_ASSERT_EQUAL_STRING("host_not_allowed", check());
    SET(url, "https://fw.example.com.evil.org/x.bin");
    TEST_ASSERT_EQUAL_STRING("host_not_allowed", check());
    SET(url, "https://fw.example.com@evil.org/x.bin");      // userinfo trick
    TEST_ASSERT_EQUAL_STRING("host_not_allowed", check());
    SET(url, "https://evil.org/fw.example.com/x.bin");
    TEST_ASSERT_EQUAL_STRING("host_not_allowed", check());
    SET(url, "https://fw.example.com:8443/x.bin");
    TEST_ASSERT_EQUAL_STRING("host_not_allowed", check());
    SET(url, "https://FW.Example.COM:443/x.bin");
    TEST_ASSERT_EQUAL_STRING("none", check());
    SET(url, "https://fw.example.com");
    TEST_ASSERT_EQUAL_STRING("none", check());
    C.allowed_host_count = 0;                               // empty allow-list refuses everything
    TEST_ASSERT_EQUAL_STRING("host_not_allowed", check());
}

static void test_url_host_extraction() {
    char h[64];
    TEST_ASSERT_TRUE(httpsUrlHost("https://fw.example.com/a/b", h, sizeof(h)));
    TEST_ASSERT_EQUAL_STRING("fw.example.com", h);
    TEST_ASSERT_TRUE(httpsUrlHost("https://fw.example.com?x=1", h, sizeof(h)));
    TEST_ASSERT_EQUAL_STRING("fw.example.com", h);
    TEST_ASSERT_FALSE(httpsUrlHost("https:///x", h, sizeof(h)));
    TEST_ASSERT_FALSE(httpsUrlHost("https://:443/x", h, sizeof(h)));
    TEST_ASSERT_FALSE(httpsUrlHost("ftp://fw.example.com/x", h, sizeof(h)));
    TEST_ASSERT_FALSE(httpsUrlHost("https://fw.example.com/x", h, 5));   // does not fit
    TEST_ASSERT_FALSE(httpsUrlHost(nullptr, h, sizeof(h)));
}

static void test_must_be_newer_than_running() {
    SET(version, "1.3.2");
    TEST_ASSERT_EQUAL_STRING("not_newer", check());
    SET(version, "1.3.1");
    SET(min_version, "");
    TEST_ASSERT_EQUAL_STRING("not_newer", check());
    SET(version, "1.3.2-rc.1");                             // prerelease of the running version is older
    TEST_ASSERT_EQUAL_STRING("not_newer", check());
    D.running_version = "1.4.0-rc.2";
    SET(version, "1.4.0");                                  // release after its prerelease is newer
    TEST_ASSERT_EQUAL_STRING("none", check());
    D.running_version = "garbage";
    TEST_ASSERT_EQUAL_STRING("running_version_invalid", check());
}

static void test_anti_downgrade_floor() {
    TEST_ASSERT_EQUAL_STRING("none", check("1.4.0"));
    TEST_ASSERT_EQUAL_STRING("below_floor", check("1.4.1"));
    TEST_ASSERT_EQUAL_STRING("below_floor", check("2.0.0"));
    TEST_ASSERT_EQUAL_STRING("none", check(nullptr));
    TEST_ASSERT_EQUAL_STRING("none", check("garbage"));     // an unreadable floor is ignored, version > running still holds
}

static void test_size_must_fit_spare_slot() {
    M.size = 0x1E0000;
    TEST_ASSERT_EQUAL_STRING("none", check("", 0x1E0000));
    M.size = 0x1E0001;
    TEST_ASSERT_EQUAL_STRING("too_large", check("", 0x1E0000));
    TEST_ASSERT_EQUAL_STRING("too_large", check("", 0));    // no spare slot
}

static void test_next_floor_is_max() {
    char out[33];
    nextFloor("", M, out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("1.2.0", out);
    nextFloor("1.3.0", M, out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("1.3.0", out);
    nextFloor("1.0.0", M, out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("1.2.0", out);
    SET(min_version, "");
    nextFloor("1.0.0", M, out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("1.0.0", out);
    nextFloor(nullptr, M, out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("", out);
    nextFloor("junk", M, out, sizeof(out));                 // a corrupt floor is replaced, not kept
    TEST_ASSERT_EQUAL_STRING("", out);
}

static void test_reason_names_round_trip() {
    for (int i = 0; i < (int)Reason::_count; i++) {
        Reason r;
        const char* n = reasonName((Reason)i);
        TEST_ASSERT_TRUE_MESSAGE(reasonFromName(n, r), n);
        TEST_ASSERT_EQUAL_INT(i, (int)r);
        TEST_ASSERT_NOT_EQUAL(0, strcmp(n, "unknown"));
    }
    Reason r;
    TEST_ASSERT_FALSE(reasonFromName("nope", r));
    TEST_ASSERT_FALSE(reasonFromName(nullptr, r));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_accepts_good_manifest);
    RUN_TEST(test_product_must_match);
    RUN_TEST(test_chip_must_match);
    RUN_TEST(test_board_matches_when_manifest_names_one);
    RUN_TEST(test_channel_must_match);
    RUN_TEST(test_url_must_be_https_on_allowed_host);
    RUN_TEST(test_url_host_extraction);
    RUN_TEST(test_must_be_newer_than_running);
    RUN_TEST(test_anti_downgrade_floor);
    RUN_TEST(test_size_must_fit_spare_slot);
    RUN_TEST(test_next_floor_is_max);
    RUN_TEST(test_reason_names_round_trip);
    return UNITY_END();
}
