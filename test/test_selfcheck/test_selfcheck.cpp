// Crypto known-answer self-check: passes on a correct backend, fails on broken ones.
#include <unity.h>
#include <cstring>
#include "fota_selfcheck.h"
#include "host/fota_openssl.h"

using namespace fota;

void setUp() {}
void tearDown() {}

struct AlwaysTrue : IEcdsaP256Verifier {      // a verifier that accepts everything must be caught
    bool verify(const uint8_t*, size_t, const uint8_t*, const uint8_t*, size_t) override { return true; }
};
struct AlwaysFalse : IEcdsaP256Verifier {
    bool verify(const uint8_t*, size_t, const uint8_t*, const uint8_t*, size_t) override { return false; }
};
struct ZeroSha : ISha256 {                      // a hash that ignores its input must be caught
    void begin() override {}
    void update(const uint8_t*, size_t) override {}
    void finish(uint8_t out[32]) override { memset(out, 0, 32); }
};

static void test_real_backend_passes() {
    OpensslSha256 s;
    OpensslEcdsaP256 e;
    TEST_ASSERT_TRUE(cryptoSelfCheck(s, e));
}
static void test_permissive_verifier_fails() {
    OpensslSha256 s;
    AlwaysTrue e;
    TEST_ASSERT_FALSE(cryptoSelfCheck(s, e));
}
static void test_rejecting_verifier_fails() {
    OpensslSha256 s;
    AlwaysFalse e;
    TEST_ASSERT_FALSE(cryptoSelfCheck(s, e));
}
static void test_broken_hash_fails() {
    ZeroSha s;
    OpensslEcdsaP256 e;
    TEST_ASSERT_FALSE(cryptoSelfCheck(s, e));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_real_backend_passes);
    RUN_TEST(test_permissive_verifier_fails);
    RUN_TEST(test_rejecting_verifier_fails);
    RUN_TEST(test_broken_hash_fails);
    return UNITY_END();
}
