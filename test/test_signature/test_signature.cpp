// Manifest signature verification with the real crypto (host backend: OpenSSL) and TEST-ONLY keys.
#include <unity.h>
#include <cstring>
#include <string>
#include "fota_signature.h"
#include "fota_test_vectors.h"
#include "host/fota_openssl.h"

using namespace fota;

static OpensslSha256 gSha;
static OpensslEcdsaP256 gEcdsa;

// Shape of a real device table (docs/release.md): the OpenBao transit key, one entry per key version N that is still
// trusted, plus a break-glass key (YubiKey) that signs bare base64 DER and so has no N (0).
static const TrustedKey kKeys[] = {
    {"test-only-fleet", 1, (const uint8_t*)TEST_ONLY_KEY_A_PEM, sizeof(TEST_ONLY_KEY_A_PEM) - 1},
    {"test-only-fleet", 2, (const uint8_t*)TEST_ONLY_KEY_B_PEM, sizeof(TEST_ONLY_KEY_B_PEM) - 1},
    {"test-only-breakglass", 0, TEST_ONLY_KEY_A_DER, sizeof(TEST_ONLY_KEY_A_DER)},
    {"test-only-p384", 0, (const uint8_t*)TEST_ONLY_KEY_P384_PEM, sizeof(TEST_ONLY_KEY_P384_PEM) - 1},
};
static const size_t kKeyCount = sizeof(kKeys) / sizeof(kKeys[0]);

void setUp() {}
void tearDown() {}

static SigError verify(const std::string& manifest, const char* keyId, const std::string& sig) {
    return verifyManifestSignature(manifest.data(), manifest.size(), keyId, sig.data(), sig.size(), kKeys, kKeyCount,
                                   gSha, gEcdsa);
}
static const std::string M(TEST_ONLY_MANIFEST);

#define EXPECT_SIG(err, got) TEST_ASSERT_EQUAL_STRING(sigErrorName(err), sigErrorName(got))

static const char* FLEET = "test-only-fleet";
static const char* BREAKGLASS = "test-only-breakglass";

static void test_openbao_signature_valid() { EXPECT_SIG(SigError::Ok, verify(M, FLEET, TEST_ONLY_SIG_A_VAULT_V1)); }

static void test_openbao_rotated_key_version_valid() {
    EXPECT_SIG(SigError::Ok, verify(M, FLEET, TEST_ONLY_SIG_B_VAULT_V2));
    // v2 maps to key B: a key-A signature labelled v2 does not verify
    EXPECT_SIG(SigError::Invalid, verify(M, FLEET, TEST_ONLY_SIG_A_VAULT_V2));
}

static void test_openbao_unknown_key_version_refused() {
    EXPECT_SIG(SigError::KeyVersionMismatch, verify(M, FLEET, std::string("vault:v3:") + TEST_ONLY_SIG_A_B64));
    EXPECT_SIG(SigError::KeyVersionMismatch, verify(M, BREAKGLASS, TEST_ONLY_SIG_A_VAULT_V1));   // no N for this key
}

static void test_breakglass_bare_base64_valid() {
    EXPECT_SIG(SigError::Ok, verify(M, BREAKGLASS, TEST_ONLY_SIG_A_B64));                         // DER public key
}

static void test_bare_signature_refused_for_vault_only_key() {
    // the fleet key has no N-less entry, so a bare signature (even a genuine one) is refused: N must be stated
    EXPECT_SIG(SigError::KeyVersionMismatch, verify(M, FLEET, TEST_ONLY_SIG_A_B64));
}

static void test_signature_file_whitespace_tolerated() {
    EXPECT_SIG(SigError::Ok, verify(M, FLEET, std::string(TEST_ONLY_SIG_A_VAULT_V1) + "\n"));
    EXPECT_SIG(SigError::Ok, verify(M, FLEET, std::string(TEST_ONLY_SIG_A_VAULT_V1) + " \r\n"));
    EXPECT_SIG(SigError::Ok, verify(M, BREAKGLASS, std::string(TEST_ONLY_SIG_A_B64) + "\n\n"));
    EXPECT_SIG(SigError::Ok, verify(M, BREAKGLASS, std::string("\t") + TEST_ONLY_SIG_A_B64));
}

static void test_every_tampered_manifest_byte_fails() {
    for (size_t i = 0; i < M.size(); i++) {
        std::string t = M;
        t[i] ^= 0x01;
        TEST_ASSERT_EQUAL_STRING_MESSAGE("Invalid", sigErrorName(verify(t, FLEET, TEST_ONLY_SIG_A_VAULT_V1)),
                                         std::to_string(i).c_str());
    }
}

static void test_any_manifest_byte_change_fails_even_whitespace() {
    EXPECT_SIG(SigError::Invalid, verify(M + "\n", FLEET, TEST_ONLY_SIG_A_VAULT_V1));   // trailing newline
    EXPECT_SIG(SigError::Invalid, verify(M + " ", FLEET, TEST_ONLY_SIG_A_VAULT_V1));
    EXPECT_SIG(SigError::Invalid, verify("\n" + M, BREAKGLASS, TEST_ONLY_SIG_A_B64));
    EXPECT_SIG(SigError::Invalid, verify(M.substr(0, M.size() - 1), FLEET, TEST_ONLY_SIG_A_VAULT_V1));
}

static void test_tampered_signature_fails() {
    std::string s(TEST_ONLY_SIG_A_VAULT_V1);
    s[30] = s[30] == 'A' ? 'B' : 'A';
    EXPECT_SIG(SigError::Invalid, verify(M, FLEET, s));
}

static void test_wrong_key_fails() {
    EXPECT_SIG(SigError::Invalid, verify(M, FLEET, std::string("vault:v1:") + TEST_ONLY_SIG_B_B64));
    EXPECT_SIG(SigError::Invalid, verify(M, BREAKGLASS, TEST_ONLY_SIG_B_B64));
}

static void test_non_p256_key_refused() { EXPECT_SIG(SigError::Invalid, verify(M, "test-only-p384", TEST_ONLY_SIG_A_B64)); }

static void test_unknown_key_id_refused() {
    EXPECT_SIG(SigError::UnknownKeyId, verify(M, "someone-else", TEST_ONLY_SIG_A_VAULT_V1));
    EXPECT_SIG(SigError::UnknownKeyId, verify(M, "", TEST_ONLY_SIG_A_B64));
    EXPECT_SIG(SigError::UnknownKeyId, verify(M, nullptr, TEST_ONLY_SIG_A_B64));
    TEST_ASSERT_EQUAL_STRING(sigErrorName(SigError::UnknownKeyId),
                             sigErrorName(verifyManifestSignature(M.data(), M.size(), FLEET, TEST_ONLY_SIG_A_VAULT_V1,
                                                                  strlen(TEST_ONLY_SIG_A_VAULT_V1), nullptr, 0, gSha, gEcdsa)));
}

static void test_find_trusted_key_by_id_and_version() {
    TEST_ASSERT_EQUAL_PTR(&kKeys[0], findTrustedKey(FLEET, 1, kKeys, kKeyCount));
    TEST_ASSERT_EQUAL_PTR(&kKeys[1], findTrustedKey(FLEET, 2, kKeys, kKeyCount));
    TEST_ASSERT_NULL(findTrustedKey(FLEET, 0, kKeys, kKeyCount));
    TEST_ASSERT_EQUAL_PTR(&kKeys[2], findTrustedKey(BREAKGLASS, 0, kKeys, kKeyCount));
    TEST_ASSERT_NULL(findTrustedKey("nope", 0, kKeys, kKeyCount));
}

static void test_bad_formats() {
    const char* bad[] = {"", "\n", "not base64!", "vault:", "vault:v:abc=", "vault:v1:", "vault:vx:" , "vault:v01:QQ==",
                         "vault:v1:@@@@", "vault:v0:QQ==", "QQ=", "QQ", "Q===", "vault:v1:QQ==:x", "VAULT:v1:QQ==", nullptr};
    for (int i = 0; bad[i]; i++)
        TEST_ASSERT_EQUAL_STRING_MESSAGE("BadFormat", sigErrorName(verify(M, FLEET, bad[i])), bad[i]);
    EXPECT_SIG(SigError::BadFormat, verify(M, FLEET, std::string(kMaxSignatureText + 1, 'A')));
    EXPECT_SIG(SigError::BadFormat, verifyManifestSignature(M.data(), M.size(), FLEET, nullptr, 0, kKeys,
                                                            kKeyCount, gSha, gEcdsa));
    EXPECT_SIG(SigError::BadFormat, verify(M, FLEET, std::string("vault:v1: ") + TEST_ONLY_SIG_A_B64));  // inner space
    // valid base64 but not a DER signature: verifies as Invalid, not Ok
    EXPECT_SIG(SigError::Invalid, verify(M, BREAKGLASS, "QUJDRA=="));
}

static void test_base64_decoder() {
    uint8_t out[8];
    size_t n = 0;
    TEST_ASSERT_TRUE(base64Decode("TWFu", 4, out, sizeof(out), n));
    TEST_ASSERT_EQUAL_size_t(3, n);
    TEST_ASSERT_EQUAL_MEMORY("Man", out, 3);
    TEST_ASSERT_TRUE(base64Decode("TWE=", 4, out, sizeof(out), n));
    TEST_ASSERT_EQUAL_size_t(2, n);
    TEST_ASSERT_TRUE(base64Decode("TQ==", 4, out, sizeof(out), n));
    TEST_ASSERT_EQUAL_size_t(1, n);
    TEST_ASSERT_TRUE(base64Decode("", 0, out, sizeof(out), n));
    TEST_ASSERT_EQUAL_size_t(0, n);
    TEST_ASSERT_FALSE(base64Decode("TWFu", 3, out, sizeof(out), n));
    TEST_ASSERT_FALSE(base64Decode("T=Fu", 4, out, sizeof(out), n));
    TEST_ASSERT_FALSE(base64Decode("TWFuTWFuTWFu", 12, out, sizeof(out), n));   // 9 bytes > cap 8
    TEST_ASSERT_FALSE(base64Decode("TR==", 4, out, sizeof(out), n));             // non-canonical trailing bits
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_openbao_signature_valid);
    RUN_TEST(test_openbao_rotated_key_version_valid);
    RUN_TEST(test_openbao_unknown_key_version_refused);
    RUN_TEST(test_breakglass_bare_base64_valid);
    RUN_TEST(test_bare_signature_refused_for_vault_only_key);
    RUN_TEST(test_signature_file_whitespace_tolerated);
    RUN_TEST(test_every_tampered_manifest_byte_fails);
    RUN_TEST(test_any_manifest_byte_change_fails_even_whitespace);
    RUN_TEST(test_tampered_signature_fails);
    RUN_TEST(test_wrong_key_fails);
    RUN_TEST(test_non_p256_key_refused);
    RUN_TEST(test_unknown_key_id_refused);
    RUN_TEST(test_find_trusted_key_by_id_and_version);
    RUN_TEST(test_bad_formats);
    RUN_TEST(test_base64_decoder);
    return UNITY_END();
}
