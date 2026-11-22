// Strict manifest parsing: the parser sees untrusted bytes before the signature is checked.
#include <unity.h>
#include <cstring>
#include <string>
#include "fota_manifest.h"
#include "fota_test_vectors.h"

using namespace fota;

void setUp() {}
void tearDown() {}

static const char* kSha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static std::string good() {
    return std::string("{\"schema\":1,\"product\":\"example-psu\",\"chip\":\"esp32c3\",\"board\":\"esp32-c3-devkitm-1\","
                       "\"channel\":\"stable\",\"version\":\"1.4.0\",\"min_version\":\"1.2.0\","
                       "\"url\":\"https://fw.example.org/zk/1.4.0.bin\",\"size\":1234567,\"sha256\":\"") +
           kSha + "\",\"key_id\":\"fleet-2026\",\"released_at\":\"2026-11-22T10:00:00Z\"}";
}

// Replace the value text of `key` (including quotes for strings) in good() with `raw` (raw JSON), or remove the
// member when raw is null.
static std::string with(const char* key, const char* raw) {
    std::string s = good();
    std::string k = std::string("\"") + key + "\":";
    size_t p = s.find(k);
    TEST_ASSERT_TRUE_MESSAGE(p != std::string::npos, key);
    size_t v = p + k.size();
    size_t e = v;
    if (s[v] == '"') { e = s.find('"', v + 1) + 1; } else { while (s[e] != ',' && s[e] != '}') e++; }
    if (raw) return s.substr(0, v) + raw + s.substr(e);
    // remove member and one adjacent comma
    if (s[e] == ',') return s.substr(0, p) + s.substr(e + 1);
    return s.substr(0, p - 1) + s.substr(e);
}

static ManifestError parse(const std::string& s, Manifest& m, const char** f = nullptr) {
    return parseManifest(s.data(), s.size(), m, f);
}
static ManifestError parse(const std::string& s) { Manifest m; return parse(s, m); }

#define EXPECT_ERR(err, s) TEST_ASSERT_EQUAL_STRING_MESSAGE(manifestErrorName(err), manifestErrorName(parse(s)), (s).c_str())

static void test_parses_full_manifest() {
    Manifest m;
    TEST_ASSERT_EQUAL_STRING("Ok", manifestErrorName(parse(good(), m)));
    TEST_ASSERT_EQUAL_UINT32(1, m.schema);
    TEST_ASSERT_EQUAL_STRING("example-psu", m.product);
    TEST_ASSERT_EQUAL_STRING("esp32c3", m.chip);
    TEST_ASSERT_EQUAL_STRING("esp32-c3-devkitm-1", m.board);
    TEST_ASSERT_EQUAL_STRING("stable", m.channel);
    TEST_ASSERT_EQUAL_STRING("1.4.0", m.version);
    TEST_ASSERT_EQUAL_STRING("1.2.0", m.min_version);
    TEST_ASSERT_EQUAL_STRING("https://fw.example.org/zk/1.4.0.bin", m.url);
    TEST_ASSERT_EQUAL_UINT32(1234567, m.size);
    TEST_ASSERT_EQUAL_STRING(kSha, m.sha256);
    TEST_ASSERT_EQUAL_STRING("fleet-2026", m.key_id);
    TEST_ASSERT_EQUAL_STRING("2026-11-22T10:00:00Z", m.released_at);
    TEST_ASSERT_TRUE(m.hasBoard());
    TEST_ASSERT_TRUE(m.hasMinVersion());
}

static void test_optional_fields_may_be_absent() {
    Manifest m;
    std::string s = with("min_version", nullptr);
    s = s.replace(s.find("\"board\""), strlen("\"board\":\"esp32-c3-devkitm-1\","), "");
    TEST_ASSERT_EQUAL_STRING("Ok", manifestErrorName(parse(s, m)));
    TEST_ASSERT_FALSE(m.hasBoard());
    TEST_ASSERT_FALSE(m.hasMinVersion());
}

static void test_whitespace_and_order_are_free() {
    std::string s = std::string(" {\n \"key_id\" : \"k\" ,\t\"schema\":1,\"chip\":\"esp32s3\",\"product\":\"p\",") +
                    "\"channel\":\"beta\",\"version\":\"2.0.0-rc.1\",\"url\":\"https://h/x\",\"size\":1,\"sha256\":\"" +
                    kSha + "\",\"released_at\":\"2026-01-01T00:00:00Z\"}\r\n";
    Manifest m;
    TEST_ASSERT_EQUAL_STRING("Ok", manifestErrorName(parse(s, m)));
    TEST_ASSERT_EQUAL_STRING("beta", m.channel);
    TEST_ASSERT_EQUAL_STRING("2.0.0-rc.1", m.version);
}

static void test_unknown_or_unsupported_schema() {
    EXPECT_ERR(ManifestError::UnsupportedSchema, with("schema", "2"));
    EXPECT_ERR(ManifestError::UnsupportedSchema, with("schema", "0"));
    EXPECT_ERR(ManifestError::BadType, with("schema", "\"1\""));
    EXPECT_ERR(ManifestError::BadType, with("schema", "1.0"));
    EXPECT_ERR(ManifestError::MissingField, with("schema", nullptr));
}

static void test_each_required_field_missing() {
    const char* req[] = {"product", "chip", "channel", "version", "url", "size", "sha256", "key_id", "released_at", nullptr};
    for (int i = 0; req[i]; i++) {
        Manifest m;
        const char* f = nullptr;
        TEST_ASSERT_EQUAL_STRING_MESSAGE("MissingField", manifestErrorName(parse(with(req[i], nullptr), m, &f)), req[i]);
        TEST_ASSERT_EQUAL_STRING(req[i], f);
    }
}

static void test_bad_types() {
    EXPECT_ERR(ManifestError::BadType, with("size", "\"1234\""));
    EXPECT_ERR(ManifestError::BadType, with("size", "1.5"));
    EXPECT_ERR(ManifestError::BadType, with("size", "1e3"));
    EXPECT_ERR(ManifestError::BadType, with("size", "-1"));
    EXPECT_ERR(ManifestError::BadType, with("size", "true"));
    EXPECT_ERR(ManifestError::BadType, with("size", "null"));
    EXPECT_ERR(ManifestError::BadType, with("product", "7"));
    EXPECT_ERR(ManifestError::BadType, with("version", "null"));
    EXPECT_ERR(ManifestError::Nested, with("product", "{\"a\":1}"));
    EXPECT_ERR(ManifestError::Nested, with("url", "[\"https://x/y\"]"));
}

static void test_bad_values() {
    EXPECT_ERR(ManifestError::BadValue, with("size", "0"));
    EXPECT_ERR(ManifestError::BadValue, with("size", "2147483648"));
    EXPECT_ERR(ManifestError::BadValue, with("size", "99999999999999999999999"));
    EXPECT_ERR(ManifestError::BadValue, with("size", "0123"));
    EXPECT_ERR(ManifestError::BadValue, with("channel", "\"nightly\""));
    EXPECT_ERR(ManifestError::BadValue, with("version", "\"1.4\""));
    EXPECT_ERR(ManifestError::BadValue, with("min_version", "\"x\""));
    EXPECT_ERR(ManifestError::BadValue, with("min_version", "\"1.5.0\""));   // floor above the version itself
    EXPECT_ERR(ManifestError::BadValue, with("sha256", "\"abc\""));
    std::string upper(kSha);
    for (auto& c : upper) c = (char)toupper(c);
    EXPECT_ERR(ManifestError::BadValue, with("sha256", ("\"" + upper + "\"").c_str()));
    EXPECT_ERR(ManifestError::BadValue, with("url", "\"http://fw.example.org/x.bin\""));
    EXPECT_ERR(ManifestError::BadValue, with("url", "\"https://fw.example.org/a b\""));
    EXPECT_ERR(ManifestError::BadValue, with("chip", "\"ESP32C3\""));
    EXPECT_ERR(ManifestError::BadValue, with("chip", "\"\""));
    EXPECT_ERR(ManifestError::BadValue, with("product", "\"Zk Psu\""));
    EXPECT_ERR(ManifestError::BadValue, with("key_id", "\"\""));
    EXPECT_ERR(ManifestError::BadValue, with("released_at", "\"yesterday\""));
    EXPECT_ERR(ManifestError::BadValue, with("released_at", "\"2026-11-22 10:00:00Z\""));
}

static void test_field_too_long() {
    std::string longProduct = "\"" + std::string(33, 'a') + "\"";
    EXPECT_ERR(ManifestError::FieldTooLong, with("product", longProduct.c_str()));
    std::string longUrl = "\"https://h/" + std::string(260, 'a') + "\"";
    EXPECT_ERR(ManifestError::FieldTooLong, with("url", longUrl.c_str()));
}

static void test_oversize_document() {
    std::string s = good();
    s.insert(1, std::string(kMaxManifestBytes, ' '));
    EXPECT_ERR(ManifestError::TooLarge, s);
}

static void test_duplicate_and_unknown_keys() {
    std::string s = good();
    s.insert(1, "\"chip\":\"esp32s3\",");
    EXPECT_ERR(ManifestError::DuplicateKey, s);
    std::string u = good();
    u.insert(1, "\"extra\":\"x\",");
    EXPECT_ERR(ManifestError::UnknownKey, u);
}

static void test_syntax_errors() {
    EXPECT_ERR(ManifestError::NotObject, std::string("[1]"));
    EXPECT_ERR(ManifestError::NotObject, std::string("\"x\""));
    EXPECT_ERR(ManifestError::Syntax, std::string(""));
    EXPECT_ERR(ManifestError::Syntax, std::string("{"));
    std::string g = good();
    EXPECT_ERR(ManifestError::Syntax, g.substr(0, g.size() - 1));          // truncated
    EXPECT_ERR(ManifestError::Syntax, g + "x");                           // trailing data
    EXPECT_ERR(ManifestError::Syntax, g + "{}");
    std::string trailingComma = g.substr(0, g.size() - 1) + ",}";
    EXPECT_ERR(ManifestError::Syntax, trailingComma);
    EXPECT_ERR(ManifestError::Syntax, with("product", "\"a\\u0041\""));    // escapes beyond \" \\ \/ are refused
    EXPECT_ERR(ManifestError::Syntax, with("product", "\"a\tb\""));       // raw control character
    std::string withNul = with("product", "\"ab\"");
    withNul[withNul.find("ab") + 1] = '\0';
    EXPECT_ERR(ManifestError::Syntax, withNul);                            // embedded NUL
}

static void test_error_leaves_output_untouched() {
    Manifest m;
    TEST_ASSERT_EQUAL_STRING("Ok", manifestErrorName(parse(good(), m)));
    TEST_ASSERT_EQUAL_STRING("BadValue", manifestErrorName(parse(with("chip", "\"X\""), m)));
    TEST_ASSERT_EQUAL_STRING("esp32c3", m.chip);
}

// TEST_ONLY_MANIFEST is produced by tools/fota_release.py's encoder (tools/gen_test_vectors.py asserts it), so this
// proves the device parser accepts what the release tool writes.
static void test_release_tool_output_parses() {
    Manifest m;
    TEST_ASSERT_EQUAL_STRING("Ok", manifestErrorName(parseManifest(TEST_ONLY_MANIFEST, strlen(TEST_ONLY_MANIFEST), m)));
    TEST_ASSERT_EQUAL_STRING("demo-device", m.product);
    TEST_ASSERT_EQUAL_UINT32(4, m.size);
}

// A factory descriptor (browser flashing, tools/fota_release.py factory) is NOT an OTA manifest: the device parser
// must refuse it, so the two can never be mixed up. TEST_ONLY_FACTORY comes from the release tool's encoder.
static void test_factory_descriptor_is_refused_as_manifest() {
    Manifest m;
    const char* field = nullptr;
    TEST_ASSERT_EQUAL_STRING("UnknownKey",
                             manifestErrorName(parseManifest(TEST_ONLY_FACTORY, strlen(TEST_ONLY_FACTORY), m, &field)));
    TEST_ASSERT_NOT_NULL(strstr(TEST_ONLY_FACTORY, "\"factory_url\""));
}

static void test_error_names() {
    TEST_ASSERT_EQUAL_STRING("TooLarge", manifestErrorName(ManifestError::TooLarge));
    TEST_ASSERT_EQUAL_STRING("UnsupportedSchema", manifestErrorName(ManifestError::UnsupportedSchema));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_parses_full_manifest);
    RUN_TEST(test_optional_fields_may_be_absent);
    RUN_TEST(test_whitespace_and_order_are_free);
    RUN_TEST(test_unknown_or_unsupported_schema);
    RUN_TEST(test_each_required_field_missing);
    RUN_TEST(test_bad_types);
    RUN_TEST(test_bad_values);
    RUN_TEST(test_field_too_long);
    RUN_TEST(test_oversize_document);
    RUN_TEST(test_duplicate_and_unknown_keys);
    RUN_TEST(test_syntax_errors);
    RUN_TEST(test_error_leaves_output_untouched);
    RUN_TEST(test_release_tool_output_parses);
    RUN_TEST(test_factory_descriptor_is_refused_as_manifest);
    RUN_TEST(test_error_names);
    return UNITY_END();
}
