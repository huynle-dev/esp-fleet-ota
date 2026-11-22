// FleetOta state machine end to end with fakes: check, update, download, reboot, self-test, rollback, persistence,
// auto-check. Manifests are signed at test time with an in-memory TEST-ONLY key.
#include <unity.h>
#include <cstring>
#include <memory>
#include <string>
#include "fleet_ota.h"
#include "fota_fakes.h"
#include "fota_test_signer.h"
#include "host/fota_openssl.h"

using namespace fota;

static const char* MURL = "https://fw.example.com/example-psu/esp32c3/stable/manifest.json";
static const char* SURL = "https://fw.example.com/example-psu/esp32c3/stable/manifest.json.sig";
static const char* IURL = "https://fw.example.com/example-psu/1.4.0/esp32c3/firmware.bin";
static const char* kHosts[] = {"fw.example.com"};

struct Release {
    std::string product = "example-psu", chip = "esp32c3", channel = "stable", version = "1.4.0",
                minVersion = "1.2.0", url = IURL, keyId = "test-only-esp-fleet-ota", board = "";
    std::string image;
    std::string json() const {
        std::string s = "{\"schema\":1,\"product\":\"" + product + "\",\"chip\":\"" + chip + "\",";
        if (!board.empty()) s += "\"board\":\"" + board + "\",";
        s += "\"channel\":\"" + channel + "\",\"version\":\"" + version + "\",";
        if (!minVersion.empty()) s += "\"min_version\":\"" + minVersion + "\",";
        s += "\"url\":\"" + url + "\",\"size\":" + std::to_string(image.size()) + ",\"sha256\":\"" +
             testSha256Hex(image) + "\",\"key_id\":\"" + keyId + "\",\"released_at\":\"2026-11-22T10:00:00Z\"}";
        return s;
    }
};

struct Rig {
    fakes::Clock clock;
    fakes::Http http;
    fakes::Writer writer;
    fakes::Platform platform;
    fakes::Store store;
    fakes::Hooks hooks;
    OpensslSha256 sha, sha2;
    OpensslEcdsaP256 ecdsa;
    TestSigner signer;
    TrustedKey keys[1];
    OtaConfig cfg;
    DeviceIdentity dev{"example-psu", "esp32c3", "esp32-c3-devkitm-1", "1.3.2"};
    std::unique_ptr<FleetOta> ota;
    Rig() {
        keys[0] = TrustedKey{"test-only-esp-fleet-ota", 1, signer.spki.data(), signer.spki.size()};
        cfg.manifest_url = MURL;
        cfg.channel = "stable";
        cfg.allowed_hosts = kHosts;
        cfg.allowed_host_count = 1;
        cfg.keys = keys;
        cfg.key_count = 1;
    }
    void boot() {
        ota.reset(new FleetOta(cfg, dev, OtaDeps{http, writer, platform, store, hooks, clock, sha, ecdsa}));
        ota->begin();
    }
    // Publishes a signed release; `mutate` may alter the served manifest bytes after signing.
    void publish(Release& r, const std::string& servedSuffix = "", const std::string& sigSuffix = "\n") {
        if (r.image.empty()) {
            r.image.resize(30000);
            for (size_t i = 0; i < r.image.size(); i++) r.image[i] = (char)(i * 7 + 3);
        }
        std::string m = r.json();
        fakes::Response mr; mr.body = m + servedSuffix;
        fakes::Response sr; sr.body = signer.signVault(m, 1) + sigSuffix;
        fakes::Response ir; ir.body = r.image; ir.chunk = 1500;
        http.routes[MURL] = mr;
        http.routes[SURL] = sr;
        http.routes[r.url] = ir;
    }
    void runLoop(int n = 1000) { for (int i = 0; i < n; i++) { ota->loop(); clock.now += 10; } }
    std::string last() { return store.kv.count("last_result") ? store.kv["last_result"] : ""; }
};

static std::unique_ptr<Rig> R;
void setUp() { R.reset(new Rig()); }
void tearDown() { R.reset(); }

#define REASON(x) reasonName(x)

// ------------------------------------------------------------------ check
static void test_check_finds_update_without_installing() {
    Release r; R->publish(r); R->boot();
    TEST_ASSERT_EQUAL_STRING("idle", stateName(R->ota->state()));
    TEST_ASSERT_EQUAL_STRING("none", REASON(R->ota->check()));
    TEST_ASSERT_EQUAL_STRING("available", stateName(R->ota->state()));
    TEST_ASSERT_EQUAL_STRING("1.4.0", R->ota->availableVersion());
    TEST_ASSERT_FALSE(R->writer.begun);
    TEST_ASSERT_EQUAL_INT(2, (int)R->http.opened.size());           // manifest + signature only
    TEST_ASSERT_EQUAL_STRING(SURL, R->http.opened[1].c_str());
}

static void test_check_tampered_manifest_refused() {
    Release r; R->publish(r);
    std::string& body = R->http.routes[MURL].body;
    body.replace(body.find("esp32c3"), 7, "esp32s3");                  // a valid manifest, but not what was signed
    R->boot();
    TEST_ASSERT_EQUAL_STRING("signature_invalid", REASON(R->ota->check()));
    TEST_ASSERT_EQUAL_STRING("idle", stateName(R->ota->state()));
    TEST_ASSERT_EQUAL_STRING("", R->ota->availableVersion());
    TEST_ASSERT_EQUAL_STRING("signature_invalid", REASON(R->ota->status().last_check));
}

static void test_manifest_trailing_newline_breaks_signature() {
    Release r; R->publish(r, "\n"); R->boot();
    TEST_ASSERT_EQUAL_STRING("signature_invalid", REASON(R->ota->check()));
}

static void test_signature_file_whitespace_tolerated() {
    Release r; R->publish(r, "", "  \r\n\n"); R->boot();
    TEST_ASSERT_EQUAL_STRING("none", REASON(R->ota->check()));
}

static void test_unknown_key_and_version() {
    Release r; r.keyId = "someone"; R->publish(r); R->boot();
    TEST_ASSERT_EQUAL_STRING("unknown_key_id", REASON(R->ota->check()));
    setUp();
    Release r2; R->publish(r2);
    R->http.routes[SURL].body = R->signer.signVault(r2.json(), 2);    // N=2 is not trusted
    R->boot();
    TEST_ASSERT_EQUAL_STRING("key_version_mismatch", REASON(R->ota->check()));
}

static void test_signed_by_other_key_refused() {
    Release r; R->publish(r);
    TestSigner other;
    R->http.routes[SURL].body = other.signVault(r.json(), 1);
    R->boot();
    TEST_ASSERT_EQUAL_STRING("signature_invalid", REASON(R->ota->check()));
}

static void test_policy_refusals_after_signature() {
    struct Case { const char* field; const char* value; const char* reason; } cases[] = {
        {"chip", "esp32s3", "wrong_chip"},
        {"product", "other-device", "wrong_product"},
        {"channel", "beta", "wrong_channel"},
        {"version", "1.3.2", "not_newer"},
        {"url", "https://evil.example.org/x.bin", "host_not_allowed"},
        {"board", "xiao-esp32c3", "wrong_board"},
    };
    for (auto& c : cases) {
        setUp();
        Release r;
        if (!strcmp(c.field, "chip")) r.chip = c.value;
        if (!strcmp(c.field, "product")) r.product = c.value;
        if (!strcmp(c.field, "channel")) r.channel = c.value;
        if (!strcmp(c.field, "version")) { r.version = c.value; r.minVersion = ""; }
        if (!strcmp(c.field, "url")) r.url = c.value;
        if (!strcmp(c.field, "board")) r.board = c.value;
        R->publish(r); R->boot();
        TEST_ASSERT_EQUAL_STRING_MESSAGE(c.reason, REASON(R->ota->check()), c.field);
        TEST_ASSERT_EQUAL_STRING("idle", stateName(R->ota->state()));
    }
}

static void test_anti_downgrade_floor_from_store() {
    Release r; R->publish(r);
    R->store.kv["floor"] = "1.5.0";
    R->boot();
    TEST_ASSERT_EQUAL_STRING("below_floor", REASON(R->ota->check()));
}

static void test_image_must_fit_spare_slot() {
    Release r; R->publish(r);
    R->writer.spare = 1000;
    R->boot();
    TEST_ASSERT_EQUAL_STRING("too_large", REASON(R->ota->check()));
}

static void test_manifest_url_must_be_https_and_allowed() {
    Release r; R->publish(r);
    R->cfg.signature_url = SURL;                         // explicit, so each URL is checked on its own
    R->cfg.manifest_url = "http://fw.example.com/m.json";
    R->boot();
    TEST_ASSERT_EQUAL_STRING("url_not_https", REASON(R->ota->check()));
    R->cfg.manifest_url = "https://evil.example.org/m.json";
    R->boot();
    TEST_ASSERT_EQUAL_STRING("host_not_allowed", REASON(R->ota->check()));
    TEST_ASSERT_TRUE(R->http.opened.empty());
}

static void test_signature_url_must_be_https_and_allowed() {
    Release r; R->publish(r);
    R->cfg.signature_url = "http://fw.example.com/m.json.sig";
    R->boot();
    TEST_ASSERT_EQUAL_STRING("url_not_https", REASON(R->ota->check()));
    R->cfg.signature_url = "https://evil.example.org/m.json.sig";
    R->boot();
    TEST_ASSERT_EQUAL_STRING("host_not_allowed", REASON(R->ota->check()));
    TEST_ASSERT_TRUE(R->http.opened.empty());
    R->cfg.signature_url = SURL;
    R->boot();
    TEST_ASSERT_EQUAL_STRING("none", REASON(R->ota->check()));
}

static void test_fetch_failures() {
    Release r; R->publish(r);
    R->http.routes[MURL].openOk = false;
    R->boot();
    TEST_ASSERT_EQUAL_STRING("manifest_fetch_failed", REASON(R->ota->check()));
    R->http.routes[MURL].openOk = true;
    R->http.routes[SURL].openOk = false;
    TEST_ASSERT_EQUAL_STRING("signature_fetch_failed", REASON(R->ota->check()));
    R->http.routes[SURL].openOk = true;
    R->http.routes[MURL].body = std::string(kMaxManifestBytes + 1, ' ');
    TEST_ASSERT_EQUAL_STRING("manifest_invalid", REASON(R->ota->check()));
    R->http.routes[MURL].body = "{\"schema\":1}";
    TEST_ASSERT_EQUAL_STRING("manifest_invalid", REASON(R->ota->check()));
    R->http.routes[MURL].body = r.json();
    R->http.routes[MURL].stallAt = 10;
    TEST_ASSERT_EQUAL_STRING("manifest_fetch_failed", REASON(R->ota->check()));   // bounded by fetch_timeout_ms
}

// ------------------------------------------------------------------ update
static void test_update_downloads_and_reboots() {
    Release r; R->publish(r); R->boot();
    TEST_ASSERT_EQUAL_STRING("none", REASON(R->ota->update("1.4.0")));
    TEST_ASSERT_EQUAL_INT(1, R->hooks.beforeCalls);
    TEST_ASSERT_EQUAL_STRING("downloading", stateName(R->ota->state()));
    for (int i = 0; i < 1000 && R->ota->state() == State::downloading; i++) R->ota->loop();
    TEST_ASSERT_TRUE(R->ota->state() == State::verifying || R->ota->state() == State::rebooting);
    R->runLoop(5);
    TEST_ASSERT_EQUAL_STRING("rebooting", stateName(R->ota->state()));
    TEST_ASSERT_TRUE(R->writer.committed);
    TEST_ASSERT_TRUE(R->writer.data == r.image);
    TEST_ASSERT_EQUAL_STRING("1.4.0|1.2.0", R->store.kv["pending"].c_str());
    TEST_ASSERT_EQUAL_INT(0, R->platform.reboots);
    TEST_ASSERT_EQUAL_INT(0, (int)R->store.kv.count("floor"));        // the floor only rises after the self-test
    R->clock.now += R->cfg.reboot_delay_ms;
    R->ota->loop();
    TEST_ASSERT_EQUAL_INT(1, R->platform.reboots);
}

// The device never derives the image path (the layout is the release tool's job): it downloads whatever https
// URL on an allow-listed host the signed manifest names.
static void test_installs_from_any_allowed_image_url_in_manifest() {
    const char* urls[] = {"https://fw.example.com/example-psu/1.4.0/esp32c3/firmware.bin",
                          "https://fw.example.com/some/other/layout/image-1.4.0.bin",
                          "https://FW.EXAMPLE.COM:443/example-psu/1.4.0/esp32c3/firmware.bin?v=1"};
    for (const char* u : urls) {
        setUp();
        Release r; r.url = u; R->publish(r); R->boot();
        TEST_ASSERT_EQUAL_STRING_MESSAGE("none", REASON(R->ota->update("1.4.0")), u);
        R->runLoop(1000);
        TEST_ASSERT_EQUAL_STRING_MESSAGE("rebooting", stateName(R->ota->state()), u);
        TEST_ASSERT_EQUAL_STRING(u, R->http.opened.back().c_str());       // exactly the signed URL
        TEST_ASSERT_TRUE(R->writer.data == r.image);
    }
}

static void test_update_requires_expected_version() {
    Release r; R->publish(r); R->boot();
    TEST_ASSERT_EQUAL_STRING("version_mismatch", REASON(R->ota->update("1.5.0")));
    TEST_ASSERT_FALSE(R->writer.begun);
    TEST_ASSERT_EQUAL_INT(0, R->hooks.beforeCalls);
    TEST_ASSERT_EQUAL_STRING("refused|version_mismatch|1.5.0", R->last().c_str());
    TEST_ASSERT_EQUAL_STRING("version_mismatch", REASON(R->ota->update(nullptr)));
    TEST_ASSERT_EQUAL_STRING("version_mismatch", REASON(R->ota->update("")));
}

static void test_update_refused_by_device_hook() {
    Release r; R->publish(r); R->boot();
    R->hooks.allow = false;
    TEST_ASSERT_EQUAL_STRING("device_refused", REASON(R->ota->update("1.4.0")));
    TEST_ASSERT_FALSE(R->writer.begun);
    TEST_ASSERT_EQUAL_INT(0, R->hooks.beforeCalls);
    TEST_ASSERT_EQUAL_STRING("refused|device_refused|1.4.0", R->last().c_str());
    TEST_ASSERT_EQUAL_STRING("available", stateName(R->ota->state()));
}

static void test_update_refused_when_check_fails() {
    Release r; R->publish(r, "\n"); R->boot();          // tampered manifest
    TEST_ASSERT_EQUAL_STRING("signature_invalid", REASON(R->ota->update("1.4.0")));
    TEST_ASSERT_FALSE(R->writer.begun);
    TEST_ASSERT_EQUAL_STRING("refused|signature_invalid|1.4.0", R->last().c_str());
}

static void test_update_hash_mismatch_fails_cleanly() {
    Release r; R->publish(r); R->boot();
    R->http.routes[IURL].body[100] ^= 1;                // image altered on the server after signing
    TEST_ASSERT_EQUAL_STRING("none", REASON(R->ota->update("1.4.0")));
    R->runLoop(1000);
    TEST_ASSERT_EQUAL_STRING("failed", stateName(R->ota->state()));
    TEST_ASSERT_FALSE(R->writer.bootable);
    TEST_ASSERT_TRUE(R->writer.aborted);
    TEST_ASSERT_EQUAL_INT(0, R->platform.reboots);
    TEST_ASSERT_EQUAL_STRING("failed|hash_mismatch|1.4.0", R->last().c_str());
    TEST_ASSERT_EQUAL_INT(0, (int)R->store.kv.count("pending"));
}

static void test_update_busy_while_downloading() {
    Release r; R->publish(r); R->boot();
    TEST_ASSERT_EQUAL_STRING("none", REASON(R->ota->update("1.4.0")));
    TEST_ASSERT_EQUAL_STRING("busy", REASON(R->ota->update("1.4.0")));
    TEST_ASSERT_EQUAL_STRING("busy", REASON(R->ota->check()));
}

// ------------------------------------------------------------------ after the reboot
static void bootIntoNewImage() {
    R->dev.running_version = "1.4.0";
    R->platform.pending = true;
    R->platform.slot = "app1";
    R->store.kv["pending"] = "1.4.0|1.2.0";
}

static void test_self_test_pass_marks_valid_and_raises_floor() {
    bootIntoNewImage();
    R->hooks.script = {SelfTest::pending, SelfTest::pending, SelfTest::pending, SelfTest::pass};
    R->boot();
    TEST_ASSERT_EQUAL_STRING("pending_verify", stateName(R->ota->state()));
    TEST_ASSERT_EQUAL_INT(0, R->platform.markValidCalls);
    R->ota->loop(); R->ota->loop(); R->ota->loop();
    TEST_ASSERT_EQUAL_INT(0, R->platform.markValidCalls);             // never before the self-test passes
    R->ota->loop();
    TEST_ASSERT_EQUAL_INT(1, R->platform.markValidCalls);
    TEST_ASSERT_EQUAL_INT(0, R->platform.markInvalidCalls);
    TEST_ASSERT_EQUAL_STRING("ok", stateName(R->ota->state()));
    TEST_ASSERT_EQUAL_STRING("ok|none|1.4.0", R->last().c_str());
    TEST_ASSERT_EQUAL_STRING("1.2.0", R->store.kv["floor"].c_str());
    TEST_ASSERT_EQUAL_INT(0, (int)R->store.kv.count("pending"));
}

static void test_self_test_fail_rolls_back() {
    bootIntoNewImage();
    R->hooks.script = {SelfTest::pending, SelfTest::fail};
    R->boot();
    R->runLoop(5);
    TEST_ASSERT_EQUAL_INT(0, R->platform.markValidCalls);
    TEST_ASSERT_EQUAL_INT(1, R->platform.markInvalidCalls);
    TEST_ASSERT_EQUAL_STRING("rolled_back|self_test_failed|1.4.0", R->last().c_str());
    TEST_ASSERT_EQUAL_INT(0, (int)R->store.kv.count("pending"));
    TEST_ASSERT_EQUAL_INT(0, (int)R->store.kv.count("floor"));
}

static void test_self_test_deadline_rolls_back() {
    bootIntoNewImage();
    R->hooks.script = {SelfTest::pending};
    R->boot();
    R->clock.now += R->cfg.self_test_deadline_ms - 100;
    R->ota->loop();
    TEST_ASSERT_EQUAL_INT(0, R->platform.markInvalidCalls);
    R->clock.now += 200;
    R->ota->loop();
    TEST_ASSERT_EQUAL_INT(0, R->platform.markValidCalls);
    TEST_ASSERT_EQUAL_INT(1, R->platform.markInvalidCalls);
    TEST_ASSERT_EQUAL_STRING("rolled_back|self_test_timeout|1.4.0", R->last().c_str());
}

static void test_mark_valid_failure_rolls_back() {
    bootIntoNewImage();
    R->platform.markValidOk = false;
    R->boot();
    R->runLoop(3);
    TEST_ASSERT_EQUAL_INT(1, R->platform.markInvalidCalls);
    TEST_ASSERT_EQUAL_STRING("rolled_back|boot_failed|1.4.0", R->last().c_str());
}

static void test_busy_while_pending_verify() {
    bootIntoNewImage();
    R->hooks.script = {SelfTest::pending};
    Release r; R->publish(r);
    R->boot();
    TEST_ASSERT_EQUAL_STRING("busy", REASON(R->ota->check()));
    TEST_ASSERT_EQUAL_STRING("busy", REASON(R->ota->update("1.4.0")));
}

static void test_bootloader_rollback_detected() {
    R->store.kv["pending"] = "1.4.0|1.2.0";              // we installed 1.4.0, but 1.3.2 is running and not pending
    R->boot();
    TEST_ASSERT_EQUAL_STRING("idle", stateName(R->ota->state()));
    TEST_ASSERT_EQUAL_STRING("rolled_back|boot_failed|1.4.0", R->last().c_str());
    TEST_ASSERT_EQUAL_INT(0, (int)R->store.kv.count("pending"));
    TEST_ASSERT_EQUAL_INT(0, R->platform.markValidCalls);
}

static void test_confirmed_but_unrecorded_install_completes() {
    R->dev.running_version = "1.4.0";                    // marked valid, then lost power before recording
    R->store.kv["pending"] = "1.4.0|1.2.0";
    R->boot();
    TEST_ASSERT_EQUAL_STRING("ok", stateName(R->ota->state()));
    TEST_ASSERT_EQUAL_STRING("ok|none|1.4.0", R->last().c_str());
    TEST_ASSERT_EQUAL_STRING("1.2.0", R->store.kv["floor"].c_str());
}

static void test_pending_verify_without_record_still_self_tests() {
    R->platform.pending = true;                          // e.g. an image installed by another tool
    R->hooks.script = {SelfTest::pass};
    R->boot();
    TEST_ASSERT_EQUAL_STRING("pending_verify", stateName(R->ota->state()));
    R->ota->loop();
    TEST_ASSERT_EQUAL_INT(1, R->platform.markValidCalls);
    TEST_ASSERT_EQUAL_STRING("ok|none|1.3.2", R->last().c_str());
}

static void test_last_result_survives_reboot() {
    R->store.kv["last_result"] = "failed|timeout|1.4.0";
    R->boot();
    OtaStatus s = R->ota->status();
    TEST_ASSERT_EQUAL_INT((int)ResultKind::failed, (int)s.last_result.kind);
    TEST_ASSERT_EQUAL_STRING("timeout", reasonName(s.last_result.reason));
    TEST_ASSERT_EQUAL_STRING("1.4.0", s.last_result.version);
}

// ------------------------------------------------------------------ auto-check
static void test_auto_check_off_by_default() {
    Release r; R->publish(r); R->boot();
    TEST_ASSERT_FALSE(R->ota->status().auto_check_enabled);
    for (int i = 0; i < 100; i++) { R->clock.now += 3600000; R->ota->loop(); }
    TEST_ASSERT_TRUE(R->http.opened.empty());
}

static void test_auto_check_interval_clamped_and_installs_when_allowed() {
    Release r; R->publish(r); R->boot();
    R->ota->setAutoCheck(true, 60000);
    TEST_ASSERT_EQUAL_UINT32(kMinAutoCheckIntervalMs, R->ota->status().auto_check_interval_ms);
    R->clock.now += 60000; R->ota->loop();
    TEST_ASSERT_TRUE(R->http.opened.empty());             // not after 1 min
    R->clock.now += kMinAutoCheckIntervalMs; R->ota->loop();
    TEST_ASSERT_EQUAL_STRING("downloading", stateName(R->ota->state()));
}

static void test_auto_check_waits_for_device() {
    Release r; R->publish(r); R->boot();
    R->hooks.allow = false;
    R->ota->setAutoCheck(true, kMinAutoCheckIntervalMs);
    R->clock.now += kMinAutoCheckIntervalMs + 1; R->ota->loop();
    TEST_ASSERT_EQUAL_STRING("available", stateName(R->ota->state()));
    TEST_ASSERT_FALSE(R->writer.begun);
}

// ------------------------------------------------------------------ status
static void test_status_and_json() {
    Release r; R->publish(r); R->boot();
    R->ota->check();
    OtaStatus s = R->ota->status();
    TEST_ASSERT_EQUAL_STRING("1.3.2", s.current_version);
    TEST_ASSERT_EQUAL_STRING("app0", s.running_slot);
    TEST_ASSERT_EQUAL_STRING("1.4.0", s.available_version);
    char buf[512];
    size_t n = formatStatusJson(s, buf, sizeof(buf));
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_EQUAL_STRING(
        "{\"current_version\":\"1.3.2\",\"running_slot\":\"app0\",\"state\":\"available\","
        "\"last_result\":{\"kind\":\"none\",\"reason\":\"none\",\"version\":\"\"},\"available_version\":\"1.4.0\","
        "\"last_check\":\"none\",\"progress\":0,\"total\":0,\"auto_check\":{\"enabled\":false,\"interval_s\":21600}}",
        buf);
    TEST_ASSERT_EQUAL_size_t(0, formatStatusJson(s, buf, 20));
}

// A crypto backend that accepts everything would defeat the signature check: FleetOta runs the known-answer test
// (fota_selfcheck.h) once and refuses to check or update while it fails.
struct PermissiveVerifier : IEcdsaP256Verifier {
    bool verify(const uint8_t*, size_t, const uint8_t*, const uint8_t*, size_t) override { return true; }
};

static void test_fails_closed_when_crypto_self_check_fails() {
    Release r; R->publish(r, "\n");                    // tampered: a permissive verifier would accept it
    PermissiveVerifier bad;
    R->ota.reset(new FleetOta(R->cfg, R->dev, OtaDeps{R->http, R->writer, R->platform, R->store, R->hooks, R->clock,
                                                       R->sha, bad}));
    R->ota->begin();
    TEST_ASSERT_EQUAL_STRING("crypto_self_check_failed", REASON(R->ota->check()));
    TEST_ASSERT_EQUAL_STRING("crypto_self_check_failed", REASON(R->ota->update("1.4.0")));
    TEST_ASSERT_TRUE(R->http.opened.empty());
    TEST_ASSERT_FALSE(R->writer.begun);
}

static void test_state_names() {
    const char* names[] = {"idle", "checking", "available", "downloading", "verifying", "rebooting", "pending_verify",
                           "ok", "failed"};
    for (int i = 0; i < 9; i++) TEST_ASSERT_EQUAL_STRING(names[i], stateName((State)i));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_check_finds_update_without_installing);
    RUN_TEST(test_check_tampered_manifest_refused);
    RUN_TEST(test_manifest_trailing_newline_breaks_signature);
    RUN_TEST(test_signature_file_whitespace_tolerated);
    RUN_TEST(test_unknown_key_and_version);
    RUN_TEST(test_signed_by_other_key_refused);
    RUN_TEST(test_policy_refusals_after_signature);
    RUN_TEST(test_anti_downgrade_floor_from_store);
    RUN_TEST(test_image_must_fit_spare_slot);
    RUN_TEST(test_manifest_url_must_be_https_and_allowed);
    RUN_TEST(test_signature_url_must_be_https_and_allowed);
    RUN_TEST(test_fetch_failures);
    RUN_TEST(test_update_downloads_and_reboots);
    RUN_TEST(test_installs_from_any_allowed_image_url_in_manifest);
    RUN_TEST(test_update_requires_expected_version);
    RUN_TEST(test_update_refused_by_device_hook);
    RUN_TEST(test_update_refused_when_check_fails);
    RUN_TEST(test_update_hash_mismatch_fails_cleanly);
    RUN_TEST(test_update_busy_while_downloading);
    RUN_TEST(test_self_test_pass_marks_valid_and_raises_floor);
    RUN_TEST(test_self_test_fail_rolls_back);
    RUN_TEST(test_self_test_deadline_rolls_back);
    RUN_TEST(test_mark_valid_failure_rolls_back);
    RUN_TEST(test_busy_while_pending_verify);
    RUN_TEST(test_bootloader_rollback_detected);
    RUN_TEST(test_confirmed_but_unrecorded_install_completes);
    RUN_TEST(test_pending_verify_without_record_still_self_tests);
    RUN_TEST(test_last_result_survives_reboot);
    RUN_TEST(test_auto_check_off_by_default);
    RUN_TEST(test_auto_check_interval_clamped_and_installs_when_allowed);
    RUN_TEST(test_auto_check_waits_for_device);
    RUN_TEST(test_status_and_json);
    RUN_TEST(test_fails_closed_when_crypto_self_check_fails);
    RUN_TEST(test_state_names);
    return UNITY_END();
}
