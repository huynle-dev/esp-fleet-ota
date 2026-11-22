// esp-fleet-ota minimal example: WiFi + FleetOta + a serial console standing in for the device's MCP tools.
//   s            ota_status (JSON)
//   c            ota_check
//   u <version>  ota_update <version>
//   a on|off     auto-check
// The trusted keys are TEST-ONLY (test_only_keys.h): a real device lists its OpenBao transit key versions and its
// break-glass key (docs/release.md, docs/integration.md). WiFi credentials come from build flags (-DWIFI_SSID=..., -DWIFI_PASS=...).
#include <Arduino.h>
#include <WiFi.h>
#include <esp_task_wdt.h>
#include "esp_fleet_ota.h"
#include "test_only_keys.h"

#ifndef WIFI_SSID
#define WIFI_SSID ""
#endif
#ifndef WIFI_PASS
#define WIFI_PASS ""
#endif
#ifndef FIRMWARE_VERSION
#define FIRMWARE_VERSION "0.0.0"
#endif

extern const uint8_t rootca_crt_bundle_start[] asm("_binary_x509_crt_bundle_start");
extern const uint8_t rootca_crt_bundle_end[] asm("_binary_x509_crt_bundle_end");

// TEST-ONLY keys and ids, generated with the test fixtures (tools/gen_test_vectors.py). Never ship these: a real
// device lists the key ids and public keys you configure for your signing service (docs/integration.md); they must
// match exactly.
static const fota::TrustedKey kKeys[] = {
    {kExampleTestOnlyOpenBaoKeyId, 1, (const uint8_t*)kExampleTestOnlyOpenBaoPem, sizeof(kExampleTestOnlyOpenBaoPem) - 1},
    {kExampleTestOnlyBreakGlassKeyId, 0, (const uint8_t*)kExampleTestOnlyBreakGlassPem,
     sizeof(kExampleTestOnlyBreakGlassPem) - 1},
};
static const char* const kHosts[] = {"fw.example.com"};

// Device policy. A real device checks its own state (the PSU: output off, no job running).
class Hooks : public fota::IDeviceHooks {
public:
    bool canUpdateNow(char* why, size_t cap) override {
        if (WiFi.status() != WL_CONNECTED) { snprintf(why, cap, "wifi down"); return false; }
        return true;
    }
    void onBeforeUpdate() override { Serial.println("ota: starting update"); }
    fota::SelfTest selfTest() override {
        // Pass once the new image proved it can do its job: here, WiFi up and enough heap.
        if (WiFi.status() == WL_CONNECTED && ESP.getFreeHeap() > 30000) return fota::SelfTest::pass;
        return fota::SelfTest::pending;
    }
};

static Hooks gHooks;
static fota::OtaConfig makeConfig() {
    fota::OtaConfig c;
    c.manifest_url = "https://fw.example.com/fleet-ota-example/" FOTA_CHIP "/stable/manifest.json";
    c.channel = "stable";
    c.allowed_hosts = kHosts;
    c.allowed_host_count = 1;
    c.keys = kKeys;
    c.key_count = sizeof(kKeys) / sizeof(kKeys[0]);
    return c;
}
static const fota::OtaConfig gCfg = makeConfig();
static const fota::DeviceIdentity gDev{"fleet-ota-example", FOTA_CHIP, FOTA_BOARD, FIRMWARE_VERSION};
static fota::EspFleetOta gOta(gCfg, gDev, gHooks, rootca_crt_bundle_start,
                              (size_t)(rootca_crt_bundle_end - rootca_crt_bundle_start));

static void printStatus() {
    char buf[512];
    if (fota::formatStatusJson(gOta.ota().status(), buf, sizeof(buf))) Serial.println(buf);
}

static void handleLine(String line) {
    line.trim();
    if (line == "s") { printStatus(); return; }
    if (line == "c") { Serial.printf("ota_check: %s\n", fota::reasonName(gOta.ota().check())); printStatus(); return; }
    if (line.startsWith("u ")) {
        String v = line.substring(2);
        v.trim();
        Serial.printf("ota_update: %s\n", fota::reasonName(gOta.ota().update(v.c_str())));
        return;
    }
    if (line == "a on") { gOta.ota().setAutoCheck(true, 6 * 3600000u); printStatus(); return; }
    if (line == "a off") { gOta.ota().setAutoCheck(false, 6 * 3600000u); printStatus(); return; }
    Serial.println("commands: s | c | u <version> | a on|off");
}

void setup() {
    Serial.begin(115200);
    esp_task_wdt_config_t twdt = {.timeout_ms = 15000, .idle_core_mask = 0, .trigger_panic = true};
    esp_task_wdt_reconfigure(&twdt);
    esp_task_wdt_add(nullptr);
    WiFi.mode(WIFI_STA);
    if (strlen(WIFI_SSID)) WiFi.begin(WIFI_SSID, WIFI_PASS);
    gOta.begin();                      // enters pending_verify after an update; loop() runs the self-test
    Serial.printf("fleet-ota example %s on %s (%s)\n", FIRMWARE_VERSION, FOTA_CHIP, FOTA_BOARD);
    printStatus();
}

void loop() {
    esp_task_wdt_reset();
    gOta.loop();
    static String line;
    while (Serial.available()) {
        char ch = (char)Serial.read();
        if (ch == '\n') { handleLine(line); line = ""; }
        else if (line.length() < 80) line += ch;
    }
    delay(2);
}
