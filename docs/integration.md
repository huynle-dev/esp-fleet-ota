# Integrating esp-fleet-ota into a device

The reference is `examples/minimal` (builds for esp32c3 and esp32s3).

## 1. Build

```ini
; platformio.ini of the device
[env:esp32c3]
platform = https://github.com/pioarduino/platform-espressif32/releases/download/stable/platform-espressif32.zip
board = esp32-c3-devkitm-1
framework = arduino
board_build.partitions = partitions.csv
lib_deps =
    symlink://../../esp-fleet-ota          ; or a git URL with a tag
lib_ldf_mode = deep+
build_unflags = -std=gnu++11
build_flags =
    -std=gnu++17
    -DFOTA_BOARD=\"esp32-c3-devkitm-1\"    ; the board id the release manifests use (optional, see below)
    -DFIRMWARE_VERSION=\"1.4.0\"           ; MUST be the exact semver of the release manifest
    -I ${platformio.packages_dir}/framework-arduinoespressif32/libraries/Network/src
```

- `FOTA_CHIP` comes from `CONFIG_IDF_TARGET` (`esp32c3`, `esp32s3`, ...); nothing else is chip-specific.
- `FOTA_BOARD` is optional. When a manifest names a `board`, a device whose `FOTA_BOARD` differs (or is empty) refuses
  it with `wrong_board`. Manifests without `board` fit every board of that product + chip.
- The running version string is compared with semver rules; a non-semver version makes every check fail with
  `running_version_invalid`.

## 2. Partitions

Two OTA app slots plus `otadata`. A table for 4 MB flash with two 1.875 MB slots is in
`examples/minimal/partitions.csv`:

```
nvs,      data, nvs,     0x9000,   0x5000
otadata,  data, ota,     0xe000,   0x2000
app0,     app,  ota_0,   0x10000,  0x1E0000
app1,     app,  ota_1,   0x1F0000, 0x1E0000
coredump, data, coredump,0x3D0000, 0x30000
```

The library refuses images larger than the spare slot (`too_large`) before downloading. Changing the partition table
needs a serial flash; it cannot be done over the air.

## 3. Rollback: `verifyRollbackLater()`

The pioarduino Arduino libs ship `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` for esp32c3 and esp32s3, and the core's
`initArduino()` marks a pending image valid at once unless the weak `bool verifyRollbackLater()` returns true
(`cores/esp32/esp32-hal-misc.c`). **This library defines it** (`src/esp/fota_esp.cpp`, C linkage, returns true), so
the new image stays `ESP_OTA_IMG_PENDING_VERIFY` until `FleetOta` has run the device self-test. Do not define it in the
sketch as well (duplicate symbol). To provide your own, build with `-DFLEET_OTA_NO_ROLLBACK_OVERRIDE`; it must still
return true. Check with `nm firmware.elf | grep verifyRollbackLater`: it must be `T`, not `W`.

Consequence: an image installed by serial (`esptool`) is not pending, so nothing changes for development flashing.

## 4. Configuration and keys

```cpp
#include "esp_fleet_ota.h"

extern const uint8_t rootca_crt_bundle_start[] asm("_binary_x509_crt_bundle_start");
extern const uint8_t rootca_crt_bundle_end[] asm("_binary_x509_crt_bundle_end");

// Your key ids and public keys; entries made with: fota_release.py c-key --public-key <pem> --key-id <id> --key-version <N>
static const char kEspFleetOtaV1[] = "-----BEGIN PUBLIC KEY-----\n" "...\n" "-----END PUBLIC KEY-----\n";
static const char kBreakGlass[] = "-----BEGIN PUBLIC KEY-----\n" "...\n" "-----END PUBLIC KEY-----\n";
static const fota::TrustedKey kKeys[] = {
    {"esp-fleet-ota", 1, (const uint8_t*)kEspFleetOtaV1, sizeof(kEspFleetOtaV1) - 1},  // OpenBao transit, N = 1
    {"<your break-glass key id>", 0, (const uint8_t*)kBreakGlass, sizeof(kBreakGlass) - 1}, // YubiKey, no N
};
static const char* const kHosts[] = {"fw.example.com"};

fota::OtaConfig cfg;            // defaults: channel "stable", self-test deadline 120 s, auto-check OFF
cfg.manifest_url = "https://fw.example.com/example-psu/" FOTA_CHIP "/stable/manifest.json";
cfg.allowed_hosts = kHosts; cfg.allowed_host_count = 1;
cfg.keys = kKeys; cfg.key_count = 2;
```

- **The key ids and public keys you configure must match your signing setup exactly** (byte for byte for the id; the
  PEM is the public key of that signing key and version). With OpenBao transit, N is taken from the `.sig`
  (`vault:vN:`); a break-glass key uses N = 0. A mismatched id is refused as `unknown_key_id`, a missing N as
  `key_version_mismatch`: the table is plain data, so no code changes are needed when ids or keys change. The ids and
  keys in this repository (`test-only-esp-fleet-ota`, `test-only-esp-fleet-ota-breakglass`,
  `examples/minimal/src/test_only_keys.h`) are TEST-ONLY.
- The signature is fetched from `manifest_url + ".sig"` unless `signature_url` is set. Both URLs, and the image URL in
  the manifest, must be `https://` on port 443 with a host in `allowed_hosts` (exact, case-insensitive, no wildcards).
- TLS uses the core's CA bundle (`rootca_crt_bundle`, which includes the ISRG roots used by Let's Encrypt) with host name
  verification; the glue never calls `setInsecure()` and does not follow redirects.
- Image URL: the device downloads exactly the `url` in the signed manifest (for example
  `https://fw.example.com/<product>/<version>/<chip>/firmware.bin`; nothing on the device depends on the layout).
- Key table rules: an entry is (key_id, N). `vault:vN:` signatures need an entry with that N; bare base64
  signatures need an entry with N = 0. Unknown key_id: `unknown_key_id`; known key_id without that N:
  `key_version_mismatch`. Keep one entry per trusted OpenBao key version (docs/release.md, rotation).
- Channel: `cfg.channel` (`stable`, `beta` or `dev`) must equal the manifest's channel; switching a device to beta or
  dev means changing both the channel and the manifest URL. A manifest naming `dev` is only ever accepted by a device
  configured for the dev channel (`wrong_channel` otherwise). Devices running a release of this library from before
  `dev` existed refuse a dev manifest outright (`manifest_invalid`), so a server must never publish a dev manifest to
  a channel path that an older device reads (`stable`/`beta`); dev manifests go to `<product>/<chip>/dev/` only.

## 5. Device hooks

```cpp
// Example: a bench power supply controller with an MQTT/TLS connection and a serial (Modbus) link to the supply.
class SupplyOtaHooks : public fota::IDeviceHooks {
    bool canUpdateNow(char* why, size_t cap) override {      // ota_update and auto-install ask first
        if (supply.outputOn()) { snprintf(why, cap, "output is on"); return false; }   // never reboot under load
        if (jobs.running()) { snprintf(why, cap, "a job is running"); return false; }
        return true;
    }
    void onBeforeUpdate() override {                        // free heap and stop flash/UART users
        mqtt.disconnect();                                   // frees one TLS session for the download
        supplyLink.pause();
    }
    fota::SelfTest selfTest() override {                     // called from loop() until pass/fail or 120 s
        if (!supplyLink.responding()) return fota::SelfTest::pending;
        if (!wifiUp() || !mqtt.connected()) return fota::SelfTest::pending;
        return fota::SelfTest::pass;                         // or fail on a definite error
    }
};
```

The self-test must prove that the new image can do its job **and can update again** (network + TLS up). An image that
boots but cannot reach the network would otherwise be confirmed and strand the device. `fail` rolls back at once;
`pending` until the deadline rolls back with `self_test_timeout`.

## 6. Lifecycle

```cpp
static SupplyOtaHooks gHooks;
static fota::EspFleetOta gOta(cfg, fota::DeviceIdentity{"example-psu", FOTA_CHIP, FOTA_BOARD, FIRMWARE_VERSION},
                              gHooks, rootca_crt_bundle_start, rootca_crt_bundle_end - rootca_crt_bundle_start);
void setup() { /* watchdog, wifi ... */ gOta.begin(); }
void loop()  { esp_task_wdt_reset(); gOta.loop(); /* ... */ }
```

`begin()` reconciles the boot (pending verify, rolled back, confirmed) and loads `last_result` and the rejected
versions from NVS (namespace `fleet_ota`, keys `last_result`, `floor`, `pending`, `rejected`). `loop()` runs the self-test, advances a download by one chunk,
reboots after `reboot_delay_ms` (2 s, so the MCP reply goes out first) and runs the optional auto-check.

## 7. MCP tools and MQTT

| Tool | Arguments | Calls | Returns |
|---|---|---|---|
| `ota_status` | none | `status()` + `formatStatusJson()` | `{"current_version","running_slot","state","last_result":{kind,reason,version},"available_version","last_check","progress","total","auto_check":{enabled,interval_s}[,"rejected":[versions]]}` |
| `ota_check` | none | `check()` | `{"result": reasonName(r), ...status}`; never installs |
| `ota_update` | `{"version": "1.4.0"}` (required), `"force": true` (optional, default false) | `update(version, force)` | `{"result": "none"}` when the download started, else the refusal reason (`version_mismatch`, `device_refused`, `busy`, `rejected`, any check reason) |
| `ota_auto` (optional) | `{"enabled": bool, "interval_s": n}` | `setAutoCheck()` | status; interval is clamped to >= 3600 s |

**Rejected versions.** When an installed image fails its self-test, misses the deadline, cannot be marked valid or is
rolled back by the bootloader, its version is remembered (NVS key `rejected`, the last 8, oldest evicted). Later offers
of that version are refused with `rejected` by `ota_check`, `ota_update` and the auto-check, even when the release is
re-signed, re-built (`+build` metadata) or re-hosted: the comparison is by version. `ota_update` with `"force": true`
(`update(version, true)`) installs it anyway; only this refusal is bypassed, every other check still applies. A
confirmed install forgets every remembered version <= the installed one. `status().rejected` (never null, oldest
first) and the `"rejected"` array in the status JSON (present only when the list is not empty) let the product show
the list; give `formatStatusJson` a 768-byte buffer.

`check()` blocks for the TLS handshakes and two small downloads (bounded by `fetch_timeout_ms` each); run it from the
same task as the MCP server, not from an ISR or a callback that holds other locks. MQTT: publish the status JSON
retained on `<prefix>/ota/status` when `state` or `last_result` changes; accept the same commands on a command topic
only if the broker connection is authenticated, since `ota_update` is an action.

## 8. Heap and watchdog checklist

- A C3 device that already holds two TLS sessions (for example MQTT and a remote-control tunnel) may have only
  ~57 KB free / ~47 KB in its largest block. The download needs a third session unless `onBeforeUpdate()` closes one:
  disconnect MQTT (or the tunnel) before the download; it reconnects after the reboot anyway.
- 15 s task watchdog: the library feeds it between chunks and while waiting; the glue removes the task from the
  watchdog only during the TLS handshake. Measure the worst case on hardware (docs/release.md, hardware checks).
