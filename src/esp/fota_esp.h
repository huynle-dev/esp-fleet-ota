// ESP32 (Arduino on ESP-IDF 5.x, pioarduino) implementations of the fota_io.h / fota_crypto.h interfaces.
// Thin glue only: all decisions are in the pure logic. Compiled only for ESP targets with the Arduino framework.
//
// Rollback: this library DEFINES the Arduino core's weak `bool verifyRollbackLater()` to return true, so the core does
// not mark a new image valid at init; FleetOta marks it valid only after the device self-test passes. Build with
// -DFLEET_OTA_NO_ROLLBACK_OVERRIDE to provide your own (it must still return true).
#pragma once
#if defined(ESP_PLATFORM) && defined(ARDUINO)

#include <Arduino.h>
#include <HTTPClient.h>
#include <NetworkClientSecure.h>
#include <Preferences.h>
#include <esp_ota_ops.h>
#include <mbedtls/sha256.h>
#include "../fleet_ota.h"
#include "../fota_target.h"

namespace fota {

class EspClock : public IClock {
public:
    uint64_t nowMs() override;
    void feedWatchdog() override;   // esp_task_wdt_reset() when the calling task is subscribed
    void idle() override;           // delay(1) + feed
};

// One HTTPS GET with the CA bundle and host name verification (NetworkClientSecure sets SNI and checks the
// certificate's name against the URL host). Never setInsecure(). HTTP/1.0 so the body is never chunk-encoded;
// redirects are NOT followed (a redirect could leave the host allow-list).
class EspHttpSource : public IHttpSource {
public:
    EspHttpSource(const uint8_t* caBundle, size_t caBundleLen, uint32_t timeoutMs = 10000);
    bool open(const char* url, int64_t& contentLength) override;
    int read(uint8_t* buf, size_t cap) override;
    void close() override;

private:
    const uint8_t* bundle_;
    size_t bundleLen_;
    uint32_t timeoutMs_;
    NetworkClientSecure tls_;
    HTTPClient http_;
    NetworkClient* stream_ = nullptr;
    int64_t remaining_ = -1;
    bool open_ = false;
};

// The spare slot via esp_ota_*: begin with OTA_WITH_SEQUENTIAL_WRITES (erase as it goes, so no multi-second erase
// trips the watchdog), end validates the image, then set_boot_partition. abort leaves the boot partition untouched.
class EspPartitionWriter : public IPartitionWriter {
public:
    uint32_t spareSize() override;
    bool begin(uint32_t imageSize) override;
    bool write(const uint8_t* data, size_t len) override;
    bool commit() override;
    void abort() override;

private:
    const esp_partition_t* part_ = nullptr;
    esp_ota_handle_t handle_ = 0;
    bool open_ = false;
};

class EspOtaPlatform : public IOtaPlatform {
public:
    const char* runningSlot() override;
    bool pendingVerify() override;
    bool markValid() override;
    void markInvalidAndReboot() override;
    void reboot() override;
};

// NVS through Preferences, namespace "fleet_ota".
class NvsStore : public IStore {
public:
    bool get(const char* key, char* out, size_t cap) override;
    bool put(const char* key, const char* value) override;
    bool remove(const char* key) override;
};

class MbedtlsSha256 : public ISha256 {
public:
    MbedtlsSha256();
    ~MbedtlsSha256() override;
    void begin() override;
    void update(const uint8_t* data, size_t len) override;
    void finish(uint8_t out[32]) override;

private:
    mbedtls_sha256_context ctx_;
};

// mbedtls_pk_parse_public_key + checks the key is EC on secp256r1 + mbedtls_pk_verify(SHA-256).
class MbedtlsEcdsaP256 : public IEcdsaP256Verifier {
public:
    bool verify(const uint8_t* publicKey, size_t keyLen, const uint8_t hash[32], const uint8_t* sig,
                size_t sigLen) override;
};

// Everything wired together. Keep ONE instance with static storage (it is ~1.3 KB plus the TLS client).
class EspFleetOta {
public:
    EspFleetOta(const OtaConfig& cfg, const DeviceIdentity& dev, IDeviceHooks& hooks, const uint8_t* caBundle,
                size_t caBundleLen);
    void begin() { ota_.begin(); }
    void loop() { ota_.loop(); }
    FleetOta& ota() { return ota_; }

private:
    EspClock clock_;
    EspHttpSource http_;
    EspPartitionWriter writer_;
    EspOtaPlatform platform_;
    NvsStore store_;
    MbedtlsSha256 sha_;   // shared: signature check and image hash never overlap
    MbedtlsEcdsaP256 ecdsa_;
    FleetOta ota_;
};

} // namespace fota

#endif
