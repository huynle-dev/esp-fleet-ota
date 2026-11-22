#if defined(ESP_PLATFORM) && defined(ARDUINO)
#include "fota_esp.h"
#include <cstring>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>

#ifndef FLEET_OTA_NO_ROLLBACK_OVERRIDE
// The Arduino core (esp32-hal-misc.c, initArduino) marks a pending image valid at init unless this returns true.
// FleetOta must decide after the self-test, so defer. C linkage: the core is C.
extern "C" bool verifyRollbackLater() { return true; }
#endif

namespace fota {

namespace {
bool wdtSubscribed() { return esp_task_wdt_status(nullptr) == ESP_OK; }
} // namespace

// ------------------------------------------------------------------ clock
uint64_t EspClock::nowMs() { return (uint64_t)(esp_timer_get_time() / 1000); }
void EspClock::feedWatchdog() { if (wdtSubscribed()) esp_task_wdt_reset(); }
void EspClock::idle() { delay(1); feedWatchdog(); }

// ------------------------------------------------------------------ HTTPS
EspHttpSource::EspHttpSource(const uint8_t* caBundle, size_t caBundleLen, uint32_t timeoutMs)
    : bundle_(caBundle), bundleLen_(caBundleLen), timeoutMs_(timeoutMs) {}

bool EspHttpSource::open(const char* url, int64_t& contentLength) {
    close();
    if (!url || strncmp(url, "https://", 8) != 0 || !bundle_ || !bundleLen_) return false;
    tls_.setCACertBundle(bundle_, bundleLen_);          // verification on; never setInsecure()
    tls_.setTimeout(timeoutMs_ / 1000 ? timeoutMs_ / 1000 : 1);
    tls_.setHandshakeTimeout(timeoutMs_ / 1000 ? timeoutMs_ / 1000 : 1);
    http_.setReuse(false);
    http_.useHTTP10(true);                               // no chunked transfer encoding
    http_.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
    http_.setConnectTimeout((int32_t)timeoutMs_);
    http_.setTimeout((uint16_t)(timeoutMs_ > 60000 ? 60000 : timeoutMs_));
    if (!http_.begin(tls_, url)) return false;
    // The TLS handshake blocks inside mbedTLS (bounded by the handshake timeout), so take the task
    // off the watchdog for that call only.
    const bool sub = wdtSubscribed();
    if (sub) esp_task_wdt_delete(nullptr);
    const int code = http_.GET();
    if (sub) { esp_task_wdt_add(nullptr); esp_task_wdt_reset(); }
    if (code != 200) { http_.end(); return false; }
    const int size = http_.getSize();
    contentLength = size >= 0 ? (int64_t)size : -1;
    remaining_ = contentLength;
    stream_ = http_.getStreamPtr();
    open_ = stream_ != nullptr;
    if (!open_) http_.end();
    return open_;
}

int EspHttpSource::read(uint8_t* buf, size_t cap) {
    if (!open_ || !stream_) return kError;
    if (remaining_ == 0) return kEof;
    const int avail = stream_->available();
    if (avail > 0) {
        size_t n = (size_t)avail < cap ? (size_t)avail : cap;
        if (remaining_ > 0 && (int64_t)n > remaining_) n = (size_t)remaining_;
        const int got = stream_->read(buf, n);
        if (got < 0) return kError;
        if (remaining_ > 0) remaining_ -= got;
        return got;
    }
    if (!stream_->connected()) return kEof;               // HTTP/1.0: the server closes at the end of the body
    return 0;
}

void EspHttpSource::close() {
    if (open_ || stream_) http_.end();
    tls_.stop();
    stream_ = nullptr;
    open_ = false;
    remaining_ = -1;
}

// ------------------------------------------------------------------ spare slot
uint32_t EspPartitionWriter::spareSize() {
    const esp_partition_t* p = esp_ota_get_next_update_partition(nullptr);
    return p ? (uint32_t)p->size : 0;
}

bool EspPartitionWriter::begin(uint32_t imageSize) {
    abort();
    part_ = esp_ota_get_next_update_partition(nullptr);
    if (!part_ || imageSize > part_->size) return false;
    if (esp_ota_begin(part_, OTA_WITH_SEQUENTIAL_WRITES, &handle_) != ESP_OK) return false;
    open_ = true;
    return true;
}

bool EspPartitionWriter::write(const uint8_t* data, size_t len) {
    return open_ && esp_ota_write(handle_, data, len) == ESP_OK;
}

bool EspPartitionWriter::commit() {
    if (!open_) return false;
    open_ = false;                                        // esp_ota_end frees the handle on success and on error
    if (esp_ota_end(handle_) != ESP_OK) return false;     // validates the image (and its signature with Secure Boot)
    return esp_ota_set_boot_partition(part_) == ESP_OK;
}

void EspPartitionWriter::abort() {
    if (open_) esp_ota_abort(handle_);
    open_ = false;
}

// ------------------------------------------------------------------ boot state
const char* EspOtaPlatform::runningSlot() {
    const esp_partition_t* p = esp_ota_get_running_partition();
    return p ? p->label : "";
}

bool EspOtaPlatform::pendingVerify() {
    esp_ota_img_states_t st;
    const esp_partition_t* p = esp_ota_get_running_partition();
    return p && esp_ota_get_state_partition(p, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY;
}

bool EspOtaPlatform::markValid() { return esp_ota_mark_app_valid_cancel_rollback() == ESP_OK; }

void EspOtaPlatform::markInvalidAndReboot() {
    // Reboots into the previous image; returns only when there is none to roll back to.
    esp_err_t e = esp_ota_mark_app_invalid_rollback_and_reboot();
    log_e("fleet-ota: rollback not possible (%d)", (int)e);
}

void EspOtaPlatform::reboot() { esp_restart(); }

// ------------------------------------------------------------------ NVS
namespace { const char* kNs = "fleet_ota"; }

bool NvsStore::get(const char* key, char* out, size_t cap) {
    Preferences p;
    if (!p.begin(kNs, true)) return false;
    bool ok = false;
    if (p.isKey(key)) {
        size_t n = p.getString(key, out, cap);
        ok = n > 0 && n < cap;
    }
    p.end();
    return ok;
}

bool NvsStore::put(const char* key, const char* value) {
    Preferences p;
    if (!p.begin(kNs, false)) return false;
    bool ok = p.putString(key, value) == strlen(value);
    p.end();
    return ok;
}

bool NvsStore::remove(const char* key) {
    Preferences p;
    if (!p.begin(kNs, false)) return false;
    if (p.isKey(key)) p.remove(key);
    p.end();
    return true;
}

// ------------------------------------------------------------------ crypto
MbedtlsSha256::MbedtlsSha256() { mbedtls_sha256_init(&ctx_); }
MbedtlsSha256::~MbedtlsSha256() { mbedtls_sha256_free(&ctx_); }
void MbedtlsSha256::begin() { mbedtls_sha256_starts(&ctx_, 0); }
void MbedtlsSha256::update(const uint8_t* d, size_t n) { mbedtls_sha256_update(&ctx_, d, n); }
void MbedtlsSha256::finish(uint8_t out[32]) { mbedtls_sha256_finish(&ctx_, out); }

bool MbedtlsEcdsaP256::verify(const uint8_t* key, size_t keyLen, const uint8_t hash[32], const uint8_t* sig,
                              size_t sigLen) {
    uint8_t pem[300];
    const uint8_t* k = key;
    size_t klen = keyLen;
    if (keyLen >= 10 && memcmp(key, "-----BEGIN", 10) == 0) {   // mbedTLS wants PEM NUL-terminated, NUL counted
        if (keyLen + 1 > sizeof(pem)) return false;
        memcpy(pem, key, keyLen);
        pem[keyLen] = 0;
        k = pem;
        klen = keyLen + 1;
    }
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    bool ok = false;
    if (mbedtls_pk_parse_public_key(&pk, k, klen) == 0 && mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY) {
        const mbedtls_ecp_keypair* ec = mbedtls_pk_ec(pk);
        if (ec && mbedtls_ecp_keypair_get_group_id(ec) == MBEDTLS_ECP_DP_SECP256R1)
            ok = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sigLen) == 0;
    }
    mbedtls_pk_free(&pk);
    return ok;
}

// ------------------------------------------------------------------ wiring
EspFleetOta::EspFleetOta(const OtaConfig& cfg, const DeviceIdentity& dev, IDeviceHooks& hooks, const uint8_t* caBundle,
                         size_t caBundleLen)
    : http_(caBundle, caBundleLen, cfg.download.stallTimeoutMs),
      ota_(cfg, dev, OtaDeps{http_, writer_, platform_, store_, hooks, clock_, sha_, ecdsa_}) {}

} // namespace fota
#endif
