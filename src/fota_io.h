// Everything the pure logic needs from the device, as small interfaces. The ESP glue (src/esp/) implements them;
// the native tests use fakes. No Arduino headers.
#pragma once
#include <cstddef>
#include <cstdint>
#include "fota_reason.h"

namespace fota {

class IClock {
public:
    virtual ~IClock() = default;
    virtual uint64_t nowMs() = 0;   // monotonic
    virtual void feedWatchdog() {}  // called between chunks and while polling
    virtual void idle() {}          // brief yield while waiting for network data (device: delay(1) + feed)
};

// One HTTPS GET. Device: NetworkClientSecure with the CA bundle and host name verification (never setInsecure).
class IHttpSource {
public:
    virtual ~IHttpSource() = default;
    // Starts the request. On success `contentLength` is the Content-Length, or -1 when unknown (chunked).
    // Non-2xx statuses, TLS or connect failures return false.
    virtual bool open(const char* url, int64_t& contentLength) = 0;
    // > 0: bytes copied into buf; 0: no data available right now; kEof: the body ended; kError: broken connection.
    virtual int read(uint8_t* buf, size_t cap) = 0;
    virtual void close() = 0;
    static constexpr int kEof = -1;
    static constexpr int kError = -2;
};

// The spare OTA slot. Device: esp_ota_begin/write/end + esp_ota_set_boot_partition.
class IPartitionWriter {
public:
    virtual ~IPartitionWriter() = default;
    virtual uint32_t spareSize() = 0;                    // 0 when there is no spare OTA slot
    virtual bool begin(uint32_t imageSize) = 0;          // prepare (erase) the spare slot; NOT bootable
    virtual bool write(const uint8_t* data, size_t len) = 0;
    // Only after the SHA-256 matched: validate the image and make it the next boot partition.
    virtual bool commit() = 0;
    // Discard a partial or rejected image. The spare slot must not be bootable afterwards.
    virtual void abort() = 0;
};

// Boot/rollback state of the running image. Device: esp_ota_get_state_partition, esp_ota_mark_app_valid_cancel_rollback,
// esp_ota_mark_app_invalid_rollback_and_reboot, esp_restart.
class IOtaPlatform {
public:
    virtual ~IOtaPlatform() = default;
    virtual const char* runningSlot() = 0;               // partition label, e.g. "app0"
    virtual bool pendingVerify() = 0;                    // the running image was just installed and awaits confirmation
    virtual bool markValid() = 0;                        // cancel rollback: keep this image
    virtual void markInvalidAndReboot() = 0;             // roll back to the previous image (does not return on device)
    virtual void reboot() = 0;                           // does not return on device
};

// Small persistent key/value store. Device: NVS via Preferences (namespace "fleet_ota").
class IStore {
public:
    virtual ~IStore() = default;
    // Copies the value (NUL-terminated) into out[cap]; false when absent or it does not fit.
    virtual bool get(const char* key, char* out, size_t cap) = 0;
    virtual bool put(const char* key, const char* value) = 0;
    virtual bool remove(const char* key) = 0;
};

enum class SelfTest : uint8_t { pending, pass, fail };

// Device policy. canUpdateNow: e.g. the PSU refuses while its output is on or a job runs (`why` explains, may be "").
class IDeviceHooks {
public:
    virtual ~IDeviceHooks() = default;
    virtual bool canUpdateNow(char* why, size_t cap) { (void)why; (void)cap; return true; }
    virtual void onBeforeUpdate() {}                     // e.g. close sessions, stop tasks that touch flash
    // Called repeatedly after a reboot into a new image until it returns pass/fail or the deadline expires.
    virtual SelfTest selfTest() { return SelfTest::pass; }
};

} // namespace fota
