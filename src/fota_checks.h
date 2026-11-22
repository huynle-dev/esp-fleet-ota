// Policy checks on a parsed (and signature-verified) manifest, before anything is downloaded. No Arduino headers.
#pragma once
#include <cstddef>
#include <cstdint>
#include "fota_manifest.h"
#include "fota_reason.h"

namespace fota {

struct DeviceIdentity {
    const char* product;          // e.g. "example-psu"
    const char* chip;             // CONFIG_IDF_TARGET, e.g. "esp32c3" (see fota_target.h)
    const char* board;            // e.g. "esp32-c3-devkitm-1"; "" or null when the device does not know
    const char* running_version;  // semver of the running image
};

struct CheckConfig {
    const char* channel;                  // "stable" | "beta"
    const char* const* allowed_hosts;     // exact host names (case-insensitive), no wildcards
    size_t allowed_host_count;
};

// Returns Reason::none when the manifest may be installed on this device. `floor` is the persisted anti-downgrade
// floor ("" or null when none). `spareSlotBytes` is the size of the partition the image would be written to.
// Order of checks (first failure wins): product, chip, board, channel, url scheme, host, running version parse,
// newer than running, at least the floor, size fits.
Reason checkManifest(const Manifest& m, const DeviceIdentity& dev, const CheckConfig& cfg, const char* floor,
                     uint32_t spareSlotBytes);

// Extracts the host of an https URL into out[cap]. Refuses userinfo ('@'), empty hosts and ports other than 443.
bool httpsUrlHost(const char* url, char* out, size_t cap);

// true when `url` is https (port 443) and its host is in the allow-list (exact, case-insensitive).
bool urlHostAllowed(const char* url, const char* const* hosts, size_t count);

// The new floor to persist after an image passed its self-test: max(oldFloor, m.min_version). Writes into out[cap].
void nextFloor(const char* oldFloor, const Manifest& m, char* out, size_t cap);

} // namespace fota
