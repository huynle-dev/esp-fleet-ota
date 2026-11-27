// FleetOta: the update state machine and the API a device exposes over its MCP server / MQTT. No Arduino headers.
//
//   idle --check()--> checking --ok--> available --update(v)--> downloading --> verifying --> rebooting --reboot-->
//   pending_verify --selfTest pass--> ok        (image marked valid, floor raised, last_result ok)
//                  --fail/deadline--> (last_result rolled_back, markInvalidAndReboot -> previous image boots)
//   any download/write/hash failure --> failed (spare slot aborted, never bootable, last_result failed)
//
// ota_status -> status() / formatStatusJson(); ota_check -> check(); ota_update -> update(expectedVersion).
// Single-threaded: call begin() once after boot, then loop() often from the device's main loop.
#pragma once
#include <cstddef>
#include <cstdint>
#include "fota_checks.h"
#include "fota_crypto.h"
#include "fota_download.h"
#include "fota_io.h"
#include "fota_manifest.h"
#include "fota_reason.h"
#include "fota_rejected.h"
#include "fota_result.h"
#include "fota_signature.h"

namespace fota {

enum class State : uint8_t { idle, checking, available, downloading, verifying, rebooting, pending_verify, ok, failed };
const char* stateName(State s);

constexpr uint32_t kMinAutoCheckIntervalMs = 3600000;    // 1 h

struct AutoCheck {
    bool enabled = false;                    // OFF by default
    uint32_t interval_ms = 6 * 3600000u;     // clamped to >= kMinAutoCheckIntervalMs
};

struct OtaConfig {
    const char* manifest_url = nullptr;      // https://fw.example.com/<product>/<chip>/<channel>/manifest.json
    const char* signature_url = nullptr;     // null: manifest_url + ".sig"
    const char* channel = "stable";          // "stable" | "beta" | "dev"; must equal the manifest's channel
    const char* const* allowed_hosts = nullptr;
    size_t allowed_host_count = 0;
    const TrustedKey* keys = nullptr;
    size_t key_count = 0;
    uint32_t self_test_deadline_ms = 120000;
    uint32_t reboot_delay_ms = 2000;         // lets the device answer the MCP call before restarting
    uint32_t fetch_timeout_ms = 15000;       // manifest and signature, each
    DownloadLimits download;
    AutoCheck auto_check;
};

struct OtaDeps {
    IHttpSource& http;
    IPartitionWriter& writer;
    IOtaPlatform& platform;
    IStore& store;
    IDeviceHooks& hooks;
    IClock& clock;
    ISha256& sha;
    IEcdsaP256Verifier& ecdsa;
};

struct OtaStatus {
    const char* current_version;
    const char* running_slot;
    State state;
    LastResult last_result;
    const char* available_version;           // "" when none
    Reason last_check;                       // outcome of the most recent check (none = ok)
    uint32_t progress_bytes, total_bytes;
    bool auto_check_enabled;
    uint32_t auto_check_interval_ms;
    const RejectedVersions* rejected;        // versions refused as `rejected` (oldest first); never null from status()
};

class FleetOta {
public:
    FleetOta(const OtaConfig& cfg, const DeviceIdentity& dev, const OtaDeps& deps);

    // Reconciles the boot: a new image awaiting confirmation enters pending_verify; a record of an install whose image
    // is not running means the bootloader rolled back (last_result rolled_back/boot_failed).
    void begin();
    void loop();

    // Fetch + verify the manifest and signature, run the policy checks. Never installs. Returns Reason::none when an
    // update is available (state available, availableVersion() set). Blocking but bounded by fetch_timeout_ms.
    Reason check();
    // Start installing `expectedVersion`. Re-checks first; refuses when the available version differs, when the device
    // hook says no, or while busy. Returns Reason::none when the download started (progress via loop()).
    // `force` = true installs a version that is in the rejected list (it failed its self-test or was rolled back here
    // before); it bypasses only that refusal, every other check still applies. Default: not forced.
    Reason update(const char* expectedVersion, bool force = false);

    void setAutoCheck(bool enabled, uint32_t intervalMs);

    OtaStatus status() const;
    State state() const { return state_; }
    const char* availableVersion() const { return available_.version; }

private:
    Reason fetch(const char* url, char* buf, size_t cap, size_t& len);
    Reason checkWith(bool force);
    void rememberRejected(const char* version);
    Reason verifyAndCheck(const char* text, size_t len, const char* sig, size_t sigLen, Manifest& out);
    void finishFailure(ResultKind kind, Reason r, const char* version);
    void loopPendingVerify();
    void loopDownload();
    void loopAutoCheck();
    void confirmInstalled(const char* version, const char* minVersion);

    OtaConfig cfg_;
    DeviceIdentity dev_;
    OtaDeps d_;
    Downloader dl_;
    State state_ = State::idle;
    Manifest available_;          // last verified manifest that passed the checks (valid when state_ == available)
    bool haveAvailable_ = false;
    Reason lastCheck_ = Reason::none;
    LastResult last_;
    RejectedVersions rejected_;   // loaded in begin(), persisted under "rejected"
    uint64_t verifyDeadline_ = 0, rebootAt_ = 0, nextAuto_ = 0;
    char pendingVersion_[33] = {0};
    char pendingMin_[33] = {0};
    int8_t cryptoOk_ = -1;        // -1 not run yet; known-answer test result, run once before the first check
};

// {"current_version":..,"running_slot":..,"state":..,"last_result":{"kind":..,"reason":..,"version":..},
//  "available_version":..|null,"last_check":..,"progress":..,"total":..,"auto_check":{"enabled":..,"interval_s":..}
//  [,"rejected":["<v>",...]]}        (the "rejected" key only when the list is not empty, oldest first)
// Returns the length written, or 0 when it does not fit in cap (768 bytes always fit).
size_t formatStatusJson(const OtaStatus& s, char* out, size_t cap);

} // namespace fota
