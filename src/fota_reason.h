// Reason codes for every refusal and failure. Stable snake_case names are what devices report over MCP/MQTT and what
// is persisted in last_result, so never renumber or rename: append. No Arduino headers.
#pragma once
#include <cstdint>

namespace fota {

enum class Reason : uint8_t {
    none = 0,
    // fetching and verifying the manifest
    manifest_fetch_failed,
    manifest_invalid,
    signature_fetch_failed,
    signature_bad_format,
    unknown_key_id,
    key_version_mismatch,
    signature_invalid,
    // policy checks on a verified manifest
    wrong_product,
    wrong_chip,
    wrong_board,
    wrong_channel,
    not_newer,
    below_floor,
    running_version_invalid,
    too_large,
    url_not_https,
    host_not_allowed,
    // ota_update preconditions
    no_update_available,
    version_mismatch,
    busy,
    device_refused,         // canUpdateNow() said no
    // download and write
    begin_failed,
    download_failed,
    timeout,
    truncated,
    oversize,
    write_failed,
    hash_mismatch,
    finalize_failed,
    // after the reboot into the new image
    self_test_failed,
    self_test_timeout,
    boot_failed,            // the new image never confirmed (bootloader rolled back)
    store_failed,
    crypto_self_check_failed,   // the SHA-256/ECDSA backend failed its known-answer test: fail closed
    rejected,               // this version failed its self-test or was rolled back here before (update(v, force) overrides)
    _count
};

const char* reasonName(Reason r);
// Reverse of reasonName; returns false for unknown names.
bool reasonFromName(const char* name, Reason& out);

} // namespace fota
