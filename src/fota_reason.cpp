#include "fota_reason.h"
#include <cstring>

namespace fota {

namespace {
const char* const kNames[] = {
    "none",
    "manifest_fetch_failed", "manifest_invalid", "signature_fetch_failed", "signature_bad_format", "unknown_key_id",
    "key_version_mismatch", "signature_invalid",
    "wrong_product", "wrong_chip", "wrong_board", "wrong_channel", "not_newer", "below_floor", "running_version_invalid",
    "too_large", "url_not_https", "host_not_allowed",
    "no_update_available", "version_mismatch", "busy", "device_refused",
    "begin_failed", "download_failed", "timeout", "truncated", "oversize", "write_failed", "hash_mismatch",
    "finalize_failed",
    "self_test_failed", "self_test_timeout", "boot_failed", "store_failed",
    "crypto_self_check_failed",
};
static_assert(sizeof(kNames) / sizeof(kNames[0]) == (size_t)Reason::_count, "one name per Reason");
} // namespace

const char* reasonName(Reason r) {
    return (size_t)r < (size_t)Reason::_count ? kNames[(size_t)r] : "unknown";
}

bool reasonFromName(const char* name, Reason& out) {
    if (!name) return false;
    for (size_t i = 0; i < (size_t)Reason::_count; i++)
        if (!strcmp(kNames[i], name)) { out = (Reason)i; return true; }
    return false;
}

} // namespace fota
