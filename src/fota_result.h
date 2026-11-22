// The outcome of the last update attempt, persisted across reboots (store key "last_result") and reported by
// ota_status. Text form: "<kind>|<reason>|<version>", e.g. "rolled_back|self_test_failed|1.4.0". No Arduino headers.
#pragma once
#include <cstddef>
#include "fota_io.h"
#include "fota_reason.h"

namespace fota {

enum class ResultKind : uint8_t { none, ok, rolled_back, refused, failed };

const char* resultKindName(ResultKind k);

struct LastResult {
    ResultKind kind = ResultKind::none;
    Reason reason = Reason::none;
    char version[33] = {0};    // the version the attempt was about ("" when unknown)
};

constexpr size_t kLastResultTextMax = 96;

// Writes the text form into out[cap] (cap >= kLastResultTextMax is always enough).
void formatLastResult(const LastResult& r, char* out, size_t cap);
// Strict parse; false (and r reset to none) on anything malformed.
bool parseLastResult(const char* text, LastResult& r);

bool saveLastResult(IStore& store, const LastResult& r);
LastResult loadLastResult(IStore& store);   // none when absent or corrupt

} // namespace fota
