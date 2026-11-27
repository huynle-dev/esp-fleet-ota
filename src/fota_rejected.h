// Rejected-version memory: versions whose installed image failed its self-test or was rolled back. An offer of a
// remembered version is refused (`Reason::rejected`) unless the update request forces it, so a device does not loop
// installing an image that already failed on it. No Arduino headers, no heap.
//
// Persisted in the store under key "rejected" as a comma-separated list, oldest first, e.g. "1.4.0,1.5.0-rc.1".
// Bounded to kMaxRejected entries (the oldest is evicted). A missing key is an empty list; entries that are not valid
// semver are dropped when loading. Versions are compared by semver precedence (build metadata ignored), never by
// signature or hash, so re-signing or re-hosting the same version does not bypass the memory.
#pragma once
#include <cstddef>
#include <cstdint>
#include "fota_io.h"

namespace fota {

constexpr size_t kMaxRejected = 8;
constexpr size_t kRejectedTextMax = kMaxRejected * 33;   // 8 versions of <= 32 chars + separators + NUL

struct RejectedVersions {
    char version[kMaxRejected][33] = {};   // oldest first
    uint8_t count = 0;

    // true when a remembered version has the same precedence as `v`.
    bool contains(const char* v) const;
    // Remembers `v` as the newest entry (an equal entry moves to the end); evicts the oldest when full. Invalid
    // versions are ignored. Returns true when the list changed.
    bool add(const char* v);
    // Forgets every entry <= `v` (after `v` was installed and confirmed). Returns true when the list changed.
    bool clearUpTo(const char* v);
};

// Text form "<v1>,<v2>,..." into out[cap] (cap >= kRejectedTextMax is always enough); "" for an empty list.
void formatRejected(const RejectedVersions& r, char* out, size_t cap);
// Lenient parse: keeps the valid semver entries (at most the newest kMaxRejected), drops the rest.
RejectedVersions parseRejected(const char* text);

RejectedVersions loadRejected(IStore& store);              // empty when absent
bool saveRejected(IStore& store, const RejectedVersions& r);   // removes the key when the list is empty

} // namespace fota
