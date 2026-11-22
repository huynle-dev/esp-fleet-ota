// Semantic Versioning 2.0.0 parsing and precedence (https://semver.org §2, §9, §10, §11). No Arduino headers.
//
// Strict: MAJOR.MINOR.PATCH with no leading zeros, each <= 4294967295; optional -prerelease (dot-separated identifiers
// of [0-9A-Za-z-], numeric identifiers without leading zeros) and +build metadata (ignored for precedence). No "v"
// prefix, no whitespace. Max 64 characters.
#pragma once
#include <cstddef>
#include <cstdint>

namespace fota {

struct SemVer {
    uint32_t major = 0, minor = 0, patch = 0;
    char pre[64] = {0};     // prerelease without the leading '-', "" when none
};

// true when `s` (NUL-terminated) is a valid version; fills `out`.
bool parseSemVer(const char* s, SemVer& out);

// <0 when a < b, 0 when equal precedence, >0 when a > b (build metadata ignored).
int compareSemVer(const SemVer& a, const SemVer& b);

// Convenience for two strings; both must parse. Returns false when either is invalid, else sets cmp.
bool compareVersions(const char* a, const char* b, int& cmp);

} // namespace fota
