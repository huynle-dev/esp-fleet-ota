#include "fota_semver.h"
#include <cstring>

namespace fota {

namespace {

bool isDigit(char c) { return c >= '0' && c <= '9'; }
bool isIdentChar(char c) { return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-'; }

// Numeric core component at s[i..]: no leading zero (except "0"), fits uint32. Advances i.
bool parseNumber(const char* s, size_t& i, uint32_t& out) {
    if (!isDigit(s[i])) return false;
    if (s[i] == '0' && isDigit(s[i + 1])) return false;
    uint64_t v = 0;
    while (isDigit(s[i])) {
        v = v * 10 + (uint64_t)(s[i] - '0');
        if (v > 0xFFFFFFFFull) return false;
        i++;
    }
    out = (uint32_t)v;
    return true;
}

// Dot-separated identifiers [0-9A-Za-z-]+ in s[begin, end). `numericRule`: numeric identifiers must not have leading
// zeros (prerelease); build metadata has no such rule.
bool validIdentifiers(const char* s, size_t begin, size_t end, bool numericRule) {
    if (begin >= end) return false;
    size_t start = begin;
    for (size_t i = begin; i <= end; i++) {
        if (i == end || s[i] == '.') {
            if (i == start) return false;   // empty identifier
            if (numericRule) {
                bool allDigits = true;
                for (size_t k = start; k < i; k++) allDigits = allDigits && isDigit(s[k]);
                if (allDigits && i - start > 1 && s[start] == '0') return false;
            }
            start = i + 1;
        } else if (!isIdentChar(s[i])) {
            return false;
        }
    }
    return true;
}

bool allDigits(const char* s, size_t n) {
    for (size_t i = 0; i < n; i++) if (!isDigit(s[i])) return false;
    return n > 0;
}

// Compare one prerelease identifier pair (§11.4.1-3).
int compareIdent(const char* a, size_t na, const char* b, size_t nb) {
    const bool da = allDigits(a, na), db = allDigits(b, nb);
    if (da && db) {                         // no leading zeros, so longer is larger
        if (na != nb) return na < nb ? -1 : 1;
        int c = memcmp(a, b, na);
        return c < 0 ? -1 : (c > 0 ? 1 : 0);
    }
    if (da) return -1;                      // numeric < alphanumeric
    if (db) return 1;
    size_t n = na < nb ? na : nb;
    int c = memcmp(a, b, n);                // ASCII order
    if (c) return c < 0 ? -1 : 1;
    if (na != nb) return na < nb ? -1 : 1;
    return 0;
}

} // namespace

bool parseSemVer(const char* s, SemVer& out) {
    if (!s) return false;
    const size_t len = strnlen(s, 65);
    if (len == 0 || len > 64) return false;
    SemVer v;
    size_t i = 0;
    if (!parseNumber(s, i, v.major) || s[i++] != '.') return false;
    if (!parseNumber(s, i, v.minor) || s[i++] != '.') return false;
    if (!parseNumber(s, i, v.patch)) return false;
    if (s[i] == '-') {
        size_t begin = ++i;
        while (s[i] && s[i] != '+') i++;
        if (!validIdentifiers(s, begin, i, true)) return false;
        memcpy(v.pre, s + begin, i - begin);
        v.pre[i - begin] = 0;
    }
    if (s[i] == '+') {
        size_t begin = ++i;
        while (s[i]) i++;
        if (!validIdentifiers(s, begin, i, false)) return false;
    }
    if (s[i] != 0) return false;
    out = v;
    return true;
}

int compareSemVer(const SemVer& a, const SemVer& b) {
    if (a.major != b.major) return a.major < b.major ? -1 : 1;
    if (a.minor != b.minor) return a.minor < b.minor ? -1 : 1;
    if (a.patch != b.patch) return a.patch < b.patch ? -1 : 1;
    const bool pa = a.pre[0] != 0, pb = b.pre[0] != 0;
    if (!pa && !pb) return 0;
    if (!pa) return 1;                      // a release has higher precedence than its prereleases
    if (!pb) return -1;
    const char* x = a.pre;
    const char* y = b.pre;
    while (true) {
        size_t nx = strcspn(x, "."), ny = strcspn(y, ".");
        int c = compareIdent(x, nx, y, ny);
        if (c) return c;
        const bool endX = x[nx] == 0, endY = y[ny] == 0;
        if (endX && endY) return 0;
        if (endX) return -1;                // fewer identifiers = lower precedence
        if (endY) return 1;
        x += nx + 1;
        y += ny + 1;
    }
}

bool compareVersions(const char* a, const char* b, int& cmp) {
    SemVer va, vb;
    if (!parseSemVer(a, va) || !parseSemVer(b, vb)) return false;
    cmp = compareSemVer(va, vb);
    return true;
}

} // namespace fota
