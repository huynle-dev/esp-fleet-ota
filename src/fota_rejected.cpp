#include "fota_rejected.h"
#include <cstring>
#include "fota_semver.h"

namespace fota {

namespace {

const char* kKey = "rejected";

bool validVersion(const char* v) {
    SemVer sv;
    return v && *v && strlen(v) < sizeof(RejectedVersions::version[0]) && parseSemVer(v, sv);
}

// Index of the entry with the same precedence as v, or -1.
int find(const RejectedVersions& r, const char* v) {
    for (uint8_t i = 0; i < r.count; i++) {
        int c = 0;
        if (compareVersions(r.version[i], v, c) && c == 0) return i;
    }
    return -1;
}

void removeAt(RejectedVersions& r, uint8_t i) {
    for (uint8_t k = i; k + 1 < r.count; k++) memcpy(r.version[k], r.version[k + 1], sizeof(r.version[k]));
    r.count--;
    memset(r.version[r.count], 0, sizeof(r.version[r.count]));
}

} // namespace

bool RejectedVersions::contains(const char* v) const { return validVersion(v) && find(*this, v) >= 0; }

bool RejectedVersions::add(const char* v) {
    if (!validVersion(v)) return false;
    int i = find(*this, v);
    if (i >= 0) removeAt(*this, (uint8_t)i);
    else if (count == kMaxRejected) removeAt(*this, 0);        // evict the oldest
    strcpy(version[count++], v);
    return true;
}

bool RejectedVersions::clearUpTo(const char* v) {
    if (!validVersion(v)) return false;
    bool changed = false;
    for (uint8_t i = 0; i < count;) {
        int c = 0;
        if (compareVersions(version[i], v, c) && c <= 0) { removeAt(*this, i); changed = true; }
        else i++;
    }
    return changed;
}

void formatRejected(const RejectedVersions& r, char* out, size_t cap) {
    if (!out || !cap) return;
    size_t n = 0;
    out[0] = 0;
    for (uint8_t i = 0; i < r.count; i++) {
        const size_t len = strlen(r.version[i]);
        if (n + (i ? 1 : 0) + len + 1 > cap) { out[0] = 0; return; }   // never a truncated list
        if (i) out[n++] = ',';
        memcpy(out + n, r.version[i], len + 1);
        n += len;
    }
}

RejectedVersions parseRejected(const char* text) {
    RejectedVersions r;
    if (!text) return r;
    const char* p = text;
    while (true) {
        const char* e = strchr(p, ',');
        const size_t len = e ? (size_t)(e - p) : strlen(p);
        char v[sizeof(r.version[0])];
        if (len > 0 && len < sizeof(v)) {
            memcpy(v, p, len);
            v[len] = 0;
            r.add(v);                // validates, de-duplicates and keeps the newest kMaxRejected
        }
        if (!e) break;
        p = e + 1;
    }
    return r;
}

RejectedVersions loadRejected(IStore& store) {
    char buf[kRejectedTextMax];
    if (!store.get(kKey, buf, sizeof(buf))) return RejectedVersions();
    return parseRejected(buf);
}

bool saveRejected(IStore& store, const RejectedVersions& r) {
    if (!r.count) return store.remove(kKey);
    char buf[kRejectedTextMax];
    formatRejected(r, buf, sizeof(buf));
    return store.put(kKey, buf);
}

} // namespace fota
