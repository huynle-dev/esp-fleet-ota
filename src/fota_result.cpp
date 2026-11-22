#include "fota_result.h"
#include <cstdio>
#include <cstring>
#include "fota_semver.h"

namespace fota {

namespace {
const char* const kKinds[] = {"none", "ok", "rolled_back", "refused", "failed"};
constexpr size_t kKindCount = sizeof(kKinds) / sizeof(kKinds[0]);
const char* kKey = "last_result";
} // namespace

const char* resultKindName(ResultKind k) { return (size_t)k < kKindCount ? kKinds[(size_t)k] : "none"; }

void formatLastResult(const LastResult& r, char* out, size_t cap) {
    if (!out || !cap) return;
    snprintf(out, cap, "%s|%s|%s", resultKindName(r.kind), reasonName(r.reason), r.version);
}

bool parseLastResult(const char* text, LastResult& r) {
    r = LastResult();
    if (!text) return false;
    const char* a = strchr(text, '|');
    if (!a) return false;
    const char* b = strchr(a + 1, '|');
    if (!b || strchr(b + 1, '|')) return false;
    char kind[16], reason[40];
    size_t kl = (size_t)(a - text), rl = (size_t)(b - a - 1), vl = strlen(b + 1);
    if (kl >= sizeof(kind) || rl >= sizeof(reason) || vl >= sizeof(r.version)) return false;
    memcpy(kind, text, kl); kind[kl] = 0;
    memcpy(reason, a + 1, rl); reason[rl] = 0;
    LastResult x;
    bool found = false;
    for (size_t i = 0; i < kKindCount; i++)
        if (!strcmp(kKinds[i], kind)) { x.kind = (ResultKind)i; found = true; }
    if (!found || !reasonFromName(reason, x.reason)) return false;
    memcpy(x.version, b + 1, vl + 1);
    SemVer sv;
    if (vl && !parseSemVer(x.version, sv)) return false;
    r = x;
    return true;
}

bool saveLastResult(IStore& store, const LastResult& r) {
    char buf[kLastResultTextMax];
    formatLastResult(r, buf, sizeof(buf));
    return store.put(kKey, buf);
}

LastResult loadLastResult(IStore& store) {
    char buf[kLastResultTextMax];
    LastResult r;
    if (store.get(kKey, buf, sizeof(buf))) parseLastResult(buf, r);
    return r;
}

} // namespace fota
