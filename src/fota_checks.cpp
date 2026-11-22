#include "fota_checks.h"
#include <cstring>
#include "fota_semver.h"

namespace fota {

namespace {
char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }
bool ieq(const char* a, const char* b) {
    for (; *a && *b; a++, b++) if (lower(*a) != lower(*b)) return false;
    return *a == *b;
}
bool empty(const char* s) { return !s || !*s; }
} // namespace

bool httpsUrlHost(const char* url, char* out, size_t cap) {
    if (!url || strncmp(url, "https://", 8) != 0) return false;
    const char* h = url + 8;
    size_t n = strcspn(h, "/?#");               // authority
    const char* colon = (const char*)memchr(h, ':', n);
    if (memchr(h, '@', n) || memchr(h, '[', n)) return false;    // no userinfo, no IPv6 literals
    size_t hostLen = colon ? (size_t)(colon - h) : n;
    if (colon) {
        size_t portLen = n - hostLen - 1;
        if (portLen != 3 || memcmp(colon + 1, "443", 3) != 0) return false;
    }
    if (hostLen == 0 || hostLen + 1 > cap) return false;
    for (size_t i = 0; i < hostLen; i++) out[i] = lower(h[i]);
    out[hostLen] = 0;
    return true;
}

bool urlHostAllowed(const char* url, const char* const* hosts, size_t count) {
    char host[128];
    if (!httpsUrlHost(url, host, sizeof(host))) return false;
    for (size_t i = 0; i < count && hosts; i++)
        if (hosts[i] && ieq(hosts[i], host)) return true;
    return false;
}

Reason checkManifest(const Manifest& m, const DeviceIdentity& dev, const CheckConfig& cfg, const char* floor,
                     uint32_t spareSlotBytes) {
    if (empty(dev.product) || strcmp(m.product, dev.product) != 0) return Reason::wrong_product;
    if (empty(dev.chip) || strcmp(m.chip, dev.chip) != 0) return Reason::wrong_chip;
    if (m.hasBoard() && (empty(dev.board) || strcmp(m.board, dev.board) != 0)) return Reason::wrong_board;
    if (empty(cfg.channel) || strcmp(m.channel, cfg.channel) != 0) return Reason::wrong_channel;

    if (strncmp(m.url, "https://", 8) != 0) return Reason::url_not_https;
    if (!urlHostAllowed(m.url, cfg.allowed_hosts, cfg.allowed_host_count)) return Reason::host_not_allowed;

    SemVer running, offered;
    if (!parseSemVer(dev.running_version, running)) return Reason::running_version_invalid;
    if (!parseSemVer(m.version, offered)) return Reason::not_newer;     // the parser already refuses this
    if (compareSemVer(offered, running) <= 0) return Reason::not_newer;
    SemVer fl;
    if (!empty(floor) && parseSemVer(floor, fl) && compareSemVer(offered, fl) < 0) return Reason::below_floor;

    if (m.size == 0 || m.size > spareSlotBytes) return Reason::too_large;
    return Reason::none;
}

void nextFloor(const char* oldFloor, const Manifest& m, char* out, size_t cap) {
    if (!out || cap == 0) return;
    SemVer a, b;
    const bool hasOld = !empty(oldFloor) && parseSemVer(oldFloor, a);
    const bool hasNew = m.hasMinVersion() && parseSemVer(m.min_version, b);
    const char* pick = "";
    if (hasOld && hasNew) pick = compareSemVer(a, b) >= 0 ? oldFloor : m.min_version;
    else if (hasOld) pick = oldFloor;
    else if (hasNew) pick = m.min_version;
    strncpy(out, pick, cap - 1);
    out[cap - 1] = 0;
}

} // namespace fota
