#include "fleet_ota.h"
#include <cstdio>
#include <cstring>
#include <new>
#include "fota_selfcheck.h"
#include "fota_semver.h"

namespace fota {

namespace {

const char* kPendingKey = "pending";   // "<version>|<min_version>" of an image written but not yet confirmed
const char* kFloorKey = "floor";       // highest min_version of a confirmed image (anti-downgrade)

void copyStr(char* dst, size_t cap, const char* src) {
    if (!cap) return;
    if (!src) src = "";
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = 0;
}

bool validVersionOrEmpty(const char* v) {
    SemVer sv;
    return v && (!*v || parseSemVer(v, sv));
}

LastResult makeResult(ResultKind k, Reason r, const char* version) {
    LastResult x;
    x.kind = k;
    x.reason = r;
    if (validVersionOrEmpty(version)) copyStr(x.version, sizeof(x.version), version);
    return x;
}

Reason sigToReason(SigError e) {
    switch (e) {
        case SigError::Ok: return Reason::none;
        case SigError::UnknownKeyId: return Reason::unknown_key_id;
        case SigError::BadFormat: return Reason::signature_bad_format;
        case SigError::KeyVersionMismatch: return Reason::key_version_mismatch;
        case SigError::Invalid: return Reason::signature_invalid;
    }
    return Reason::signature_invalid;
}

Reason checkUrl(const char* url, const OtaConfig& cfg) {
    if (!url || strncmp(url, "https://", 8) != 0) return Reason::url_not_https;
    if (!urlHostAllowed(url, cfg.allowed_hosts, cfg.allowed_host_count)) return Reason::host_not_allowed;
    return Reason::none;
}

// Copies s with characters that would break a JSON string removed.
void jsonSafe(char* dst, size_t cap, const char* s) {
    size_t n = 0;
    for (; s && *s && n + 1 < cap; s++)
        if ((unsigned char)*s >= 0x20 && *s != '"' && *s != '\\') dst[n++] = *s;
    dst[n] = 0;
}

} // namespace

const char* stateName(State s) {
    switch (s) {
        case State::idle: return "idle";
        case State::checking: return "checking";
        case State::available: return "available";
        case State::downloading: return "downloading";
        case State::verifying: return "verifying";
        case State::rebooting: return "rebooting";
        case State::pending_verify: return "pending_verify";
        case State::ok: return "ok";
        case State::failed: return "failed";
    }
    return "unknown";
}

FleetOta::FleetOta(const OtaConfig& c, const DeviceIdentity& d, const OtaDeps& deps)
    : cfg_(c), dev_(d), d_(deps), dl_(deps.http, deps.writer, deps.sha, deps.clock) {
    if (cfg_.auto_check.interval_ms < kMinAutoCheckIntervalMs) cfg_.auto_check.interval_ms = kMinAutoCheckIntervalMs;
}

void FleetOta::setAutoCheck(bool enabled, uint32_t intervalMs) {
    cfg_.auto_check.enabled = enabled;
    cfg_.auto_check.interval_ms = intervalMs < kMinAutoCheckIntervalMs ? kMinAutoCheckIntervalMs : intervalMs;
    nextAuto_ = d_.clock.nowMs() + cfg_.auto_check.interval_ms;
}

void FleetOta::begin() {
    const uint64_t now = d_.clock.nowMs();
    last_ = loadLastResult(d_.store);
    rejected_ = loadRejected(d_.store);
    nextAuto_ = now + cfg_.auto_check.interval_ms;

    char rec[80];
    bool havePending = d_.store.get(kPendingKey, rec, sizeof(rec));
    pendingVersion_[0] = pendingMin_[0] = 0;
    if (havePending) {
        char* bar = strchr(rec, '|');
        if (bar) *bar = 0;
        copyStr(pendingVersion_, sizeof(pendingVersion_), rec);
        copyStr(pendingMin_, sizeof(pendingMin_), bar ? bar + 1 : "");
        if (!validVersionOrEmpty(pendingVersion_) || !validVersionOrEmpty(pendingMin_)) {
            pendingVersion_[0] = pendingMin_[0] = 0;
            havePending = false;
            d_.store.remove(kPendingKey);
        }
    }

    if (d_.platform.pendingVerify()) {
        if (!havePending) copyStr(pendingVersion_, sizeof(pendingVersion_), dev_.running_version);
        verifyDeadline_ = now + cfg_.self_test_deadline_ms;
        state_ = State::pending_verify;
        return;
    }
    if (havePending) {
        if (dev_.running_version && !strcmp(pendingVersion_, dev_.running_version)) {
            confirmInstalled(pendingVersion_, pendingMin_);       // confirmed earlier, the record was not finished
        } else {
            last_ = makeResult(ResultKind::rolled_back, Reason::boot_failed, pendingVersion_);
            saveLastResult(d_.store, last_);
            rememberRejected(pendingVersion_);
            d_.store.remove(kPendingKey);
            state_ = State::idle;
        }
        return;
    }
    state_ = State::idle;
}

void FleetOta::confirmInstalled(const char* version, const char* minVersion) {
    char oldFloor[33] = {0};
    d_.store.get(kFloorKey, oldFloor, sizeof(oldFloor));
    Manifest m;
    copyStr(m.min_version, sizeof(m.min_version), minVersion);
    char floor[33];
    nextFloor(oldFloor, m, floor, sizeof(floor));
    if (floor[0] && strcmp(floor, oldFloor) != 0) d_.store.put(kFloorKey, floor);
    last_ = makeResult(ResultKind::ok, Reason::none, version);
    saveLastResult(d_.store, last_);
    if (rejected_.clearUpTo(version)) saveRejected(d_.store, rejected_);
    d_.store.remove(kPendingKey);
    state_ = State::ok;
}

void FleetOta::rememberRejected(const char* version) {
    if (rejected_.add(version)) saveRejected(d_.store, rejected_);
}

void FleetOta::loop() {
    switch (state_) {
        case State::pending_verify: loopPendingVerify(); return;
        case State::downloading:
        case State::verifying: loopDownload(); return;
        case State::rebooting:
            if (d_.clock.nowMs() >= rebootAt_) {
                rebootAt_ = UINT64_MAX;
                d_.platform.reboot();
            }
            return;
        default: loopAutoCheck(); return;
    }
}

void FleetOta::loopPendingVerify() {
    const uint64_t now = d_.clock.nowMs();
    Reason fail = Reason::none;
    if (now >= verifyDeadline_) {
        fail = Reason::self_test_timeout;
    } else {
        SelfTest r = d_.hooks.selfTest();
        if (r == SelfTest::pending) return;
        if (r == SelfTest::pass) {
            if (d_.platform.markValid()) {
                confirmInstalled(pendingVersion_, pendingMin_);
                return;
            }
            fail = Reason::boot_failed;
        } else {
            fail = Reason::self_test_failed;
        }
    }
    // Record first: markInvalidAndReboot does not return on the device.
    last_ = makeResult(ResultKind::rolled_back, fail, pendingVersion_);
    saveLastResult(d_.store, last_);
    rememberRejected(pendingVersion_);
    d_.store.remove(kPendingKey);
    state_ = State::failed;
    d_.platform.markInvalidAndReboot();
}

void FleetOta::finishFailure(ResultKind kind, Reason r, const char* version) {
    last_ = makeResult(kind, r, version);
    saveLastResult(d_.store, last_);
}

void FleetOta::loopDownload() {
    Downloader::Status st = dl_.step();
    if (st == Downloader::Status::running) {
        if (dl_.received() == dl_.total()) state_ = State::verifying;
        return;
    }
    if (st == Downloader::Status::done) {
        char rec[80];
        snprintf(rec, sizeof(rec), "%s|%s", pendingVersion_, pendingMin_);
        d_.store.put(kPendingKey, rec);
        rebootAt_ = d_.clock.nowMs() + cfg_.reboot_delay_ms;
        state_ = State::rebooting;
        return;
    }
    finishFailure(ResultKind::failed, dl_.reason(), pendingVersion_);
    haveAvailable_ = false;
    state_ = State::failed;
}

void FleetOta::loopAutoCheck() {
    if (!cfg_.auto_check.enabled) return;
    const uint64_t now = d_.clock.nowMs();
    if (now < nextAuto_) return;
    nextAuto_ = now + cfg_.auto_check.interval_ms;
    if (check() != Reason::none) return;
    char why[64] = {0};
    if (!d_.hooks.canUpdateNow(why, sizeof(why))) return;      // try again at the next interval
    char version[33];
    copyStr(version, sizeof(version), available_.version);
    update(version);
}

Reason FleetOta::fetch(const char* url, char* buf, size_t cap, size_t& len) {
    len = 0;
    int64_t clen = -1;
    if (!d_.http.open(url, clen)) return Reason::download_failed;
    if (clen >= 0 && (uint64_t)clen >= cap) { d_.http.close(); return Reason::oversize; }
    const uint64_t start = d_.clock.nowMs();
    Reason r = Reason::none;
    while (true) {
        d_.clock.feedWatchdog();
        if (d_.clock.nowMs() - start > cfg_.fetch_timeout_ms) { r = Reason::timeout; break; }
        if (len >= cap) { r = Reason::oversize; break; }
        int n = d_.http.read((uint8_t*)buf + len, cap - len);
        if (n == IHttpSource::kEof) break;
        if (n == IHttpSource::kError) { r = Reason::download_failed; break; }
        if (n == 0) { d_.clock.idle(); continue; }
        len += (size_t)n;
    }
    d_.http.close();
    return r;
}

Reason FleetOta::check() { return checkWith(false); }

Reason FleetOta::checkWith(bool force) {
    switch (state_) {
        case State::downloading: case State::verifying: case State::rebooting: case State::pending_verify:
            return Reason::busy;
        default: break;
    }
    haveAvailable_ = false;
    available_ = Manifest();
    if (cryptoOk_ < 0) cryptoOk_ = cryptoSelfCheck(d_.sha, d_.ecdsa) ? 1 : 0;
    if (!cryptoOk_) {
        lastCheck_ = Reason::crypto_self_check_failed;
        state_ = State::idle;
        return lastCheck_;
    }
    state_ = State::checking;

    Reason r = checkUrl(cfg_.manifest_url, cfg_);
    char sigUrl[300];
    if (r == Reason::none) {
        if (cfg_.signature_url) copyStr(sigUrl, sizeof(sigUrl), cfg_.signature_url);
        else if (strlen(cfg_.manifest_url) + 5 <= sizeof(sigUrl)) snprintf(sigUrl, sizeof(sigUrl), "%s.sig", cfg_.manifest_url);
        else sigUrl[0] = 0;
        r = checkUrl(sigUrl, cfg_);
    }

    char* text = nullptr;
    size_t textLen = 0;
    Manifest m;
    if (r == Reason::none) {
        text = new (std::nothrow) char[kMaxManifestBytes + 1];
        if (!text) r = Reason::manifest_fetch_failed;
    }
    if (r == Reason::none) {
        Reason f = fetch(cfg_.manifest_url, text, kMaxManifestBytes + 1, textLen);
        if (f == Reason::oversize) r = Reason::manifest_invalid;
        else if (f != Reason::none) r = Reason::manifest_fetch_failed;
        else if (parseManifest(text, textLen, m) != ManifestError::Ok) r = Reason::manifest_invalid;
    }
    if (r == Reason::none) {
        char sig[kMaxSignatureText + 1];
        size_t sigLen = 0;
        Reason f = fetch(sigUrl, sig, sizeof(sig), sigLen);
        if (f == Reason::oversize) r = Reason::signature_bad_format;
        else if (f != Reason::none) r = Reason::signature_fetch_failed;
        else r = sigToReason(verifyManifestSignature(text, textLen, m.key_id, sig, sigLen, cfg_.keys, cfg_.key_count,
                                                     d_.sha, d_.ecdsa));
    }
    delete[] text;
    if (r == Reason::none) {
        char floor[33] = {0};
        d_.store.get(kFloorKey, floor, sizeof(floor));
        CheckConfig cc{cfg_.channel, cfg_.allowed_hosts, cfg_.allowed_host_count};
        r = checkManifest(m, dev_, cc, floor, d_.writer.spareSize());
    }
    if (r == Reason::none && !force && rejected_.contains(m.version)) r = Reason::rejected;
    lastCheck_ = r;
    if (r == Reason::none) {
        available_ = m;
        haveAvailable_ = true;
        state_ = State::available;
    } else {
        state_ = State::idle;
    }
    return r;
}

Reason FleetOta::update(const char* expectedVersion, bool force) {
    switch (state_) {
        case State::downloading: case State::verifying: case State::rebooting: case State::pending_verify:
            return Reason::busy;
        default: break;
    }
    Reason r = checkWith(force);
    if (r != Reason::none) {
        finishFailure(ResultKind::refused, r, expectedVersion);
        return r;
    }
    if (!expectedVersion || strcmp(expectedVersion, available_.version) != 0) {
        finishFailure(ResultKind::refused, Reason::version_mismatch, expectedVersion);
        return Reason::version_mismatch;
    }
    char why[64] = {0};
    if (!d_.hooks.canUpdateNow(why, sizeof(why))) {
        finishFailure(ResultKind::refused, Reason::device_refused, expectedVersion);
        return Reason::device_refused;
    }
    copyStr(pendingVersion_, sizeof(pendingVersion_), available_.version);
    copyStr(pendingMin_, sizeof(pendingMin_), available_.min_version);
    d_.hooks.onBeforeUpdate();
    if (!dl_.start(available_.url, available_.size, available_.sha256, cfg_.download)) {
        finishFailure(ResultKind::failed, dl_.reason(), pendingVersion_);
        haveAvailable_ = false;
        state_ = State::failed;
        return dl_.reason();
    }
    state_ = State::downloading;
    return Reason::none;
}

OtaStatus FleetOta::status() const {
    const bool busy = state_ == State::downloading || state_ == State::verifying || state_ == State::rebooting;
    return OtaStatus{dev_.running_version ? dev_.running_version : "",
                     d_.platform.runningSlot(),
                     state_,
                     last_,
                     haveAvailable_ ? available_.version : "",
                     lastCheck_,
                     busy ? dl_.received() : 0,
                     busy ? dl_.total() : 0,
                     cfg_.auto_check.enabled,
                     cfg_.auto_check.interval_ms,
                     &rejected_};
}

size_t formatStatusJson(const OtaStatus& s, char* out, size_t cap) {
    if (!out || !cap) return 0;
    char cur[40], slot[24], avail[40];
    jsonSafe(cur, sizeof(cur), s.current_version);
    jsonSafe(slot, sizeof(slot), s.running_slot);
    if (s.available_version && *s.available_version) {
        char v[34];
        jsonSafe(v, sizeof(v), s.available_version);
        snprintf(avail, sizeof(avail), "\"%s\"", v);
    } else {
        copyStr(avail, sizeof(avail), "null");
    }
    int n = snprintf(out, cap,
                     "{\"current_version\":\"%s\",\"running_slot\":\"%s\",\"state\":\"%s\","
                     "\"last_result\":{\"kind\":\"%s\",\"reason\":\"%s\",\"version\":\"%s\"},\"available_version\":%s,"
                     "\"last_check\":\"%s\",\"progress\":%lu,\"total\":%lu,\"auto_check\":{\"enabled\":%s,\"interval_s\":%lu}",
                     cur, slot, stateName(s.state), resultKindName(s.last_result.kind), reasonName(s.last_result.reason),
                     s.last_result.version, avail, reasonName(s.last_check), (unsigned long)s.progress_bytes,
                     (unsigned long)s.total_bytes, s.auto_check_enabled ? "true" : "false",
                     (unsigned long)(s.auto_check_interval_ms / 1000));
    if (n < 0 || (size_t)n >= cap) { out[0] = 0; return 0; }
    size_t len = (size_t)n;
    // Appends `s` at len; false when it (plus the closing brace and NUL) does not fit.
    auto append = [&](const char* s) {
        const size_t k = strlen(s);
        if (len + k + 2 > cap) return false;
        memcpy(out + len, s, k + 1);
        len += k;
        return true;
    };
    if (s.rejected && s.rejected->count) {
        bool ok = append(",\"rejected\":[");
        for (uint8_t i = 0; ok && i < s.rejected->count; i++) {
            char v[34];
            jsonSafe(v, sizeof(v), s.rejected->version[i]);
            ok = (i == 0 || append(",")) && append("\"") && append(v) && append("\"");
        }
        if (!ok || !append("]")) { out[0] = 0; return 0; }
    }
    if (len + 2 > cap) { out[0] = 0; return 0; }
    out[len++] = '}';
    out[len] = 0;
    return len;
}

} // namespace fota
