// Fakes for the device interfaces (fota_io.h), shared by the native tests. Header-only, test code only.
#pragma once
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include "fota_io.h"

// A test that tracks heap use (test_memory) defines FAKE_BOOKKEEPING_SCOPE to pause its tracker, so the fakes' own
// bookkeeping (URL log, std::map nodes standing in for NVS) is not counted as library allocations.
#ifndef FAKE_BOOKKEEPING_SCOPE
#define FAKE_BOOKKEEPING_SCOPE
#endif

namespace fakes {

struct Clock : fota::IClock {
    uint64_t now = 1000;
    uint32_t idleStepMs = 50;     // each idle() advances time, so stalls reach their timeout
    int feeds = 0, idles = 0;
    uint64_t nowMs() override { return now; }
    void feedWatchdog() override { feeds++; }
    void idle() override { idles++; now += idleStepMs; }
};

struct Response {
    bool openOk = true;
    std::string body;
    int64_t contentLength = -2;   // -2: use body size; -1: unknown (chunked); else that value
    size_t chunk = 1000;          // max bytes per read
    long stallAt = -1;            // after this many bytes, read() returns 0 forever
    long errorAt = -1;            // after this many bytes, read() returns kError
};

struct Http : fota::IHttpSource {
    std::map<std::string, Response> routes;
    std::vector<std::string> opened;
    const Response* cur = nullptr;
    size_t pos = 0;
    bool isOpen = false;
    int closes = 0;
    size_t maxReadCap = 0;
    bool open(const char* url, int64_t& len) override {
        { FAKE_BOOKKEEPING_SCOPE; opened.push_back(url); }
        auto it = routes.find(url);
        if (it == routes.end() || !it->second.openOk) return false;
        cur = &it->second;
        pos = 0;
        isOpen = true;
        len = cur->contentLength == -2 ? (int64_t)cur->body.size() : cur->contentLength;
        return true;
    }
    int read(uint8_t* buf, size_t cap) override {
        if (cap > maxReadCap) maxReadCap = cap;
        if (!isOpen || !cur) return kError;
        if (cur->errorAt >= 0 && (long)pos >= cur->errorAt) return kError;
        if (cur->stallAt >= 0 && (long)pos >= cur->stallAt) return 0;
        if (pos >= cur->body.size()) return kEof;
        size_t n = cur->body.size() - pos;
        if (n > cap) n = cap;
        if (n > cur->chunk) n = cur->chunk;
        if (cur->stallAt >= 0 && pos + n > (size_t)cur->stallAt) n = (size_t)cur->stallAt - pos;
        if (cur->errorAt >= 0 && pos + n > (size_t)cur->errorAt) n = (size_t)cur->errorAt - pos;
        memcpy(buf, cur->body.data() + pos, n);
        pos += n;
        return (int)n;
    }
    void close() override { isOpen = false; closes++; }
};

struct Writer : fota::IPartitionWriter {
    uint32_t spare = 0x1E0000;
    bool failBegin = false, failCommit = false;
    long failWriteAt = -1;          // fail the write that would pass this many total bytes
    bool begun = false, committed = false, aborted = false;
    bool bootable = false;          // what the bootloader would boot next
    std::string data;
    uint32_t beganSize = 0;
    uint32_t spareSize() override { return spare; }
    bool begin(uint32_t size) override {
        if (failBegin) return false;
        begun = true; committed = aborted = false; beganSize = size;
        { FAKE_BOOKKEEPING_SCOPE; data.clear(); }
        return true;
    }
    bool write(const uint8_t* d, size_t n) override {
        if (!begun || committed) return false;
        if (failWriteAt >= 0 && (long)(data.size() + n) > failWriteAt) return false;
        { FAKE_BOOKKEEPING_SCOPE; data.append((const char*)d, n); }
        return true;
    }
    bool commit() override {
        if (!begun || failCommit) return false;
        committed = true; bootable = true;
        return true;
    }
    void abort() override { aborted = true; begun = false; if (!committed) bootable = false; }
};

struct Platform : fota::IOtaPlatform {
    std::string slot = "app0";
    bool pending = false;
    int markValidCalls = 0, markInvalidCalls = 0, reboots = 0;
    bool markValidOk = true;
    const char* runningSlot() override { return slot.c_str(); }
    bool pendingVerify() override { return pending; }
    bool markValid() override { markValidCalls++; if (markValidOk) pending = false; return markValidOk; }
    void markInvalidAndReboot() override { markInvalidCalls++; }
    void reboot() override { reboots++; }
};

struct Store : fota::IStore {
    std::map<std::string, std::string> kv;
    bool failPut = false;
    int puts = 0;
    bool get(const char* k, char* out, size_t cap) override {
        auto it = kv.find(k);
        if (it == kv.end() || it->second.size() + 1 > cap) return false;
        memcpy(out, it->second.c_str(), it->second.size() + 1);
        return true;
    }
    bool put(const char* k, const char* v) override {
        FAKE_BOOKKEEPING_SCOPE;
        puts++;
        if (failPut) return false;
        kv[k] = v;
        return true;
    }
    bool remove(const char* k) override { FAKE_BOOKKEEPING_SCOPE; kv.erase(k); return true; }
};

struct Hooks : fota::IDeviceHooks {
    bool allow = true;
    const char* why = "output is on";
    int beforeCalls = 0, selfTestCalls = 0;
    std::vector<fota::SelfTest> script;     // results for successive selfTest() calls; last one repeats
    bool canUpdateNow(char* w, size_t cap) override {
        if (!allow) { strncpy(w, why, cap - 1); w[cap - 1] = 0; }
        return allow;
    }
    void onBeforeUpdate() override { beforeCalls++; }
    fota::SelfTest selfTest() override {
        selfTestCalls++;
        if (script.empty()) return fota::SelfTest::pass;
        size_t i = (size_t)selfTestCalls - 1;
        return script[i < script.size() ? i : script.size() - 1];
    }
};

} // namespace fakes
