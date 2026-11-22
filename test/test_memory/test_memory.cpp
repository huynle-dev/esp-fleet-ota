// Memory budget of check + update: global operator new/delete are replaced by a tracking allocator (this suite is its
// own executable) and the largest single allocation and the peak extra live bytes are measured. A C3 that already holds
// two TLS sessions may have only ~57 KB free / ~47 KB in its largest block, so the OTA logic must stay far below that (the TLS session of the download itself is the glue's, not counted here).
// Not counted: OpenSSL (host crypto, malloc); on the device mbedTLS verify allocates bignums with calloc (~2-3 KB,
// short-lived) - see docs/integration.md.
#include <unity.h>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <string>
#include "fleet_ota.h"
#include "fota_test_signer.h"
#include "host/fota_openssl.h"

namespace mem {
bool paused = false;
size_t live = 0, peak = 0, maxSingle = 0, count = 0;
struct Pause { bool prev; Pause() : prev(paused) { paused = true; } ~Pause() { paused = prev; } };
struct alignas(16) Hdr { size_t size; size_t tracked; };
void* alloc(size_t n) {
    const bool tr = !paused;
    Hdr* h = (Hdr*)malloc(n + sizeof(Hdr));
    if (!h) throw std::bad_alloc();
    h->size = n; h->tracked = tr ? 1 : 0;
    if (tr) { count++; live += n; if (live > peak) peak = live; if (n > maxSingle) maxSingle = n; }
    return h + 1;
}
void release(void* p) {
    if (!p) return;
    Hdr* h = (Hdr*)p - 1;
    if (h->tracked) live -= h->size;
    free(h);
}
void resetWindow() { peak = live; maxSingle = 0; count = 0; }
} // namespace mem

void* operator new(size_t n) { return mem::alloc(n); }
void* operator new[](size_t n) { return mem::alloc(n); }
void* operator new(size_t n, const std::nothrow_t&) noexcept { try { return mem::alloc(n); } catch (...) { return nullptr; } }
void* operator new[](size_t n, const std::nothrow_t&) noexcept { try { return mem::alloc(n); } catch (...) { return nullptr; } }
void operator delete(void* p) noexcept { mem::release(p); }
void operator delete[](void* p) noexcept { mem::release(p); }
void operator delete(void* p, size_t) noexcept { mem::release(p); }
void operator delete[](void* p, size_t) noexcept { mem::release(p); }

#define FAKE_BOOKKEEPING_SCOPE mem::Pause fakeBookkeepingPause_
#include "fota_fakes.h"

using namespace fota;

static const char* MURL = "https://fw.example.com/demo/esp32c3/stable/manifest.json";
static const char* IURL = "https://fw.example.com/demo/2.0.0/esp32c3/firmware.bin";
static const char* kHosts[] = {"fw.example.com"};

struct Rig {
    fakes::Clock clock; fakes::Http http; fakes::Writer writer; fakes::Platform platform; fakes::Store store;
    fakes::Hooks hooks; OpensslSha256 sha; OpensslEcdsaP256 ecdsa; TestSigner signer; TrustedKey keys[1];
    OtaConfig cfg; DeviceIdentity dev{"demo", "esp32c3", "", "1.0.0"};
    std::string image;
    std::unique_ptr<FleetOta> ota;
    explicit Rig(size_t chunk) {
        keys[0] = TrustedKey{"test-only-esp-fleet-ota", 1, signer.spki.data(), signer.spki.size()};
        cfg.manifest_url = MURL; cfg.allowed_hosts = kHosts; cfg.allowed_host_count = 1;
        cfg.keys = keys; cfg.key_count = 1; cfg.download.chunkBytes = chunk;
        image.resize(300000);
        for (size_t i = 0; i < image.size(); i++) image[i] = (char)(i * 13 + 1);
        std::string m = "{\"schema\":1,\"product\":\"demo\",\"chip\":\"esp32c3\",\"channel\":\"stable\",\"version\":\"2.0.0\","
                        "\"url\":\"" + std::string(IURL) + "\",\"size\":" + std::to_string(image.size()) +
                        ",\"sha256\":\"" + testSha256Hex(image) + "\",\"key_id\":\"test-only-esp-fleet-ota\",\"released_at\":\"2026-11-22T10:00:00Z\"}";
        fakes::Response mr; mr.body = m;
        fakes::Response sr; sr.body = signer.signVault(m, 1) + "\n";
        fakes::Response ir; ir.body = image; ir.chunk = 1460;            // one TCP segment per read
        http.routes[MURL] = mr; http.routes[std::string(MURL) + ".sig"] = sr; http.routes[IURL] = ir;
        writer.data.reserve(image.size());
        ota.reset(new FleetOta(cfg, dev, OtaDeps{http, writer, platform, store, hooks, clock, sha, ecdsa}));
        ota->begin();
    }
};

void setUp() {}
void tearDown() {}

static void report(const char* what, size_t base) {
    printf("[mem] %-24s max single %5zu B, peak extra %5zu B, allocations %zu\n", what, mem::maxSingle,
           mem::peak - base, mem::count);
}

static void measureUpdate(size_t chunk, size_t maxSingle, size_t maxPeak) {
    mem::Pause p;
    Rig r(chunk);
    size_t base;
    {
        mem::paused = false;
        base = mem::live;
        mem::resetWindow();
        TEST_ASSERT_EQUAL_STRING("none", reasonName(r.ota->check()));
        report("check (manifest + sig)", base);
        TEST_ASSERT_TRUE(mem::maxSingle <= 4096);
        TEST_ASSERT_TRUE(mem::peak - base <= 4096);
        mem::resetWindow();
        base = mem::live;
        TEST_ASSERT_EQUAL_STRING("none", reasonName(r.ota->update("2.0.0")));
        for (int i = 0; i < 100000 && r.ota->state() != State::rebooting && r.ota->state() != State::failed; i++)
            r.ota->loop();
        char label[40];
        snprintf(label, sizeof(label), "update, chunk %zu", chunk);
        report(label, base);
        mem::paused = true;
    }
    TEST_ASSERT_EQUAL_STRING("rebooting", stateName(r.ota->state()));
    TEST_ASSERT_TRUE(r.writer.data == r.image);
    TEST_ASSERT_TRUE_MESSAGE(mem::maxSingle <= maxSingle, "single allocation over budget");
    TEST_ASSERT_TRUE_MESSAGE(mem::peak - base <= maxPeak, "peak over budget");
    TEST_ASSERT_EQUAL_size_t(base, mem::live);       // nothing leaked by the download
}

static void test_update_default_chunk_budget() { measureUpdate(2048, 4096, 4096 + 512); }
static void test_update_max_chunk_budget() { measureUpdate(4096, 4096, 4096 + 512); }
static void test_oversized_chunk_request_is_clamped() { measureUpdate(65536, 4096, 4096 + 512); }

static void test_object_sizes() {
    printf("[mem] sizeof(FleetOta) = %zu B (static on the device), sizeof(Manifest) = %zu B\n", sizeof(FleetOta),
           sizeof(Manifest));
    TEST_ASSERT_TRUE(sizeof(FleetOta) < 2048);
}

int main(int, char**) {
    mem::paused = true;
    UNITY_BEGIN();
    RUN_TEST(test_update_default_chunk_budget);
    RUN_TEST(test_update_max_chunk_budget);
    RUN_TEST(test_oversized_chunk_request_is_clamped);
    RUN_TEST(test_object_sizes);
    return UNITY_END();
}
