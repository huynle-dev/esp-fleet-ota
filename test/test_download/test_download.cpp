// Download + hash engine with a fake HTTP source and a fake partition writer.
#include <unity.h>
#include <cstdio>
#include <string>
#include "fota_download.h"
#include "fota_fakes.h"
#include "host/fota_openssl.h"

using namespace fota;

static const char* URL = "https://fw.example.com/demo/1.1.0/esp32c3/firmware.bin";
static fakes::Clock K;
static fakes::Http H;
static fakes::Writer W;
static OpensslSha256 S;

static std::string body(size_t n) {
    std::string b(n, 0);
    for (size_t i = 0; i < n; i++) b[i] = (char)((i * 131 + 7) & 0xFF);
    return b;
}
static std::string hexSha(const std::string& b) {
    OpensslSha256 s;
    uint8_t h[32];
    s.begin(); s.update((const uint8_t*)b.data(), b.size()); s.finish(h);
    char out[65];
    for (int i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02x", h[i]);
    return out;
}

void setUp() { K = fakes::Clock(); H = fakes::Http(); W = fakes::Writer(); }
void tearDown() {}

// Runs to completion (bounded), returns final status.
static Downloader::Status run(Downloader& d, int maxSteps = 100000) {
    for (int i = 0; i < maxSteps && d.status() == Downloader::Status::running; i++) d.step();
    return d.status();
}

static void expectFailed(Downloader& d, const char* reason) {
    TEST_ASSERT_EQUAL_INT((int)Downloader::Status::failed, (int)d.status());
    TEST_ASSERT_EQUAL_STRING(reason, reasonName(d.reason()));
    TEST_ASSERT_FALSE_MESSAGE(W.committed, "must not commit");
    TEST_ASSERT_FALSE_MESSAGE(W.bootable, "spare slot must not be bootable");
    TEST_ASSERT_FALSE_MESSAGE(H.isOpen, "connection must be closed");
}

static void test_downloads_chunked_body_and_commits() {
    std::string b = body(100003);
    fakes::Response r; r.body = b; r.chunk = 777; r.contentLength = -1;    // chunked transfer, no length
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_TRUE(d.start(URL, (uint32_t)b.size(), hexSha(b).c_str()));
    TEST_ASSERT_EQUAL_INT((int)Downloader::Status::done, (int)run(d));
    TEST_ASSERT_TRUE(W.committed);
    TEST_ASSERT_TRUE(W.bootable);
    TEST_ASSERT_FALSE(W.aborted);
    TEST_ASSERT_EQUAL_UINT32(b.size(), W.beganSize);
    TEST_ASSERT_TRUE(W.data == b);
    TEST_ASSERT_EQUAL_UINT32(b.size(), d.received());
    TEST_ASSERT_FALSE(H.isOpen);
    TEST_ASSERT_TRUE(K.feeds >= (int)(b.size() / 777));                  // fed between chunks
    TEST_ASSERT_TRUE(H.maxReadCap <= 4096);
}

static void test_known_content_length() {
    std::string b = body(5000);
    fakes::Response r; r.body = b;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_TRUE(d.start(URL, 5000, hexSha(b).c_str()));
    TEST_ASSERT_EQUAL_INT((int)Downloader::Status::done, (int)run(d));
}

static void test_step_is_incremental() {
    std::string b = body(10000);
    fakes::Response r; r.body = b; r.chunk = 4096;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_TRUE(d.start(URL, 10000, hexSha(b).c_str()));
    d.step();
    TEST_ASSERT_EQUAL_INT((int)Downloader::Status::running, (int)d.status());
    TEST_ASSERT_TRUE(d.received() > 0 && d.received() <= 4096);
}

static void test_wrong_hash_aborts() {
    std::string b = body(9000);
    fakes::Response r; r.body = b;
    H.routes[URL] = r;
    std::string bad = hexSha(b);
    bad[0] = bad[0] == '0' ? '1' : '0';
    Downloader d(H, W, S, K);
    TEST_ASSERT_TRUE(d.start(URL, 9000, bad.c_str()));
    run(d);
    expectFailed(d, "hash_mismatch");
    TEST_ASSERT_TRUE(W.aborted);
}

static void test_tampered_byte_in_transit_aborts() {
    std::string b = body(9000);
    std::string sha = hexSha(b);
    b[4500] ^= 0x40;
    fakes::Response r; r.body = b;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_TRUE(d.start(URL, 9000, sha.c_str()));
    run(d);
    expectFailed(d, "hash_mismatch");
}

static void test_truncated_body() {
    std::string b = body(9000);
    fakes::Response r; r.body = b.substr(0, 8000); r.contentLength = -1;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_TRUE(d.start(URL, 9000, hexSha(b).c_str()));
    run(d);
    expectFailed(d, "truncated");
    TEST_ASSERT_TRUE(W.aborted);
}

static void test_content_length_mismatch() {
    std::string b = body(9000);
    fakes::Response r; r.body = b; r.contentLength = 8000;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_FALSE(d.start(URL, 9000, hexSha(b).c_str()));
    expectFailed(d, "truncated");
    r.contentLength = 9001;
    H.routes[URL] = r;
    Downloader d2(H, W, S, K);
    TEST_ASSERT_FALSE(d2.start(URL, 9000, hexSha(b).c_str()));
    expectFailed(d2, "oversize");
}

static void test_oversize_body_without_length() {
    std::string b = body(9000);
    fakes::Response r; r.body = b + "EXTRA"; r.contentLength = -1;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_TRUE(d.start(URL, 9000, hexSha(b).c_str()));
    run(d);
    expectFailed(d, "oversize");
    TEST_ASSERT_TRUE(W.data.size() <= 9000);                  // never writes past the declared size
}

static void test_image_larger_than_slot() {
    W.spare = 4096;
    std::string b = body(5000);
    fakes::Response r; r.body = b;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_FALSE(d.start(URL, 5000, hexSha(b).c_str()));
    expectFailed(d, "too_large");
    TEST_ASSERT_FALSE(W.begun);
    TEST_ASSERT_TRUE(H.opened.empty());                       // refused before connecting
}

static void test_stall_times_out() {
    std::string b = body(9000);
    fakes::Response r; r.body = b; r.stallAt = 3000;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    DownloadLimits lim; lim.stallTimeoutMs = 2000;
    TEST_ASSERT_TRUE(d.start(URL, 9000, hexSha(b).c_str(), lim));
    run(d);
    expectFailed(d, "timeout");
    TEST_ASSERT_TRUE(W.aborted);
    TEST_ASSERT_TRUE(K.feeds > 10);                            // fed while waiting
}

static void test_total_timeout() {
    std::string b = body(90000);
    fakes::Response r; r.body = b; r.chunk = 10;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    DownloadLimits lim; lim.totalTimeoutMs = 1000;
    TEST_ASSERT_TRUE(d.start(URL, 90000, hexSha(b).c_str(), lim));
    for (int i = 0; i < 100 && d.status() == Downloader::Status::running; i++) d.step();
    K.now += 2000;
    run(d);
    expectFailed(d, "timeout");
}

static void test_connection_error() {
    std::string b = body(9000);
    fakes::Response r; r.body = b; r.errorAt = 4000;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_TRUE(d.start(URL, 9000, hexSha(b).c_str()));
    run(d);
    expectFailed(d, "download_failed");
}

static void test_open_fails() {
    Downloader d(H, W, S, K);                                  // no route: 404/TLS failure
    TEST_ASSERT_FALSE(d.start(URL, 9000, hexSha(body(9000)).c_str()));
    expectFailed(d, "download_failed");
    TEST_ASSERT_FALSE(W.begun);
}

static void test_writer_failures() {
    std::string b = body(9000);
    fakes::Response r; r.body = b;
    H.routes[URL] = r;
    W.failBegin = true;
    Downloader d1(H, W, S, K);
    TEST_ASSERT_FALSE(d1.start(URL, 9000, hexSha(b).c_str()));
    expectFailed(d1, "begin_failed");

    setUp(); H.routes[URL] = r; W.failWriteAt = 5000;
    Downloader d2(H, W, S, K);
    TEST_ASSERT_TRUE(d2.start(URL, 9000, hexSha(b).c_str()));
    run(d2);
    expectFailed(d2, "write_failed");
    TEST_ASSERT_TRUE(W.aborted);

    setUp(); H.routes[URL] = r; W.failCommit = true;
    Downloader d3(H, W, S, K);
    TEST_ASSERT_TRUE(d3.start(URL, 9000, hexSha(b).c_str()));
    run(d3);
    expectFailed(d3, "finalize_failed");
    TEST_ASSERT_TRUE(W.aborted);
}

static void test_bad_arguments() {
    Downloader d(H, W, S, K);
    TEST_ASSERT_FALSE(d.start(URL, 9000, "nothex"));
    TEST_ASSERT_EQUAL_STRING("manifest_invalid", reasonName(d.reason()));
    Downloader d2(H, W, S, K);
    TEST_ASSERT_FALSE(d2.start(URL, 0, hexSha("").c_str()));
    TEST_ASSERT_EQUAL_STRING("manifest_invalid", reasonName(d2.reason()));
    Downloader d3(H, W, S, K);
    TEST_ASSERT_FALSE(d3.start("http://fw.example.com/x", 10, hexSha("").c_str()));
    TEST_ASSERT_EQUAL_STRING("url_not_https", reasonName(d3.reason()));
    TEST_ASSERT_TRUE(H.opened.empty());
}

static void test_cancel_aborts() {
    std::string b = body(9000);
    fakes::Response r; r.body = b; r.chunk = 100;
    H.routes[URL] = r;
    Downloader d(H, W, S, K);
    TEST_ASSERT_TRUE(d.start(URL, 9000, hexSha(b).c_str()));
    d.step();
    d.cancel();
    expectFailed(d, "download_failed");
    TEST_ASSERT_TRUE(W.aborted);
}

static void test_parse_sha_hex() {
    uint8_t out[32];
    TEST_ASSERT_TRUE(parseSha256Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1eff", out));
    TEST_ASSERT_EQUAL_HEX8(0x0a, out[10]);
    TEST_ASSERT_EQUAL_HEX8(0xff, out[31]);
    TEST_ASSERT_FALSE(parseSha256Hex("00", out));
    TEST_ASSERT_FALSE(parseSha256Hex(nullptr, out));
    TEST_ASSERT_FALSE(parseSha256Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1eff00", out));
    TEST_ASSERT_FALSE(parseSha256Hex("zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1eff", out));
}

int main(int, char**) {
    UNITY_BEGIN();
    RUN_TEST(test_downloads_chunked_body_and_commits);
    RUN_TEST(test_known_content_length);
    RUN_TEST(test_step_is_incremental);
    RUN_TEST(test_wrong_hash_aborts);
    RUN_TEST(test_tampered_byte_in_transit_aborts);
    RUN_TEST(test_truncated_body);
    RUN_TEST(test_content_length_mismatch);
    RUN_TEST(test_oversize_body_without_length);
    RUN_TEST(test_image_larger_than_slot);
    RUN_TEST(test_stall_times_out);
    RUN_TEST(test_total_timeout);
    RUN_TEST(test_connection_error);
    RUN_TEST(test_open_fails);
    RUN_TEST(test_writer_failures);
    RUN_TEST(test_bad_arguments);
    RUN_TEST(test_cancel_aborts);
    RUN_TEST(test_parse_sha_hex);
    return UNITY_END();
}
