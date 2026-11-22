// Streams the image into the spare slot, hashing on the fly. Bounded memory (one reused chunk buffer, <= 4 KB),
// incremental (step() does at most one read + write, so the device loop and the watchdog keep running), and every
// failure path aborts the writer so the spare slot never becomes bootable. No Arduino headers.
#pragma once
#include <cstddef>
#include <cstdint>
#include "fota_crypto.h"
#include "fota_io.h"
#include "fota_reason.h"

namespace fota {

struct DownloadLimits {
    uint32_t stallTimeoutMs = 10000;     // no bytes for this long -> timeout
    uint32_t totalTimeoutMs = 600000;    // whole download
    size_t chunkBytes = 2048;            // read/write buffer, clamped to [256, 4096]
};

class Downloader {
public:
    enum class Status : uint8_t { idle, running, done, failed };

    Downloader(IHttpSource& http, IPartitionWriter& writer, ISha256& sha, IClock& clock);
    ~Downloader();

    // `sha256Hex` is the manifest's 64 lowercase hex digest; `size` the exact image size.
    // Returns false (status failed, reason set) when it cannot even start.
    bool start(const char* url, uint32_t size, const char* sha256Hex, const DownloadLimits& limits = DownloadLimits());
    Status step();                    // advance; returns the new status
    void cancel();                    // abort a running download (reason timeout is NOT set; reason download_failed)

    Status status() const { return status_; }
    Reason reason() const { return reason_; }
    uint32_t received() const { return received_; }
    uint32_t total() const { return size_; }

private:
    Status fail(Reason r);
    void releaseBuffer();

    IHttpSource& http_;
    IPartitionWriter& writer_;
    ISha256& sha_;
    IClock& clock_;
    Status status_ = Status::idle;
    Reason reason_ = Reason::none;
    uint8_t* buf_ = nullptr;
    size_t chunk_ = 0;
    uint32_t size_ = 0, received_ = 0;
    uint8_t expected_[32] = {0};
    uint64_t startedMs_ = 0, lastDataMs_ = 0;
    DownloadLimits limits_;
    bool httpOpen_ = false, writerOpen_ = false;
};

// Parses 64 hex characters into 32 bytes.
bool parseSha256Hex(const char* hex, uint8_t out[32]);

} // namespace fota
