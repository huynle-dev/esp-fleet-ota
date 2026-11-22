#include "fota_download.h"
#include <cstring>
#include <new>

namespace fota {

namespace {
int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
} // namespace

bool parseSha256Hex(const char* hex, uint8_t out[32]) {
    if (!hex) return false;
    for (int i = 0; i < 32; i++) {
        int hi = hexNibble(hex[2 * i]);
        if (hi < 0) return false;
        int lo = hexNibble(hex[2 * i + 1]);
        if (lo < 0) return false;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return hex[64] == 0;
}

Downloader::Downloader(IHttpSource& h, IPartitionWriter& w, ISha256& s, IClock& c)
    : http_(h), writer_(w), sha_(s), clock_(c) {}

Downloader::~Downloader() {
    if (status_ == Status::running) fail(Reason::download_failed);
    releaseBuffer();
}

void Downloader::releaseBuffer() {
    delete[] buf_;
    buf_ = nullptr;
}

Downloader::Status Downloader::fail(Reason r) {
    if (httpOpen_) { http_.close(); httpOpen_ = false; }
    if (writerOpen_) { writer_.abort(); writerOpen_ = false; }
    releaseBuffer();
    reason_ = r;
    status_ = Status::failed;
    return status_;
}

bool Downloader::start(const char* url, uint32_t size, const char* sha256Hex, const DownloadLimits& limits) {
    if (status_ == Status::running) return false;
    received_ = 0;
    size_ = size;
    reason_ = Reason::none;
    limits_ = limits;
    if (!url || strncmp(url, "https://", 8) != 0) { fail(Reason::url_not_https); return false; }
    if (size == 0 || !parseSha256Hex(sha256Hex, expected_)) { fail(Reason::manifest_invalid); return false; }
    if (size > writer_.spareSize()) { fail(Reason::too_large); return false; }

    chunk_ = limits.chunkBytes < 256 ? 256 : (limits.chunkBytes > 4096 ? 4096 : limits.chunkBytes);
    buf_ = new (std::nothrow) uint8_t[chunk_];
    if (!buf_) { fail(Reason::download_failed); return false; }

    int64_t len = -1;
    if (!http_.open(url, len)) { fail(Reason::download_failed); return false; }
    httpOpen_ = true;
    if (len >= 0 && len < (int64_t)size) { fail(Reason::truncated); return false; }
    if (len > (int64_t)size) { fail(Reason::oversize); return false; }

    if (!writer_.begin(size)) { fail(Reason::begin_failed); return false; }
    writerOpen_ = true;
    sha_.begin();
    startedMs_ = lastDataMs_ = clock_.nowMs();
    status_ = Status::running;
    return true;
}

Downloader::Status Downloader::step() {
    if (status_ != Status::running) return status_;
    clock_.feedWatchdog();
    const uint64_t now = clock_.nowMs();
    if (now - startedMs_ > limits_.totalTimeoutMs) return fail(Reason::timeout);

    if (received_ < size_) {
        size_t want = size_ - received_;
        if (want > chunk_) want = chunk_;
        int n = http_.read(buf_, want);
        if (n == IHttpSource::kError) return fail(Reason::download_failed);
        if (n == IHttpSource::kEof) return fail(Reason::truncated);
        if (n == 0) {
            if (now - lastDataMs_ > limits_.stallTimeoutMs) return fail(Reason::timeout);
            clock_.idle();
            return status_;
        }
        if ((size_t)n > want) return fail(Reason::oversize);    // a source must honour cap; refuse otherwise
        sha_.update(buf_, (size_t)n);
        if (!writer_.write(buf_, (size_t)n)) return fail(Reason::write_failed);
        received_ += (uint32_t)n;
        lastDataMs_ = clock_.nowMs();
        return status_;
    }

    // All declared bytes are in: the body must end here.
    int n = http_.read(buf_, 1);
    if (n > 0) return fail(Reason::oversize);
    if (n == 0) {
        if (now - lastDataMs_ > limits_.stallTimeoutMs) return fail(Reason::timeout);
        clock_.idle();
        return status_;
    }
    if (n == IHttpSource::kError) return fail(Reason::download_failed);
    http_.close();
    httpOpen_ = false;

    uint8_t got[32];
    sha_.finish(got);
    if (memcmp(got, expected_, 32) != 0) return fail(Reason::hash_mismatch);
    if (!writer_.commit()) return fail(Reason::finalize_failed);
    writerOpen_ = false;
    releaseBuffer();
    status_ = Status::done;
    return status_;
}

void Downloader::cancel() {
    if (status_ == Status::running) fail(Reason::download_failed);
}

} // namespace fota
