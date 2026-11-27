// Strict parser for the release manifest (schema 1). No Arduino headers, no heap: fixed-size fields.
//
// The manifest is a flat JSON object. Its exact bytes are what the release key signs (detached signature, see
// fota_signature.h), so this parser runs on UNTRUSTED input before the signature is checked: it is bounded
// (kMaxManifestBytes), never allocates, and rejects anything outside the schema:
//   {"schema":1,"product":"example-psu","chip":"esp32c3","board":"esp32-c3-devkitm-1","channel":"stable",
//    "version":"1.4.0","min_version":"1.2.0","url":"https://fw.example.com/example-psu/1.4.0/esp32c3/firmware.bin","size":1234567,
//    "sha256":"<64 lowercase hex>","key_id":"esp-fleet-ota","released_at":"2026-11-22T10:00:00Z"}
// board and min_version are optional. Unknown keys, duplicate keys, nested values, arrays, floats, negative numbers,
// true/false/null, escapes other than \" \\ \/, control characters and trailing data are all rejected.
#pragma once
#include <cstddef>
#include <cstdint>

namespace fota {

constexpr size_t kMaxManifestBytes = 2048;

enum class ManifestError : uint8_t {
    Ok = 0,
    TooLarge,           // more than kMaxManifestBytes
    Syntax,             // not valid JSON (for this subset)
    NotObject,          // top level is not an object
    Nested,             // a value is an object or array
    DuplicateKey,
    UnknownKey,
    BadType,            // e.g. string where a number is required, float, bool, null
    MissingField,
    FieldTooLong,
    BadValue,           // well typed but outside the allowed values/format
    UnsupportedSchema,  // schema != 1
};

const char* manifestErrorName(ManifestError e);

struct Manifest {
    uint32_t schema = 0;
    char product[33] = {0};
    char chip[17] = {0};
    char board[33] = {0};        // "" when absent
    char channel[9] = {0};       // "stable" | "beta" | "dev"
    char version[33] = {0};      // semver
    char min_version[33] = {0};  // semver or "" when absent
    char url[257] = {0};
    uint32_t size = 0;           // bytes, 1..2^31-1
    char sha256[65] = {0};       // 64 lowercase hex
    char key_id[33] = {0};
    char released_at[21] = {0};  // YYYY-MM-DDTHH:MM:SSZ
    bool hasBoard() const { return board[0] != 0; }
    bool hasMinVersion() const { return min_version[0] != 0; }
};

// Parses `len` bytes at `data` (need not be NUL-terminated). On error `out` is untouched and, when `field` is not
// null, *field names the offending key ("" when not field-specific).
ManifestError parseManifest(const char* data, size_t len, Manifest& out, const char** field = nullptr);

} // namespace fota
