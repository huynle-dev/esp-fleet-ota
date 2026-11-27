#include "fota_manifest.h"
#include <cstring>
#include "fota_semver.h"

namespace fota {

const char* manifestErrorName(ManifestError e) {
    switch (e) {
        case ManifestError::Ok: return "Ok";
        case ManifestError::TooLarge: return "TooLarge";
        case ManifestError::Syntax: return "Syntax";
        case ManifestError::NotObject: return "NotObject";
        case ManifestError::Nested: return "Nested";
        case ManifestError::DuplicateKey: return "DuplicateKey";
        case ManifestError::UnknownKey: return "UnknownKey";
        case ManifestError::BadType: return "BadType";
        case ManifestError::MissingField: return "MissingField";
        case ManifestError::FieldTooLong: return "FieldTooLong";
        case ManifestError::BadValue: return "BadValue";
        case ManifestError::UnsupportedSchema: return "UnsupportedSchema";
    }
    return "Unknown";
}

namespace {

enum class Kind : uint8_t { String, Int };

struct FieldDef {
    const char* name;
    Kind kind;
    bool required;
    size_t offset;      // into Manifest (char array or uint32_t)
    size_t capacity;    // char array size (incl. NUL); 0 for ints
};

#define STR_FIELD(n, req) {#n, Kind::String, req, offsetof(Manifest, n), sizeof(Manifest::n)}
#define INT_FIELD(n) {#n, Kind::Int, true, offsetof(Manifest, n), 0}

const FieldDef kFields[] = {
    INT_FIELD(schema),
    STR_FIELD(product, true),
    STR_FIELD(chip, true),
    STR_FIELD(board, false),
    STR_FIELD(channel, true),
    STR_FIELD(version, true),
    STR_FIELD(min_version, false),
    STR_FIELD(url, true),
    INT_FIELD(size),
    STR_FIELD(sha256, true),
    STR_FIELD(key_id, true),
    STR_FIELD(released_at, true),
};
constexpr size_t kFieldCount = sizeof(kFields) / sizeof(kFields[0]);
constexpr size_t kMaxString = 256;   // longest field (url) without NUL

enum class Tok : uint8_t { Ok, TooLong, Syntax };

class Reader {
public:
    Reader(const char* d, size_t n) : p_(d), end_(d + n) {}
    void skipWs() { while (p_ < end_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\n' || *p_ == '\r')) p_++; }
    bool atEnd() const { return p_ >= end_; }
    char peek() const { return p_ < end_ ? *p_ : 0; }
    bool take(char c) { if (p_ < end_ && *p_ == c) { p_++; return true; } return false; }

    // Reads a JSON string at the cursor (opening quote included) into buf[cap]. On TooLong the string is still consumed.
    Tok string(char* buf, size_t cap, size_t& outLen) {
        if (!take('"')) return Tok::Syntax;
        size_t n = 0;
        bool tooLong = false;
        while (true) {
            if (p_ >= end_) return Tok::Syntax;
            char c = *p_++;
            if (c == '"') break;
            if ((unsigned char)c < 0x20) return Tok::Syntax;          // control characters, including NUL
            if (c == '\\') {
                if (p_ >= end_) return Tok::Syntax;
                char e = *p_++;
                if (e != '"' && e != '\\' && e != '/') return Tok::Syntax;
                c = e;
            }
            if (n + 1 < cap) buf[n++] = c; else tooLong = true;
        }
        buf[n] = 0;
        outLen = n;
        return tooLong ? Tok::TooLong : Tok::Ok;
    }

    // Scans a number-like token [-+.0-9eE]; returns its bounds.
    void numberToken(const char*& b, size_t& n) {
        b = p_;
        while (p_ < end_ && ((*p_ >= '0' && *p_ <= '9') || *p_ == '-' || *p_ == '+' || *p_ == '.' || *p_ == 'e' || *p_ == 'E')) p_++;
        n = (size_t)(p_ - b);
    }
    bool literal(const char* lit) {
        size_t n = strlen(lit);
        if ((size_t)(end_ - p_) < n || memcmp(p_, lit, n) != 0) return false;
        p_ += n;
        return true;
    }

private:
    const char* p_;
    const char* end_;
};

bool lowerAlnum(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }
bool digit(char c) { return c >= '0' && c <= '9'; }

bool validSlug(const char* s) {           // product, board
    if (!lowerAlnum(s[0])) return false;
    for (const char* p = s + 1; *p; p++) if (!lowerAlnum(*p) && *p != '-' && *p != '_' && *p != '.') return false;
    return true;
}
bool validChip(const char* s) {
    if (!*s) return false;
    for (const char* p = s; *p; p++) if (!lowerAlnum(*p)) return false;
    return true;
}
bool validKeyId(const char* s) {
    if (!*s) return false;
    for (const char* p = s; *p; p++)
        if (!lowerAlnum(*p) && !(*p >= 'A' && *p <= 'Z') && *p != '-' && *p != '_' && *p != '.') return false;
    return true;
}
bool validChannel(const char* s) {        // a closed set: anything else is refused, as before
    return !strcmp(s, "stable") || !strcmp(s, "beta") || !strcmp(s, "dev");
}
bool validUrlSyntax(const char* s) {      // host/allow-list checks are policy (fota_checks.h)
    if (strncmp(s, "https://", 8) != 0 || !s[8]) return false;
    for (const char* p = s; *p; p++) if ((unsigned char)*p <= 0x20 || (unsigned char)*p >= 0x7F) return false;
    return true;
}
bool validSha(const char* s) {
    size_t n = 0;
    for (; s[n]; n++) if (!digit(s[n]) && !(s[n] >= 'a' && s[n] <= 'f')) return false;
    return n == 64;
}
int num2(const char* s) { return (s[0] - '0') * 10 + (s[1] - '0'); }
bool validTimestamp(const char* s) {      // YYYY-MM-DDTHH:MM:SSZ
    const char* pat = "dddd-dd-ddTdd:dd:ddZ";
    if (strlen(s) != 20) return false;
    for (int i = 0; i < 20; i++) {
        if (pat[i] == 'd') { if (!digit(s[i])) return false; }
        else if (s[i] != pat[i]) return false;
    }
    int mo = num2(s + 5), d = num2(s + 8), h = num2(s + 11), mi = num2(s + 14), se = num2(s + 17);
    return mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && h < 24 && mi < 60 && se < 60;
}

bool validString(const char* name, const char* v) {
    if (!strcmp(name, "product") || !strcmp(name, "board")) return validSlug(v);
    if (!strcmp(name, "chip")) return validChip(v);
    if (!strcmp(name, "channel")) return validChannel(v);
    if (!strcmp(name, "version") || !strcmp(name, "min_version")) { SemVer sv; return parseSemVer(v, sv); }
    if (!strcmp(name, "url")) return validUrlSyntax(v);
    if (!strcmp(name, "sha256")) return validSha(v);
    if (!strcmp(name, "key_id")) return validKeyId(v);
    if (!strcmp(name, "released_at")) return validTimestamp(v);
    return false;
}

const FieldDef* findField(const char* key) {
    for (size_t i = 0; i < kFieldCount; i++) if (!strcmp(kFields[i].name, key)) return &kFields[i];
    return nullptr;
}

// Parses a scalar value at the cursor. String values land in sbuf; integer values in ival.
// Returns Ok, Syntax, Nested, BadType (float/negative/bool/null), FieldTooLong or BadValue (leading zero, > 2^31-1).
ManifestError scalar(Reader& r, Kind& kind, char* sbuf, uint32_t& ival) {
    char c = r.peek();
    if (c == '"') {
        size_t n = 0;
        Tok t = r.string(sbuf, kMaxString + 1, n);
        if (t == Tok::Syntax) return ManifestError::Syntax;
        kind = Kind::String;
        return t == Tok::TooLong ? ManifestError::FieldTooLong : ManifestError::Ok;
    }
    if (c == '{' || c == '[') return ManifestError::Nested;
    if (digit(c) || c == '-') {
        const char* b;
        size_t n;
        r.numberToken(b, n);
        for (size_t i = 0; i < n; i++) if (!digit(b[i])) return ManifestError::BadType;   // float, exponent, sign
        kind = Kind::Int;
        if (n > 1 && b[0] == '0') return ManifestError::BadValue;
        if (n > 10) return ManifestError::BadValue;
        uint64_t v = 0;
        for (size_t i = 0; i < n; i++) v = v * 10 + (uint64_t)(b[i] - '0');
        if (v > 0x7FFFFFFFull) return ManifestError::BadValue;
        ival = (uint32_t)v;
        return ManifestError::Ok;
    }
    if (r.literal("true") || r.literal("false") || r.literal("null")) return ManifestError::BadType;
    return ManifestError::Syntax;
}

} // namespace

ManifestError parseManifest(const char* data, size_t len, Manifest& out, const char** field) {
    const char* dummy;
    const char*& bad = field ? *field : dummy;
    bad = "";
    if (len > kMaxManifestBytes) return ManifestError::TooLarge;
    if (!data) return ManifestError::Syntax;

    Reader r(data, len);
    r.skipWs();
    if (r.atEnd()) return ManifestError::Syntax;
    if (!r.take('{')) return (r.peek() == '[' || r.peek() == '"' || digit(r.peek())) ? ManifestError::NotObject
                                                                                    : ManifestError::Syntax;
    Manifest m;
    uint32_t seen = 0;
    bool unknown = false;
    const char* unknownName = "";
    char key[24];
    char sbuf[kMaxString + 1];

    r.skipWs();
    if (!r.take('}')) {
        while (true) {
            r.skipWs();
            size_t klen = 0;
            Tok kt = r.string(key, sizeof(key), klen);
            if (kt == Tok::Syntax) return ManifestError::Syntax;
            const FieldDef* f = kt == Tok::Ok ? findField(key) : nullptr;
            r.skipWs();
            if (!r.take(':')) return ManifestError::Syntax;
            r.skipWs();
            Kind kind = Kind::String;
            uint32_t ival = 0;
            ManifestError e = scalar(r, kind, sbuf, ival);
            if (!f) {
                if (e == ManifestError::Syntax || e == ManifestError::Nested) return e;
                if (!unknown) { unknown = true; unknownName = ""; }
            } else {
                const uint32_t bit = 1u << (f - kFields);
                bad = f->name;
                if (seen & bit) return ManifestError::DuplicateKey;
                seen |= bit;
                if (e != ManifestError::Ok && e != ManifestError::FieldTooLong && e != ManifestError::BadValue) return e;
                if (kind != f->kind) return ManifestError::BadType;
                if (e != ManifestError::Ok) return e;
                if (kind == Kind::Int) {
                    *(uint32_t*)((char*)&m + f->offset) = ival;
                } else {
                    if (strlen(sbuf) + 1 > f->capacity) return ManifestError::FieldTooLong;
                    if (!validString(f->name, sbuf)) return ManifestError::BadValue;
                    strcpy((char*)&m + f->offset, sbuf);
                }
                bad = "";
            }
            r.skipWs();
            if (r.take(',')) continue;
            if (r.take('}')) break;
            return ManifestError::Syntax;
        }
    }
    r.skipWs();
    if (!r.atEnd()) return ManifestError::Syntax;

    // Schema first: a newer schema may legitimately carry keys this parser does not know.
    if ((seen & 1u) && m.schema != 1) { bad = "schema"; return ManifestError::UnsupportedSchema; }
    if (unknown) { bad = unknownName; return ManifestError::UnknownKey; }
    for (size_t i = 0; i < kFieldCount; i++)
        if (kFields[i].required && !(seen & (1u << i))) { bad = kFields[i].name; return ManifestError::MissingField; }
    if (m.size == 0) { bad = "size"; return ManifestError::BadValue; }
    if (m.hasMinVersion()) {
        int c = 0;
        if (!compareVersions(m.min_version, m.version, c) || c > 0) { bad = "min_version"; return ManifestError::BadValue; }
    }
    out = m;
    return ManifestError::Ok;
}

} // namespace fota
