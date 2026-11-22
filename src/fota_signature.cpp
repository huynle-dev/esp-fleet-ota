#include "fota_signature.h"
#include <cstring>

namespace fota {

const char* sigErrorName(SigError e) {
    switch (e) {
        case SigError::Ok: return "Ok";
        case SigError::UnknownKeyId: return "UnknownKeyId";
        case SigError::BadFormat: return "BadFormat";
        case SigError::KeyVersionMismatch: return "KeyVersionMismatch";
        case SigError::Invalid: return "Invalid";
    }
    return "Unknown";
}

namespace {

int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool isWs(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

// Parses "vault:v<N>:" at s (len n). Returns true and the prefix length / N when present and well formed.
// Returns false with prefixLen 0 when the text does not start with "vault:"; false with prefixLen 1 when malformed.
bool vaultPrefix(const char* s, size_t n, size_t& prefixLen, uint32_t& version) {
    prefixLen = 0;
    if (n < 6 || memcmp(s, "vault:", 6) != 0) return false;
    prefixLen = 1;
    size_t i = 6;
    if (i >= n || s[i] != 'v') return false;
    i++;
    size_t start = i;
    uint64_t v = 0;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
        v = v * 10 + (uint64_t)(s[i] - '0');
        if (v > 0xFFFFFFFFull) return false;
        i++;
    }
    if (i == start || (s[start] == '0') || i >= n || s[i] != ':') return false;
    prefixLen = i + 1;
    version = (uint32_t)v;
    return true;
}

} // namespace

bool base64Decode(const char* in, size_t len, uint8_t* out, size_t cap, size_t& outLen) {
    if (len % 4) return false;
    size_t n = 0;
    for (size_t i = 0; i < len; i += 4) {
        const bool last = i + 4 == len;
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; k++) {
            char c = in[i + k];
            if (c == '=' && last && k >= 2) { v[k] = 0; pad++; continue; }
            if (pad) return false;                       // data after '='
            v[k] = b64val(c);
            if (v[k] < 0) return false;
        }
        if (pad == 1 && (v[2] & 0x3)) return false;       // non-canonical trailing bits
        if (pad == 2 && (v[1] & 0xF)) return false;
        const uint32_t w = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) | ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        const int bytes = 3 - pad;
        if (n + (size_t)bytes > cap) return false;
        out[n++] = (uint8_t)(w >> 16);
        if (bytes > 1) out[n++] = (uint8_t)(w >> 8);
        if (bytes > 2) out[n++] = (uint8_t)w;
    }
    outLen = n;
    return true;
}

namespace {
bool knownKeyId(const char* keyId, const TrustedKey* keys, size_t count) {
    if (!keyId || !*keyId || !keys) return false;
    for (size_t i = 0; i < count; i++)
        if (keys[i].key_id && !strcmp(keys[i].key_id, keyId)) return true;
    return false;
}
} // namespace

const TrustedKey* findTrustedKey(const char* keyId, uint32_t keyVersion, const TrustedKey* keys, size_t count) {
    if (!knownKeyId(keyId, keys, count)) return nullptr;
    for (size_t i = 0; i < count; i++)
        if (keys[i].key_id && !strcmp(keys[i].key_id, keyId) && keys[i].key_version == keyVersion) return &keys[i];
    return nullptr;
}

SigError verifyManifestSignature(const char* manifest, size_t manifestLen, const char* keyId, const char* sigText,
                                 size_t sigLen, const TrustedKey* keys, size_t keyCount, ISha256& sha,
                                 IEcdsaP256Verifier& ecdsa) {
    if (!knownKeyId(keyId, keys, keyCount)) return SigError::UnknownKeyId;
    if (!sigText || sigLen == 0 || sigLen > kMaxSignatureText) return SigError::BadFormat;

    size_t b = 0, e = sigLen;
    while (b < e && isWs(sigText[b])) b++;
    while (e > b && isWs(sigText[e - 1])) e--;
    if (b == e) return SigError::BadFormat;

    size_t prefix = 0;
    uint32_t version = 0;
    const bool vault = vaultPrefix(sigText + b, e - b, prefix, version);
    if (!vault && prefix) return SigError::BadFormat;
    if (vault) b += prefix;
    if (b == e) return SigError::BadFormat;

    uint8_t der[80];
    size_t derLen = 0;
    if (!base64Decode(sigText + b, e - b, der, sizeof(der), derLen) || derLen == 0) return SigError::BadFormat;
    const TrustedKey* key = findTrustedKey(keyId, vault ? version : 0, keys, keyCount);
    if (!key) return SigError::KeyVersionMismatch;

    uint8_t hash[32];
    sha.begin();
    sha.update((const uint8_t*)manifest, manifestLen);
    sha.finish(hash);
    if (!ecdsa.verify(key->public_key, key->public_key_len, hash, der, derLen)) return SigError::Invalid;
    return SigError::Ok;
}

} // namespace fota
