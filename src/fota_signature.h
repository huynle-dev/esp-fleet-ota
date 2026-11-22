// Detached manifest signature: ECDSA P-256 with SHA-256 over the EXACT manifest bytes. No Arduino headers.
//
// Accepted signature encodings (the .sig file; leading/trailing whitespace and newlines are trimmed):
//   vault:v<N>:<base64 DER>   OpenBao transit/sign output, N = transit key version (>= 1)
//   <base64 DER>              bare, e.g. a YubiKey break-glass key; selects the entry with key_version 0
// The key is chosen by (manifest key_id, N) from a compiled-in table (several entries may share a key_id, one per
// trusted N). Unknown key_id -> UnknownKeyId; known key_id but no entry for that N -> KeyVersionMismatch.
// The manifest bytes are hashed exactly as given: no trimming, no normalisation.
#pragma once
#include <cstddef>
#include <cstdint>
#include "fota_crypto.h"

namespace fota {

struct TrustedKey {
    const char* key_id;        // matches Manifest::key_id
    uint32_t key_version;      // OpenBao transit key version N (>= 1); 0 = not a vault key (bare base64 signatures)
    const uint8_t* public_key; // SPKI DER, or PEM text
    size_t public_key_len;     // bytes (PEM: without the trailing NUL)
};

enum class SigError : uint8_t {
    Ok = 0,
    UnknownKeyId,
    BadFormat,          // not base64 / not vault:vN: / empty / too long
    KeyVersionMismatch, // key_id known but no entry for this N (bare = N 0)
    Invalid,            // the signature does not verify (tampered, wrong key, malformed DER, wrong curve)
};

const char* sigErrorName(SigError e);

constexpr size_t kMaxSignatureText = 160;   // "vault:v4294967295:" + base64 of a 72-byte DER signature, with slack

const TrustedKey* findTrustedKey(const char* keyId, uint32_t keyVersion, const TrustedKey* keys, size_t count);

SigError verifyManifestSignature(const char* manifest, size_t manifestLen, const char* keyId, const char* sigText,
                                 size_t sigLen, const TrustedKey* keys, size_t keyCount, ISha256& sha,
                                 IEcdsaP256Verifier& ecdsa);

// Strict base64 (RFC 4648, standard alphabet, '=' padding required). Returns false on any invalid input or when the
// output would exceed `cap`.
bool base64Decode(const char* in, size_t len, uint8_t* out, size_t cap, size_t& outLen);

} // namespace fota
