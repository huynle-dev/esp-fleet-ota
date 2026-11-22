// Crypto primitives the pure logic needs, behind small interfaces so the logic is testable on the host.
// Device backend: mbedTLS (src/esp/fota_mbedtls.h). Host test backend: OpenSSL libcrypto (src/host/fota_openssl.h).
// See docs/decisions.md D3. No Arduino headers.
#pragma once
#include <cstddef>
#include <cstdint>

namespace fota {

class ISha256 {
public:
    virtual ~ISha256() = default;
    virtual void begin() = 0;
    virtual void update(const uint8_t* data, size_t len) = 0;
    virtual void finish(uint8_t out[32]) = 0;
};

class IEcdsaP256Verifier {
public:
    virtual ~IEcdsaP256Verifier() = default;
    // `publicKey` is a SubjectPublicKeyInfo in DER, or PEM ("-----BEGIN PUBLIC KEY-----"; `keyLen` excludes the NUL).
    // `sig` is an ASN.1 DER ECDSA-Sig-Value. Must return false for a key that is not an EC key on P-256.
    virtual bool verify(const uint8_t* publicKey, size_t keyLen, const uint8_t hash[32], const uint8_t* sig,
                        size_t sigLen) = 0;
};

} // namespace fota
