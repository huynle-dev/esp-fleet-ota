// Host (test) crypto backend on OpenSSL libcrypto. Compiled only with -DFLEET_OTA_WITH_OPENSSL (the native test env).
#pragma once
#include "../fota_crypto.h"

#ifdef FLEET_OTA_WITH_OPENSSL
namespace fota {

class OpensslSha256 : public ISha256 {
public:
    OpensslSha256();
    ~OpensslSha256() override;
    void begin() override;
    void update(const uint8_t* data, size_t len) override;
    void finish(uint8_t out[32]) override;

private:
    void* ctx_;
};

class OpensslEcdsaP256 : public IEcdsaP256Verifier {
public:
    bool verify(const uint8_t* publicKey, size_t keyLen, const uint8_t hash[32], const uint8_t* sig,
                size_t sigLen) override;
};

} // namespace fota
#endif
