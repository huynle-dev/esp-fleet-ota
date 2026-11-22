#ifdef FLEET_OTA_WITH_OPENSSL
#include "fota_openssl.h"
#include <cstring>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

namespace fota {

OpensslSha256::OpensslSha256() : ctx_(EVP_MD_CTX_new()) {}
OpensslSha256::~OpensslSha256() { EVP_MD_CTX_free((EVP_MD_CTX*)ctx_); }
void OpensslSha256::begin() { EVP_DigestInit_ex((EVP_MD_CTX*)ctx_, EVP_sha256(), nullptr); }
void OpensslSha256::update(const uint8_t* d, size_t n) { EVP_DigestUpdate((EVP_MD_CTX*)ctx_, d, n); }
void OpensslSha256::finish(uint8_t out[32]) {
    unsigned int n = 32;
    EVP_DigestFinal_ex((EVP_MD_CTX*)ctx_, out, &n);
}

bool OpensslEcdsaP256::verify(const uint8_t* key, size_t keyLen, const uint8_t hash[32], const uint8_t* sig,
                              size_t sigLen) {
    EVP_PKEY* pk = nullptr;
    static const char kPem[] = "-----BEGIN";
    if (keyLen >= sizeof(kPem) - 1 && memcmp(key, kPem, sizeof(kPem) - 1) == 0) {
        BIO* bio = BIO_new_mem_buf(key, (int)keyLen);
        pk = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    } else {
        const unsigned char* p = key;
        pk = d2i_PUBKEY(nullptr, &p, (long)keyLen);
    }
    if (!pk) return false;
    bool ok = false;
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pk);
    if (ec && EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) == NID_X9_62_prime256v1)
        ok = ECDSA_verify(0, hash, 32, sig, (int)sigLen, (EC_KEY*)ec) == 1;
    EVP_PKEY_free(pk);
    return ok;
}

} // namespace fota
#endif
