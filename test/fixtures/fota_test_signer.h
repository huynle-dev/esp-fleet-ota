// TEST-ONLY P-256 signer generated at test time (OpenSSL). Keys live only in memory for the test run.
#pragma once
#include <cstdio>
#include <string>
#include <vector>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

struct TestSigner {
    EC_KEY* key = nullptr;
    std::vector<uint8_t> spki;
    TestSigner() {
        key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_generate_key(key);
        EVP_PKEY* pk = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pk, key);
        int n = i2d_PUBKEY(pk, nullptr);
        spki.resize((size_t)n);
        uint8_t* p = spki.data();
        i2d_PUBKEY(pk, &p);
        EVP_PKEY_free(pk);
    }
    ~TestSigner() { EC_KEY_free(key); }
    TestSigner(const TestSigner&) = delete;
    TestSigner& operator=(const TestSigner&) = delete;

    static std::string b64(const uint8_t* d, size_t n) {
        static const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string o;
        for (size_t i = 0; i < n; i += 3) {
            uint32_t v = (uint32_t)d[i] << 16 | (i + 1 < n ? (uint32_t)d[i + 1] << 8 : 0) | (i + 2 < n ? d[i + 2] : 0);
            o += A[(v >> 18) & 63];
            o += A[(v >> 12) & 63];
            o += i + 1 < n ? A[(v >> 6) & 63] : '=';
            o += i + 2 < n ? A[v & 63] : '=';
        }
        return o;
    }
    // base64 of the DER signature over SHA-256(msg)
    std::string signB64(const std::string& msg) const {
        uint8_t h[32];
        SHA256((const uint8_t*)msg.data(), msg.size(), h);
        uint8_t sig[80];
        unsigned int n = sizeof(sig);
        ECDSA_sign(0, h, 32, sig, &n, key);
        return b64(sig, n);
    }
    std::string signVault(const std::string& msg, unsigned version) const {
        return "vault:v" + std::to_string(version) + ":" + signB64(msg);
    }
};

static inline std::string testSha256Hex(const std::string& b) {
    uint8_t h[32];
    SHA256((const uint8_t*)b.data(), b.size(), h);
    char out[65];
    for (int i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02x", h[i]);
    return out;
}

#pragma GCC diagnostic pop
