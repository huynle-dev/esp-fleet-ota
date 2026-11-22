// Known-answer test of the crypto backend (SHA-256 + ECDSA P-256 verify), so a device can prove at boot that its
// mbedTLS backend accepts a good signature and refuses a bad one before it trusts any manifest. The KAT key is a
// throwaway key that is in no trusted key table. No Arduino headers.
#pragma once
#include "fota_crypto.h"

namespace fota {

// true when: SHA-256("abc") matches the FIPS 180-2 vector, the KAT signature verifies, and a one-bit-flipped
// message, a flipped signature and a truncated signature are all refused.
bool cryptoSelfCheck(ISha256& sha, IEcdsaP256Verifier& ecdsa);

} // namespace fota
