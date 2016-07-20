// Copyright 2016 The Fuchsia Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef VAPIDSSL_CRYPTO_SIGN_H
#define VAPIDSSL_CRYPTO_SIGN_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "crypto/hash.h"
#include "public/error.h"

// The SIGN structure represents a wrapper around a cryptographic signature
// verification algorithm. As an example, the following takes |signed_data| and
// and associated |public_key| and attempts to verify a given |signature| is
// valid, given an |id|:
//    hash_init(hash, state);
//    hash_update(hash, state, signed_data);
//    hash_final(hash, state, digest);
//    const SIGN* sign = sign_find(id);
//    sign_verify(sign, digest, signature, public_key);
//
// A wrapper for a specific crypto library must implement the details of the
// SIGN structure as documented in sign_internal.h, and |sign_find|.
// All other
// functions in this file are generic and implemented by sign.c.

// Supported signing algorithms, numbered per RFC 5246, section 7.4.1.4.1
// (https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1). These should
// correspond to the ciphersuites enumerated by |tls_ciphersuite_t|.
typedef enum sign_t {
  kSignRSA = 1,
} sign_t;
#define VAPIDSSL_SIGNS 1
#if VAPIDSSL_SIGNS > 0xFF
#error "Number of signature algorithms must fit in 1 byte";
#endif

// Signature verification structure, defined in crypto/sign_internal.h.
typedef struct sign_st SIGN;

// sign_get_hash returns the hash algorithm used in generating signatures to be
// verified by |sign|.
const HASH *sign_get_hash(const SIGN *sign);

// sign_find takes an |algorithm| and a |hash_algorithm| and returns a pointer
// to the matching signature verification algorithm, or NULL if the |algorithm|
// or |hash_algorithm| are unrecognized.  |hash_algorithm| may be the special
// value of |kCryptoAny|.
const SIGN *sign_find(uint16_t algorithm, uint16_t hash_algorithm);

// sign_verify decrypts the |signature| using the |public_key|, and checks if
// the result matches the given |digest|.  The |digest| must have been created
// by the message digest algorithm indicated by the |sign|'s hash_algorithm.
tls_result_t sign_verify(const SIGN *sign, const BUF *digest,
                         const BUF *signature, const BUF *public_key);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_CRYPTO_SIGN_H
