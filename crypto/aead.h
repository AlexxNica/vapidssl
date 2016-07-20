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

#ifndef VAPIDSSL_CRYPTO_AEAD_H
#define VAPIDSSL_CRYPTO_AEAD_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "public/error.h"


// The AEAD structure represents a wrapper around an authenticated encryption
// and decryption cipher implemented by the crypto library.  Encrypting
// plaintext is referred to as "sealing", and decrypting ciphertexts as
// "opening".  As an example, the following initializes and seals the
// unencrypted |data|, then initializes and opens the unencrypted |data|, given
// an |id|, a memory region |mem|, a |key|, a |nonce|, and |additional| data to
// be authenticated:
//    const AEAD *aead = aead_find(id);
//    BUF state = buf_init();
//    buf_malloc(mem, aead_get_state_size(aead), &state);
//    aead_init(aead, &state, &key, kSend);
//    aead_data(aead, &state, &nonce, &additional, &data, kSend);
//    // The data is now encrypted
//    aead_init(aead, &state, &key, kRecv);
//    aead_data(aead, &state, &nonce, &additional, &data, kRecv);
//    // The data is now unencrypted again.
//
// A wrapper for a specific crypto library must implement the details of the
// AEAD structure as documented in aead_internal.h, and |aead_find|.  All other
// functions in this file are generic and implemented by aead.c.

// Supported AEAD ciphers.  These should correspond to the ciphersuites
// enumerated by |tls_ciphersuite_t|. 0 is avoided to require |aead_t| fields to
// be explicitly set.
typedef enum aead_t {
  kAeadAes128Gcm = 1,
  kAeadAes256Gcm,
  kAeadChaCha20Poly1305,
} aead_t;
#define VAPIDSSL_AEADS 3

// AEAD cipher structure, defined in crypto/aead_internal.h.
typedef struct aead_st AEAD;

// aead_find takes an |algorithm| and returns a pointer to the matching AEAD
// cipher, or NULL if the |algorithm| is unrecognized.
const AEAD *aead_find(uint16_t algorithm);

// aead_next returns another supported AEAD algorithm that is distinct from
// |aead|, which may be NULL, or it returns NULL.  The AEADs are not returned
// in any prescribed order.  |aead_next| can be used to enumerate the supported
// AEAD algorithms as follows:
//   for (const AEAD* aead = aead_next(NULL); aead; aead = aead_next(aead));
const AEAD *aead_next(const AEAD *aead);

// aead_get_state_size gives the minimum size required by |aead| for the |state|
// buffer in each of its cryptographic operations.
size_t aead_get_state_size(const AEAD *aead);

// aead_get_key_size gives the size required by |aead| for the |key| buffer in
// each of its cryptographic operations.
size_t aead_get_key_size(const AEAD *aead);

// aead_get_tag_size gives the default length of the authentication tag added or
// removed by |aead|.
size_t aead_get_tag_size(const AEAD *aead);

// aead_init sets up the |state| buffer for use in sealing plaintexts or opening
// ciphertexts using the given |aead| and |key|.  Whether it will seal or open
// depends on the |direction|. |key| must contain exactly the number of bytes
// returned by |aead_get_key_size|.
tls_result_t aead_init(const AEAD *aead, BUF *state, BUF *key,
                       direction_t direction);

// aead_data uses an |aead| and a prepared |state| and |nonce| to seal plaintext
// and make it |encrypted|, or open |encrypted| ciphertexts.  Both may have
// additional |authenticated| data. Whether it seals or opens depends on the
// |direction|.  When sealing, |encrypted| must have enough space authentication
// tag. |nonce| and |authenticated| are passed directly to the crypto library,
// without any additional validation of their lengths.
tls_result_t aead_data(const AEAD *aead, BUF *state, BUF *nonce,
                       BUF *authenticated, BUF *encrypted,
                       direction_t direction);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_CRYPTO_AEAD_H
