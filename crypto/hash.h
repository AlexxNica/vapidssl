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

#ifndef VAPIDSSL_CRYPTO_HASH_H
#define VAPIDSSL_CRYPTO_HASH_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "public/config.h"
#include "public/error.h"

// The HASH structure represents a wrapper around a Merkle-Damgard cryptographic
// hash algorithm implemented by the crypto library.  The output of a hash is
// referred to as a "digest", and the unit of Merkel-Damgard compression is
// referred to as a "block".  As an example, the following initializes and
// hashes some |data| to produce a |digest|, given an |algorithm| and a memory
// region |mem|:
//    const HASH *hash = hash_find(id);
//    BUF state = buf_init();
//    buf_malloc(mem, hash_get_state_size(hash), &state);
//    BUF digest = buf_init();
//    buf_malloc(mem, hash_get_output_size(hash), &digest);
//    hash_init(hash, &state);
//    hash_update(hash, &state, &data);
//    hash_final(hash, &state, &digest);
//
// A wrapper for a specific crypto library must implement the details of the
// HASH structure as documented in hash_internal.h, and |hash_find|.  All other
// functions in this file are generic and implemented by hash.c.

// Cryptographic hash structure, defined in crypto/hash_internal.h.
typedef struct hash_st HASH;

// tls_hash_t is prefixed because is externally visible in config.h.  Add a
// typedef to match |aead_t|, |keyex_t|, and |sign_t|.
typedef tls_hash_t hash_t;
#define VAPIDSSL_HASHES 2
#if VAPIDSSL_HASHES > 0xFF
#error "Number of hash algorithms must fit in 1 byte";
#endif

// hash_find takes an |id| and returns a pointer to the matching cryptographic
// hash algorithm, or NULL if the |id| is unrecognized.
const HASH *hash_find(uint16_t id);

// hash_next returns another supported hash algorithm that is distinct from
// |hash|, which may be NULL, or it returns NULL.  The hashes are not returned
// in any prescribed order.  |hash_next| can be used to enumerate the supported
// hash algorithms as follows:
//   for (const HASH* hash = hash_next(NULL); hash; hash = hash_next(hash));
const HASH *hash_next(const HASH *hash);

// hash_get_state_size gives the minimum size required by |hash| for the |state|
// buffer in each of its cryptographic operations.
size_t hash_get_state_size(const HASH *hash);

// hash_get_block_size returns |hash|'s compression block size.  This value is
// typically an implementation detail irrelevant to digest consumers, but it is
// used the logic of consumers such as |hmac_init|.
size_t hash_get_block_size(const HASH *hash);

// hash_get_output_size returns the size of a digest produced by |hash|.
size_t hash_get_output_size(const HASH *hash);

// init sets up the |state| buffer for use in generating a message digest.
// Calling |init| twice will reinitialize the hash |state|.
void hash_init(const HASH *hash, BUF *state);

// update hashes |data| into the hash |state| previously set up by |init|.
// |update| may be called multiple times before calling |final|.
void hash_update(const HASH *hash, BUF *state, const BUF *data);

// final takes the current |hash| state and produces a message digest that it
// write to |out|. No further calls to |update| for a given |state| are allowed
// after |final| has been called and until |init| is called again.
void hash_final(const HASH *hash, BUF *state, BUF *out);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_CRYPTO_HASH_H
