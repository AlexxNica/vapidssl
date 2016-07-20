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

#ifndef VAPIDSSL_CRYPTO_HASH_INTERNAL_H
#define VAPIDSSL_CRYPTO_HASH_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "public/config.h"
#include "public/error.h"

// hash_st associates an |id| with the various parameters of a specific
// cryptographic hash algorithm, as well as with the function pointers to
// functions for initializing, updating, and producing the digest.
struct hash_st {
  // algorithm identifies this hash algorithm, and should match a value of
  // |tls_hash_t| in vapidssl/config.h.
  uint16_t algorithm;
  // state_size gives the amount of memory, in bytes, needed by this hash.
  size_t state_size;
  // block_size is the size of the input to the underlying compression function
  // in Merkle-Damgard construction. I can be used to check that the data has
  // been compressed at least once.
  size_t block_size;
  // out_size gives the length in bytes of a resulting message digest.
  size_t out_size;
  // init sets up the |state| buffer for use in generating a message digest.
  // Calling |init| twice will reinitialize the hash |state|.
  void (*init)(const struct hash_st *hash, BUF *state);
  // update hashes |data| into the hash |state| previously set up by |init|.
  // |update| may be called multiple times before calling |final|.
  void (*update)(const struct hash_st *hash, BUF *state, const BUF *data);
  // final takes the current |hash| state and produces a message digest that it
  // write to |out|. No further calls to |update| for a given |state| are
  // allowed after |final| has been called and until |init| is called again.
  void (* final)(const struct hash_st *hash, BUF *state, BUF *out);
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_CRYPTO_HASH_INTERNAL_H
