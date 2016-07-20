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

#ifndef VAPIDSSL_CRYPTO_AEAD_INTERNAL_H
#define VAPIDSSL_CRYPTO_AEAD_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/types.h"
#include "public/error.h"

// aead_st associates an |id| with the various parameters of a specific AEAD
// cipher, as well as with the function pointers to functions for initializing
// the cipher and processing data in each direction.
struct aead_st {
  // algorithm identifies this cipher's algorithm. It must match a value of
  // |aead_t|.
  uint16_t algorithm;
  // state_size gives the amount of memory, in bytes, needed by this cipher.
  size_t state_size;
  // key_size gives the key length in bytes.
  size_t key_size;
  // tag_size gives the length of the MAC tag added or removed by the cipher.
  size_t tag_size;
  // init sets up the |state| buffer for use in sealing or opening ciphertexts
  // using the given |key|, depending on the |direction|.
  tls_result_t (*init)(const struct aead_st *aead, BUF *state, BUF *key,
                       direction_t direction);
  // data uses a prepared |state| and |nonce| to seal a plain |text| or open a
  // cipher |text| with associated authenticated |additional_data|, depending on
  // the |direction|.
  tls_result_t (*data)(const struct aead_st *aead, BUF *state, BUF *nonce,
                       BUF *ciphertext, BUF *additional_data,
                       direction_t direction);
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_CRYPTO_AEAD_INTERNAL_H
