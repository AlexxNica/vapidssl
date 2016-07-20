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

#ifndef VAPIDSSL_CRYPTO_SIGN_INTERNAL_H
#define VAPIDSSL_CRYPTO_SIGN_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "crypto/hash.h"
#include "public/error.h"

// sign_st associates an |id| with a function pointers for performing
// signature
// verification.
struct sign_st {
  // algorithm identifies this signature verification algorithm, and should
  // match a value of |sign_t| in config.h.
  uint16_t algorithm;
  // hash_algorithm identifies the hash algorithm used to generate a digest of
  // the signed data.
  uint16_t hash_algorithm;
  // verify uses |hash| to produce a digest of the |signed_data| and checks it
  // against the value obtain by decrypting the |signature| using the
  // |public_key|.
  tls_result_t (*verify)(const struct sign_st *sign, const BUF *digest,
                         const BUF *public_key, const BUF *signature);
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_CRYPTO_SIGN_INTERNAL_H
