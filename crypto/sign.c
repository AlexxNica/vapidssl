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

#include "crypto/sign.h"

#include <assert.h>
#include <stddef.h>

#include "base/buf.h"
#include "crypto/hash.h"
#include "crypto/sign_internal.h"
#include "public/error.h"

// Forward declarations.

// sign_is_valid checks that |sign| is consistent with itself.
static void sign_is_valid(const SIGN *sign);

// Library routines

const HASH *sign_get_hash(const SIGN *sign) {
  assert(sign);
  return hash_find(sign->hash_algorithm);
}

tls_result_t sign_verify(const SIGN *sign, const BUF *digest,
                         const BUF *signature, const BUF *public_key) {
  sign_is_valid(sign);
  const HASH *hash = hash_find(sign->hash_algorithm);
  assert(buf_ready(digest) == hash_get_output_size(hash));
  return sign->verify(sign, digest, signature, public_key);
}

// Static functions.

static void sign_is_valid(const SIGN *sign) {
  assert(sign);
  assert(sign_find(sign->algorithm, sign->hash_algorithm) == sign);
}
