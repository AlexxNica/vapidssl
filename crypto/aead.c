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

#include "crypto/aead.h"

#include <assert.h>
#include <stddef.h>

#include "base/buf.h"
#include "base/types.h"
#include "crypto/aead_internal.h"
#include "public/error.h"

// Forward declarations.

// aead_is_valid checks that |aead| is consistent with itself.
static void aead_is_valid(const AEAD *aead);

// Library routines.

size_t aead_get_state_size(const AEAD *aead) {
  aead_is_valid(aead);
  return aead->state_size;
}

size_t aead_get_key_size(const AEAD *aead) {
  aead_is_valid(aead);
  return aead->key_size;
}

size_t aead_get_tag_size(const AEAD *aead) {
  aead_is_valid(aead);
  return aead->tag_size;
}

tls_result_t aead_init(const AEAD *aead, BUF *state, BUF *key,
                       direction_t direction) {
  aead_is_valid(aead);
  assert(buf_size(state) == aead->state_size);
  assert(buf_size(key) == aead->key_size);
  buf_reset(key, 0);
  buf_produce(key, aead->key_size, NULL);
  return aead->init(aead, state, key, direction);
}

tls_result_t aead_data(const AEAD *aead, BUF *state, BUF *nonce,
                       BUF *authenticated, BUF *encrypted,
                       direction_t direction) {
  aead_is_valid(aead);
  assert(buf_size(state) == aead->state_size);
  return aead->data(aead, state, nonce, authenticated, encrypted, direction);
}

// Static functions.

static void aead_is_valid(const AEAD *aead) {
  assert(aead);
  assert(aead_find(aead->algorithm) == aead);
}
