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

#include "crypto/hash.h"

#include <assert.h>
#include <stddef.h>

#include "base/buf.h"
#include "crypto/hash_internal.h"

// Forward declarations.

// hash_is_valid checks that |hash| is consistent with itself.
static void hash_is_valid(const HASH *hash);

// Library routines

size_t hash_get_state_size(const HASH *hash) {
  hash_is_valid(hash);
  return hash->state_size;
}

size_t hash_get_block_size(const HASH *hash) {
  hash_is_valid(hash);
  return hash->block_size;
}

size_t hash_get_output_size(const HASH *hash) {
  hash_is_valid(hash);
  return hash->out_size;
}

void hash_init(const HASH *hash, BUF *state) {
  hash_is_valid(hash);
  assert(buf_size(state) == hash->state_size);
  hash->init(hash, state);
}

void hash_update(const HASH *hash, BUF *state, const BUF *data) {
  hash_is_valid(hash);
  assert(buf_size(state) == hash->state_size);
  assert(data);
  hash->update(hash, state, data);
}

void hash_final(const HASH *hash, BUF *state, BUF *out) {
  hash_is_valid(hash);
  assert(buf_size(state) == hash->state_size);
  assert(out);
  hash->final(hash, state, out);
}

// Static functions.

static void hash_is_valid(const HASH *hash) {
  assert(hash);
  assert(hash_find(hash->algorithm) == hash);
}
