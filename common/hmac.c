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

#include "common/hmac.h"
#include "common/hmac_internal.h"

#include <assert.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "crypto/hash.h"

size_t hmac_size(const HASH *hash) {
  assert(hash);
  // The "high water" mark is in |hmac_init|, since |ipad| is bigger than the
  // |digest| in |hmac_final|.
  return hash_get_state_size(hash) + (hash_get_block_size(hash) * 2);
}

tls_result_t hmac_init(BUF *region, const HASH *hash, BUF *secret, HMAC *out) {
  assert(region);
  assert(hash);
  assert(secret);
  assert(out);
  size_t state_size = hash_get_state_size(hash);
  size_t block_size = hash_get_block_size(hash);
  memset(out, 0, sizeof(*out));
  out->hash = hash;
  if (!buf_malloc(region, state_size, &out->state) ||
      !buf_malloc(region, block_size, &out->pad)) {
    return kTlsFailure;
  }
  // Hash long secrets
  hash_init(hash, &out->state);
  if (buf_ready(secret) > block_size) {
    hash_update(hash, &out->state, secret);
    buf_reset(secret, 0);
    hash_final(hash, &out->state, secret);
  }
  // Add ipad to hash
  buf_fill(&out->pad, 0x36);
  buf_xor(secret, &out->pad);
  hash_init(hash, &out->state);
  hash_update(hash, &out->state, &out->pad);
  // Save opad
  buf_reset(&out->pad, 0);
  buf_fill(&out->pad, 0x5C);
  buf_xor(secret, &out->pad);
  return kTlsSuccess;
}

tls_result_t hmac_copy(BUF *region, const HMAC *src, HMAC *dst) {
  assert(region);
  assert(src);
  assert(dst);
  memset(dst, 0, sizeof(*dst));
  dst->hash = src->hash;
  size_t m = buf_size(&src->pad);
  size_t n = buf_size(&src->state);
  assert(m != 0);
  assert(n != 0);
  if (!buf_malloc(region, n, &dst->state)) {
    return kTlsFailure;
  } else if (!buf_malloc(region, m, &dst->pad)) {
    buf_free(&dst->state);
    return kTlsFailure;
  } else if (buf_copy(&src->state, &dst->state) != n ||
             buf_copy(&src->pad, &dst->pad) != m) {
    buf_free(&dst->state);
    buf_free(&dst->pad);
    return kTlsFailure;
  }
  return kTlsSuccess;
}

void hmac_update(HMAC *hmac, const BUF *data) {
  assert(hmac);
  if (data) {
    hash_update(hmac->hash, &hmac->state, data);
  }
}

tls_result_t hmac_final(BUF *region, HMAC *hmac, BUF *out) {
  assert(region);
  assert(hmac);
  assert(out);
  BUF digest = buf_init();
  size_t output_size = hash_get_output_size(hmac->hash);
  if (!buf_malloc(region, output_size, &digest)) {
    return kTlsFailure;
  }
  hash_final(hmac->hash, &hmac->state, &digest);
  hash_init(hmac->hash, &hmac->state);
  hash_update(hmac->hash, &hmac->state, &hmac->pad);
  hash_update(hmac->hash, &hmac->state, &digest);
  buf_reset(&digest, 0);
  hash_final(hmac->hash, &hmac->state, &digest);
  // Again, we don't strictly enforce the recommendation that |out| should be at
  // least |output_size|/2, per https://tools.ietf.org/html/rfc2104#section-5,
  // since the test data doesn't follow it.
  buf_copy(&digest, out);
  buf_free(&digest);
  buf_free(&hmac->pad);
  buf_free(&hmac->state);
  return kTlsSuccess;
}
