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

#include "tls1_2/prf.h"

#include <assert.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "common/hmac.h"
#include "crypto/hash.h"

// Forward Declarations

// prf_a and prf_hmac_hash are modeled as closely as possible on A() and
// HMAC_hash() as described in https://tools.ietf.org/html/rfc5246#section-5.
static tls_result_t prf_a(BUF *region, HMAC *hmac0, BUF *seed0, BUF *seed1,
                          BUF *seed2, BUF *a);
static tls_result_t prf_hmac_hash(BUF *region, HMAC *hmac0, BUF *a, BUF *seed0,
                                  BUF *seed1, BUF *seed2, BUF *out);

// Library routines

size_t prf_size(const HASH *hash) {
  assert(hash);
  // We have at most two digests, |a| and |tmp|, and two HMACs |hmac0| and
  // |hmacN|, concurrently.
  return (hash_get_output_size(hash) + hmac_size(hash)) * 2;
}

tls_result_t prf(BUF *region, const HASH *hash, BUF *secret, const char *label,
                 BUF *seed1, BUF *seed2, BUF *out) {
  assert(out);
  assert(hash);
  assert(secret);
  assert(label);
  // Prep the seeds.
  BUF seed0 = buf_init();
  if (strlen(label) != 0) {
    buf_wrap((uint8_t *)label, strlen(label), strlen(label), &seed0);
  }
  assert(seed1);
  // Initialize HMAC with the secret.  All other HMACs will copy this initial
  // state to get the secret.
  size_t digest_len = hash_get_output_size(hash);
  BUF a = buf_init();
  BUF tmp = buf_init();
  HMAC hmac0;
  if (!buf_malloc(region, digest_len, &a) ||
      !buf_malloc(region, digest_len, &tmp) ||
      !hmac_init(region, hash, secret, &hmac0)) {
    return kTlsFailure;
  }
  // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
  //                        HMAC_hash(secret, A(2) + seed) +
  //                        HMAC_hash(secret, A(3) + seed) + ...
  while (buf_available(out)) {
    if (!prf_a(region, &hmac0, &seed0, seed1, seed2, &a) ||
        !prf_hmac_hash(region, &hmac0, &a, &seed0, seed1, seed2, &tmp)) {
      return kTlsFailure;
    }
    buf_copy(&tmp, out);
    buf_reset(&tmp, 0);
  }
  // Clean up memory.
  if (!hmac_final(region, &hmac0, &tmp)) {
    return kTlsFailure;
  }
  buf_free(&tmp);
  buf_free(&a);
  return kTlsSuccess;
}

// Static functions

static tls_result_t prf_a(BUF *region, HMAC *hmac0, BUF *seed0, BUF *seed1,
                          BUF *seed2, BUF *a) {
  // A(0) = seed
  // A(i) = HMAC_hash(secret, A(i - 1))
  if (buf_ready(a) == 0) {
    if (!prf_hmac_hash(region, hmac0, NULL, seed0, seed1, seed2, a)) {
      return kTlsFailure;
    }
  } else {
    if (!prf_hmac_hash(region, hmac0, a, NULL, NULL, NULL, a)) {
      return kTlsFailure;
    }
  }
  return kTlsSuccess;
}

static tls_result_t prf_hmac_hash(BUF *region, HMAC *hmac0, BUF *a, BUF *seed0,
                                  BUF *seed1, BUF *seed2, BUF *out) {
  HMAC hmacN;
  if (!hmac_copy(region, hmac0, &hmacN)) {
    return kTlsFailure;
  }
  hmac_update(&hmacN, a);
  hmac_update(&hmacN, seed0);
  hmac_update(&hmacN, seed1);
  hmac_update(&hmacN, seed2);
  buf_reset(out, 0);
  return hmac_final(region, &hmacN, out);
}
