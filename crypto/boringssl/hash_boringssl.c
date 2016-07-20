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
#include "crypto/hash_internal.h"

#include <assert.h>

#include "base/buf.h"
#include "base/macros.h"
#include "crypto/crypto.h"
#include "third_party/boringssl/include/openssl/sha.h"

// TODO(aarongreen): Currently, there's nothing to prevent the libcrypto code
// from dynamically allocating memory, and it does.  We eventually will need to
// tweak buf_malloc and buf_free to be even more closely aligned with malloc and
// free, and submit a patch to BoringSSL to wrap |OPENSSL_malloc| etc. in a
// #ifundef to allow us to specify or own allocation routines.

// Forward declarations.

// hash_boringssl_get_raw gets a non-const pointer to the raw contents of
// |data|.  Callers must not modify the memory, despite the const keyword having
// been dsicarded.
static uint8_t *hash_boringssl_get_raw(const BUF *data);

// sha256_init and sha384_init set up the |state| buffers for use in generating
// a message digest.  Calling |sha256_init| or |sha384_init| twice will
// reinitialize the hash |state|.
static void hash_boringssl_sha256_init(const HASH *self, BUF *state);
static void hash_boringssl_sha384_init(const HASH *self, BUF *state);

// sha256_update and sha384_update hash |data| into the hash |state| previously
// set up by |sha256_init| or |sha384_init|, respectively.  |sha256_update| and
// |sha384_update| may be called multiple times before calling |sha256_final| or
// |sha384_final|, respectively.
static void hash_boringssl_sha256_update(const HASH *self, BUF *state,
                                         const BUF *data);
static void hash_boringssl_sha384_update(const HASH *self, BUF *state,
                                         const BUF *data);

// sha256_final and sha384_final take the current |hash| state and produces a
// message digest that it write to |out|. No further calls to |sha256_update| or
// |sha384_update| for a given |state| are allowed after |sha256_final| or
// |sha384_final| has been called and until |sha256_init| or |sha384_init| is
// called again.
static void hash_boringssl_sha256_final(const HASH *self, BUF *state, BUF *out);
static void hash_boringssl_sha384_final(const HASH *self, BUF *state, BUF *out);

// Constants

static const HASH kHashes[] = {
    {
        .algorithm = kTlsHashSHA256,
        .state_size = sizeof(SHA256_CTX),
        .block_size = SHA256_CBLOCK,
        .out_size = SHA256_DIGEST_LENGTH,
        .init = hash_boringssl_sha256_init,
        .update = hash_boringssl_sha256_update,
        .final = hash_boringssl_sha256_final,
    },
    {
        .algorithm = kTlsHashSHA384,
        .state_size = sizeof(SHA512_CTX),
        .block_size = SHA384_CBLOCK,
        .out_size = SHA384_DIGEST_LENGTH,
        .init = hash_boringssl_sha384_init,
        .update = hash_boringssl_sha384_update,
        .final = hash_boringssl_sha384_final,
    },
};

// Library routines.

const HASH *hash_find(uint16_t algorithm) {
  return (const HASH *)crypto_find(algorithm, kCryptoAny, kHashes,
                                   arraysize(kHashes), sizeof(*kHashes));
}

const HASH *hash_next(const HASH *hash) {
  return (const HASH *)crypto_next(hash, kHashes, arraysize(kHashes),
                                   sizeof(*kHashes));
}

// Static functions

static uint8_t *hash_boringssl_get_raw(const BUF *data) {
  BUF *nonconst = (BUF *)data;
  size_t consumed = buf_consumed(data);
  size_t ready = buf_ready(data);
  uint8_t *raw = NULL;
  if (ready != 0) {
    buf_reset(nonconst, consumed);
    buf_produce(nonconst, ready, &raw);
  }
  return raw;
}

static void hash_boringssl_sha256_init(const HASH *self, BUF *state) {
  assert(self->algorithm == kTlsHashSHA256);
  SHA256_CTX *ctx = BUF_AS(SHA256_CTX, state);
  SHA256_Init(ctx);
}

static void hash_boringssl_sha256_update(const HASH *self, BUF *state,
                                         const BUF *data) {
  assert(self->algorithm == kTlsHashSHA256);
  assert(buf_size(state) >= self->state_size);
  SHA256_CTX *ctx = BUF_AS(SHA256_CTX, state);
  size_t len = buf_ready(data);
  uint8_t *raw = hash_boringssl_get_raw(data);
  SHA256_Update(ctx, raw, len);
}

static void hash_boringssl_sha256_final(const HASH *self, BUF *state,
                                        BUF *out) {
  assert(self->algorithm == kTlsHashSHA256);
  uint8_t *raw = NULL;
  buf_produce(out, self->out_size, &raw);
  SHA256_CTX *ctx = BUF_AS(SHA256_CTX, state);
  SHA256_Final(raw, ctx);
}

static void hash_boringssl_sha384_init(const HASH *self, BUF *state) {
  assert(self->algorithm == kTlsHashSHA384);
  assert(buf_size(state) >= self->state_size);
  SHA512_CTX *ctx = BUF_AS(SHA512_CTX, state);
  SHA384_Init(ctx);
}

static void hash_boringssl_sha384_update(const HASH *self, BUF *state,
                                         const BUF *data) {
  assert(self->algorithm == kTlsHashSHA384);
  SHA512_CTX *ctx = BUF_AS(SHA512_CTX, state);
  size_t len = buf_ready(data);
  uint8_t *raw = hash_boringssl_get_raw(data);
  SHA384_Update(ctx, raw, len);
}

static void hash_boringssl_sha384_final(const HASH *self, BUF *state,
                                        BUF *out) {
  assert(self->algorithm == kTlsHashSHA384);
  uint8_t *raw = NULL;
  buf_produce(out, self->out_size, &raw);
  SHA512_CTX *ctx = BUF_AS(SHA512_CTX, state);
  SHA384_Final(raw, ctx);
}
