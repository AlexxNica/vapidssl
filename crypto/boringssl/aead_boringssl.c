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

#include "base/buf.h"
#include "base/error.h"
#include "base/macros.h"
#include "crypto/aead_internal.h"
#include "crypto/crypto.h"
#include "public/error.h"
#include "third_party/boringssl/include/openssl/aead.h"

// TODO(aarongreen): Currently, there's nothing to prevent the libcrypto code
// from dynamically allocating memory, and it does.  We eventually will need to
// tweak buf_malloc and buf_free to be even more closely aligned with malloc and
// free, and submit a patch to BoringSSL to wrap |OPENSSL_malloc| etc. in a
// #ifundef to allow us to specify or own allocation routines.

// Forward declarations.

// aead_get_evp returns the |EVP_AEAD| that corresponds to |aead|.
static const EVP_AEAD *aead_boringssl_get_evp(const AEAD *aead);

// evp_init sets up |state| for either encrypting or decrypting with the
// given |key|, based on |direction|
static tls_result_t aead_boringssl_evp_init(const AEAD *aead, BUF *state,
                                            BUF *key, direction_t direction);

// evp_data authenticates |ad| and encrypts or decrypts |data| using a |nonce|,
// based on |direction|. The overall length of |data| is affected: when
// encrypting, |data| must have space available for the authentication tag to be
// appended, and when decrypting, the ready |data| will be shorter as the tag is
// removed.
static tls_result_t aead_boringssl_evp_data(const AEAD *aead, BUF *state,
                                            BUF *nonce, BUF *authenticated,
                                            BUF *encrypted,
                                            direction_t direction);

// Constants

// TODO(aarongreen): Some of these values, such as nonce length, are actually
// protocol-specific and not algorithm-specific. As a result, they really ought
// to be defined with the protocol's ciphersuites rather than here. They'll be
// moved in a later CL, so as not to let perfect be the enemy of good.
static const AEAD kAEADs[] = {
    {
        .algorithm = kAeadAes128Gcm,
        .state_size = sizeof(EVP_AEAD_CTX),
        .key_size = 128 / 8,
        .tag_size = 16,
        .init = aead_boringssl_evp_init,
        .data = aead_boringssl_evp_data,
    },
    {
        .algorithm = kAeadAes256Gcm,
        .state_size = sizeof(EVP_AEAD_CTX),
        .key_size = 256 / 8,
        .tag_size = 16,
        .init = aead_boringssl_evp_init,
        .data = aead_boringssl_evp_data,
    },
    {
        .algorithm = kAeadChaCha20Poly1305,
        .state_size = sizeof(EVP_AEAD_CTX),
        .key_size = 256 / 8,
        .tag_size = 16,
        .init = aead_boringssl_evp_init,
        .data = aead_boringssl_evp_data,
    },
};

// Library routines

const AEAD *aead_find(uint16_t algorithm) {
  return (const AEAD *)crypto_find(algorithm, kCryptoAny, kAEADs,
                                   arraysize(kAEADs), sizeof(*kAEADs));
}

const AEAD *aead_next(const AEAD *aead) {
  return (const AEAD *)crypto_next(aead, kAEADs, arraysize(kAEADs),
                                   sizeof(*kAEADs));
}

// Static functions

static const EVP_AEAD *aead_boringssl_get_evp(const AEAD *aead) {
  switch (aead->algorithm) {
    case kAeadAes128Gcm:
      return EVP_aead_aes_128_gcm();
    case kAeadAes256Gcm:
      return EVP_aead_aes_256_gcm();
    case kAeadChaCha20Poly1305:
      return EVP_aead_chacha20_poly1305();
    default:
      return NULL;
  }
}

static tls_result_t aead_boringssl_evp_init(const AEAD *aead, BUF *state,
                                            BUF *key, direction_t direction) {
  EVP_AEAD_CTX *ctx = BUF_AS(EVP_AEAD_CTX, state);
  const EVP_AEAD *evp = aead_boringssl_get_evp(aead);
  assert(evp);
  uint8_t *key_raw = NULL;
  EVP_AEAD_CTX_zero(ctx);
  buf_consume(key, aead->key_size, &key_raw);
  enum evp_aead_direction_t evp_aead_direction =
      (direction == kRecv ? evp_aead_open : evp_aead_seal);
  if (!EVP_AEAD_CTX_init_with_direction(ctx, evp, key_raw, aead->key_size,
                                        aead->tag_size, evp_aead_direction)) {
    return crypto_error(NULL);
  }
  return kTlsSuccess;
}

static tls_result_t aead_boringssl_evp_data(const AEAD *aead, BUF *state,
                                            BUF *nonce, BUF *authenticated,
                                            BUF *encrypted,
                                            direction_t direction) {
  assert(aead_boringssl_get_evp(aead) != NULL);
  EVP_AEAD_CTX *ctx = BUF_AS(EVP_AEAD_CTX, state);
  // Convert the nonce.
  uint8_t *nonce_raw = NULL;
  size_t nonce_len = buf_ready(nonce);
  if (!buf_consume(nonce, nonce_len, &nonce_raw)) {
    return kTlsFailure;
  }
  // Convert the additional data.
  uint8_t *ad_raw = NULL;
  size_t ad_len = buf_ready(authenticated);
  if (!buf_consume(authenticated, ad_len, &ad_raw)) {
    return kTlsFailure;
  }
  // Convert the data.
  size_t in_len = buf_ready(encrypted);
  size_t out_len = 0;
  size_t max_out_len = in_len;
  if (direction == kRecv) {
    assert(in_len >= aead->tag_size);
    max_out_len -= aead->tag_size;
  } else {
    assert(max_out_len < max_out_len + aead->tag_size);  // Overflow.
    max_out_len += aead->tag_size;
  }
  size_t consumed = buf_consumed(encrypted);
  uint8_t *in = NULL;
  if (!buf_consume(encrypted, in_len, &in)) {
    return kTlsFailure;
  }
  buf_reset(encrypted, consumed);
  uint8_t *out = NULL;
  buf_produce(encrypted, max_out_len, &out);
  // Open or seal.
  if ((direction == kRecv &&
       !EVP_AEAD_CTX_open(ctx, out, &out_len, max_out_len, nonce_raw, nonce_len,
                          in, in_len, ad_raw, ad_len)) ||
      (direction == kSend &&
       !EVP_AEAD_CTX_seal(ctx, out, &out_len, max_out_len, nonce_raw, nonce_len,
                          in, in_len, ad_raw, ad_len))) {
    return crypto_error(NULL);
  }
  return kTlsSuccess;
}
