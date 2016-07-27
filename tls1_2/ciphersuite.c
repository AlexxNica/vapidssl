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

#include "tls1_2/ciphersuite.h"

#include <assert.h>
#include <stddef.h>

#include "base/macros.h"
#include "base/types.h"
#include "crypto/aead.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto/keyex.h"
#include "crypto/sign.h"

static const struct ciphersuite_st {
  tls_ciphersuite_t ciphersuite;

  keyex_t keyex;
  size_t verify_len;

  sign_t sign;

  aead_t aead;
  bool_t xor_nonce;
  size_t fix_nonce_len;
  size_t var_nonce_len;

  hash_t hash;
} kCiphersuites[] = {
    {
        .ciphersuite = kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .keyex = kKeyxECDHE,
        .verify_len = 12,
        .sign = kSignRSA,
        .aead = kAeadAes128Gcm,
        .xor_nonce = kFalse,
        .fix_nonce_len = 4,
        .var_nonce_len = 8,
        .hash = kTlsHashSHA256,
    },
    {
        .ciphersuite = kTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .keyex = kKeyxECDHE,
        .verify_len = 12,
        .sign = kSignRSA,
        .aead = kAeadAes256Gcm,
        .xor_nonce = kFalse,
        .fix_nonce_len = 4,
        .var_nonce_len = 8,
        .hash = kTlsHashSHA384,
    },
    {
        .ciphersuite = kTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .keyex = kKeyxECDHE,
        .verify_len = 12,
        .sign = kSignRSA,
        .aead = kAeadChaCha20Poly1305,
        .xor_nonce = kTrue,
        .fix_nonce_len = 12,
        .var_nonce_len = 8,
        .hash = kTlsHashSHA256,
    },
};

// Forward declarations

static const struct ciphersuite_st *ciphersuite_find(
    tls_ciphersuite_t ciphersuite);

// Library routines

tls_ciphersuite_t ciphersuite_next(const TLS_CONFIG *config,
                                   tls_ciphersuite_t ciphersuite) {
  const struct ciphersuite_st *suite = NULL;
  if (ciphersuite != kCryptoAny) {
    suite = ciphersuite_find(ciphersuite);
  }
  suite = (const struct ciphersuite_st *)crypto_next(
      suite, kCiphersuites, arraysize(kCiphersuites), sizeof(*kCiphersuites));
  if (!suite) {
    return kCryptoAny;
  }
  return suite->ciphersuite;
}

bool_t ciphersuite_is_supported(tls_ciphersuite_t ciphersuite) {
  const struct ciphersuite_st *suite = ciphersuite_find(ciphersuite);
  return (suite && aead_find(suite->aead) && hash_find(suite->hash) &&
                  keyex_find(suite->keyex, kCryptoAny) &&
                  sign_find(suite->sign, suite->hash)
              ? kTrue
              : kFalse);
}

const KEYEX *ciphersuite_get_keyex(tls_ciphersuite_t ciphersuite,
                                   tls_eccurve_t eccurve) {
  const struct ciphersuite_st *suite = ciphersuite_find(ciphersuite);
  assert(suite);
  return keyex_find(suite->keyex, eccurve);
}

size_t ciphersuite_get_verify_length(tls_ciphersuite_t ciphersuite) {
  const struct ciphersuite_st *suite = ciphersuite_find(ciphersuite);
  assert(suite);
  return suite->verify_len;
}

uint16_t ciphersuite_get_signature_algorithm(tls_ciphersuite_t ciphersuite) {
  const struct ciphersuite_st *suite = ciphersuite_find(ciphersuite);
  assert(suite);
  return (suite->hash << 8) | suite->sign;
}

const AEAD *ciphersuite_get_aead(tls_ciphersuite_t ciphersuite) {
  const struct ciphersuite_st *suite = ciphersuite_find(ciphersuite);
  assert(suite);
  return aead_find(suite->aead);
}

bool_t ciphersuite_xor_nonce(tls_ciphersuite_t ciphersuite) {
  const struct ciphersuite_st *suite = ciphersuite_find(ciphersuite);
  assert(suite);
  return suite->xor_nonce;
}

size_t ciphersuite_fix_nonce_length(tls_ciphersuite_t ciphersuite) {
  const struct ciphersuite_st *suite = ciphersuite_find(ciphersuite);
  assert(suite);
  return suite->fix_nonce_len;
}

size_t ciphersuite_var_nonce_length(tls_ciphersuite_t ciphersuite) {
  const struct ciphersuite_st *suite = ciphersuite_find(ciphersuite);
  assert(suite);
  return suite->var_nonce_len;
}

const HASH *ciphersuite_get_hash(tls_ciphersuite_t ciphersuite) {
  const struct ciphersuite_st *suite = ciphersuite_find(ciphersuite);
  assert(suite);
  return hash_find(suite->hash);
}

// Static functions

static const struct ciphersuite_st *ciphersuite_find(
    tls_ciphersuite_t ciphersuite) {
  return (const struct ciphersuite_st *)crypto_find(
      ciphersuite, 0, kCiphersuites, arraysize(kCiphersuites),
      sizeof(*kCiphersuites));
}
