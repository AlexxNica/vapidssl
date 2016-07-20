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
#include "crypto/sign_internal.h"

#include <assert.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/macros.h"
#include "crypto/crypto.h"
#include "public/config.h"
#include "public/error.h"
#include "third_party/boringssl/include/openssl/obj_mac.h"
#include "third_party/boringssl/include/openssl/rsa.h"

// TODO(aarongreen): Currently, there's nothing to prevent the libcrypto code
// from dynamically allocating memory, and it does.  We eventually will need to
// tweak buf_malloc and buf_free to be even more closely aligned with malloc and
// free, and submit a patch to BoringSSL to wrap |OPENSSL_malloc| etc. in a
// #ifundef to allow us to specify or own allocation routines.

// Forward declaration.

// rsa_verify uses the hash from |self| to produce a digest of the |signed_data|
// and checks it against the value obtain by decrypting the |signature| using
// the |public_key|.
static tls_result_t sign_boringssl_rsa_verify(const SIGN *self,
                                              const BUF *digest,
                                              const BUF *signature,
                                              const BUF *public_key);

// Constants.

static const SIGN kSigns[] = {
    {
        .algorithm = kSignRSA,
        .hash_algorithm = kTlsHashSHA256,
        .verify = sign_boringssl_rsa_verify,
    },
    {
        .algorithm = kSignRSA,
        .hash_algorithm = kTlsHashSHA384,
        .verify = sign_boringssl_rsa_verify,
    },
};

// Library routines.

const SIGN *sign_find(uint16_t algorithm, uint16_t hash_algorithm) {
  return (const SIGN *)crypto_find(algorithm, hash_algorithm, kSigns,
                                   arraysize(kSigns), sizeof(*kSigns));
}

// Static functions.

static tls_result_t sign_boringssl_rsa_verify(const SIGN *self,
                                              const BUF *digest,
                                              const BUF *signature,
                                              const BUF *public_key) {
  assert(self);
  assert(self->algorithm == kSignRSA);
  int nid = -1;
  switch (self->hash_algorithm) {
    case kTlsHashSHA256:
      nid = NID_sha256;
      break;
    case kTlsHashSHA384:
      nid = NID_sha384;
      break;
    default:
      return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedAlgorithm);
  }
  // Discard const-ness, but don't change anything.
  // Digest
  size_t digest_len = buf_ready(digest);
  uint8_t *digest_raw = NULL;
  BUF *digest2 = (BUF *)digest;
  buf_reset(digest2, buf_consumed(digest));
  buf_produce(digest2, digest_len, &digest_raw);
  // Signature
  size_t signature_len = buf_ready(signature);
  uint8_t *signature_raw = NULL;
  BUF *signature2 = (BUF *)signature;
  buf_reset(signature2, buf_consumed(signature));
  buf_produce(signature2, signature_len, &signature_raw);
  // Public Key
  size_t public_key_len = buf_ready(public_key);
  uint8_t *public_key_raw = NULL;
  BUF *public_key2 = (BUF *)public_key;
  buf_reset(public_key2, buf_consumed(public_key));
  buf_produce(public_key2, public_key_len, &public_key_raw);
  // Do the actual verification
  RSA *rsa = RSA_public_key_from_bytes(public_key_raw, public_key_len);
  if (!rsa ||
      !RSA_verify(nid, digest_raw, digest_len, signature_raw, signature_len,
                  rsa)) {
    if (rsa) {
      RSA_free(rsa);
    }
    return crypto_error(NULL);
  }
  return kTlsSuccess;
}
