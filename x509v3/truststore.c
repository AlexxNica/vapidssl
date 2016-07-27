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

#include "x509v3/truststore.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/list.h"
#include "base/types.h"
#include "crypto/sign.h"
#include "public/error.h"

struct trusted_st {
  BUF dn;
  BUF key;
};

size_t truststore_size(size_t max) {
  return LIST_SIZE(struct trusted_st, max);
}

tls_result_t truststore_init(BUF *region, size_t max, LIST *out) {
  return LIST_NEW(struct trusted_st, region, max, out);
}

tls_result_t truststore_add(LIST *truststore, const uint8_t *dn, size_t dn_len,
                            const uint8_t *key, size_t key_len) {
  assert(truststore);
  struct trusted_st *signer = LIST_ADD(struct trusted_st, truststore);
  return signer && buf_wrap((void *)dn, dn_len, dn_len, &signer->dn) &&
         buf_wrap((void *)key, key_len, key_len, &signer->key);
}

bool_t truststore_check(const LIST *truststore, const SIGN *sign, BUF *dn,
                        BUF *digest, BUF *signature) {
  assert(truststore);
  // DNs are read into the back of fixed size buffers; move them forward for
  // testing equality.
  buf_recycle(dn);
  // Discard constness, but don't change contents of list.
  LIST *signers = (LIST *)truststore;
  for (struct trusted_st *signer = LIST_BEGIN(struct trusted_st, signers);
       signer; signer = LIST_NEXT(struct trusted_st, signers)) {
    if (buf_equal(&signer->dn, dn) &&
        sign_verify(sign, digest, signature, &signer->key)) {
      return kTrue;
    }
  }
  return kFalse;
}
