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

#include "crypto/crypto.h"

#include <assert.h>
#include <stddef.h>

// crypto_algorithm_st defines just the first two fields common to all the other
// crypto data structues: AEAD, HASH, KEYEX, and SIGN.  The former two can be
// identified by |id| alone, while the latter two have another |param| to
// uniquely describe the algorithm. This struct is used to do the generic
// seplatform below.
struct crypto_algorithm_st {
  uint16_t id;
  uint16_t param;
};

const uint16_t kCryptoAny = 0xFFFF;

// Library routines

const void *crypto_find(uint16_t id, uint16_t param, const void *elems,
                        size_t nelems, size_t elem_size) {
  assert(elems);
  assert(elem_size >= sizeof(struct crypto_algorithm_st));
  const uint8_t *ptr = (const uint8_t *)elems;
  const struct crypto_algorithm_st *algorithm;
  for (size_t i = 0; i < nelems; ++i) {
    algorithm = (const struct crypto_algorithm_st *)ptr;
    if (algorithm->id == id &&
        (param == kCryptoAny || param == algorithm->param)) {
      return (void *)ptr;
    }
    ptr += elem_size;
  }
  return NULL;
}

const void *crypto_next(const void *elem, const void *elems, size_t nelems,
                        size_t elem_size) {
  assert(elems);
  assert(nelems != 0);
  assert(elem_size != 0);
  if (!elem) {
    return elems + (nelems - 1) * elem_size;
  }
  assert(elem >= elems);
  if (elem == elems) {
    return NULL;
  }
  assert((size_t)(elems - elem) >= elem_size);
  return elem - elem_size;
}
