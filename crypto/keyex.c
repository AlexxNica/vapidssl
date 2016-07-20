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

#include "crypto/keyex.h"

#include <assert.h>
#include <stddef.h>

#include "base/buf.h"
#include "base/error.h"
#include "crypto/keyex_internal.h"
#include "public/error.h"

// Forward declarations.

// keyex_is_valid checks that |keyex| is consistent with itkeyex.
static void keyex_is_valid(const KEYEX *keyex);

// Library routines

size_t keyex_get_accept_size(const KEYEX *keyex) {
  keyex_is_valid(keyex);
  return keyex->accept_size;
}

size_t keyex_get_output_size(const KEYEX *keyex) {
  keyex_is_valid(keyex);
  return keyex->output_size;
}

tls_result_t keyex_accept(const KEYEX *keyex, BUF *region, BUF *offer,
                          BUF *out_acceptance, BUF *out_shared) {
  keyex_is_valid(keyex);
  assert(offer);
  assert(out_acceptance);
  assert(out_shared);
  // Check sizes.
  assert(buf_size(out_acceptance) == keyex->accept_size);
  assert(buf_size(out_shared) == keyex->output_size);
  if (buf_ready(offer) < keyex->offer_size) {
    return ERROR_SET(kTlsErrVapid, kTlsErrIllegalParameter);
  }
  // Prepare the offer.
  uint8_t *offer_raw = NULL;
  if (!buf_consume(offer, keyex->offer_size, &offer_raw)) {
    return kTlsFailure;
  }
  // Prepare the acceptance.
  uint8_t *accept_raw = NULL;
  buf_reset(out_acceptance, 0);
  buf_produce(out_acceptance, keyex->accept_size, &accept_raw);
  // Prepare the shared key.
  uint8_t *shared_raw = NULL;
  buf_reset(out_shared, 0);
  buf_produce(out_shared, keyex->output_size, &shared_raw);
  // Prepare the secret.
  BUF secret = buf_init();
  if (!buf_malloc(region, keyex->secret_size, &secret)) {
    return kTlsFailure;
  }
  uint8_t *secret_raw = NULL;
  buf_produce(&secret, keyex->secret_size, &secret_raw);
  tls_result_t result =
      keyex->accept(keyex, secret_raw, offer_raw, accept_raw, shared_raw);
  buf_free(&secret);
  return result;
}

// Static functions.

static void keyex_is_valid(const KEYEX *keyex) {
  assert(keyex);
  assert(keyex_find(keyex->algorithm, keyex->eccurve) == keyex);
}
