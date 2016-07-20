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
#include "crypto/keyex_internal.h"

#include <assert.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/macros.h"
#include "crypto/crypto.h"
#include "public/config.h"
#include "public/error.h"
#include "third_party/boringssl/include/openssl/curve25519.h"

// TODO(aarongreen): Currently, there's nothing to prevent the libcrypto code
// from dynamically allocating and freeing memory within a single API call, and
// it does.  We eventually will need to hook malloc/realloc/free so that
// BoringSSL uses the memory that the library consumer has lent to use. We may
// achieve this by tweaking buf_malloc and buf_free to be even more closely
// aligned with malloc and free and using the |OPENSSL_malloc|, etc.
// preprocessor definitions to use our routines.  Alternatively, we may submit a
// patch to BoringSSL to allow consumers to set the allocator.

// Forward declaration.

// X25519_accept uses Curve 25519 to take an |offer| from a server, which is
// just an element of the group of some order, and uses it to generate an
// |acceptance|, which is another element of some other order, and to derive a
// |shared| secret, which is the element of the product of those two orders.
static tls_result_t keyex_boringssl_X25519_accept(const KEYEX *self,
                                                  uint8_t *secret,
                                                  uint8_t *offer,
                                                  uint8_t *accept,
                                                  uint8_t *shared);

// Constants

static const KEYEX kKeyExchanges[] = {
    {
        .algorithm = kKeyxECDHE,
        .eccurve = kTlsCurve25519,
        .secret_size = 32,
        .offer_size = 32,
        .accept_size = 32,
        .output_size = 32,
        .accept = keyex_boringssl_X25519_accept,
    },
};

// Library routines.

const KEYEX *keyex_find(uint16_t algorithm, uint16_t eccurve_parameter) {
  return (const KEYEX *)crypto_find(algorithm, eccurve_parameter, kKeyExchanges,
                                    arraysize(kKeyExchanges),
                                    sizeof(*kKeyExchanges));
}

// Static functions

static tls_result_t keyex_boringssl_X25519_accept(const KEYEX *self,
                                                  uint8_t *secret,
                                                  uint8_t *offer,
                                                  uint8_t *accept,
                                                  uint8_t *shared) {
  assert(self->algorithm == kKeyxECDHE);
  assert(self->eccurve == kTlsCurve25519);
  // Generate the secret, use it to accept the offer, and use both the secret
  // and offer to derive the shared key.
  X25519_keypair(accept, secret);
  if (!X25519(shared, secret, offer)) {
    return crypto_error(NULL);
  }
  // |buf_free| implicitly zeros the |secret|.
  return kTlsSuccess;
}
