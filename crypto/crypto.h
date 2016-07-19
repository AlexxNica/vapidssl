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

#ifndef VAPIDSSL_CRYPTO_CRYPTO_H
#define VAPIDSSL_CRYPTO_CRYPTO_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "public/error.h"

// This file declares generic utility functions used by the algorithms within
// src/crypto.

// kCryptoAny can be used to match any parameter in |crypto_find|, below.
extern const uint16_t kCryptoAny;

// crypto_find looks through the first |nelems| elements of the array |elems|,
// each of |elem_size| bytes, looking for one with a matching |algorithm| and
// |param|. It returns the match if found, or NULL.
const void *crypto_find(uint16_t algorithm, uint16_t param, const void *elems,
                        size_t nelems, size_t elem_size);

// crypto_next returns another supported algorithm from |elems| that is distinct
// from |elem|, which may be NULL, or it returns NULL.  The elements are not
// returned in any prescribed order.
const void *crypto_next(const void *elem, const void *elems, size_t nelems,
                        size_t elem_size);

// crypto_error sets the error state for this thread from the
// implementation-specific error data of the crypto library.  |arg| is provided
// as a generic means of conveying additional error data; if not needed it can
// be left NULL. This method returns the result of |error_set|, which is always
// |kTlsFailure|.
tls_result_t crypto_error(void *arg);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_CRYPTO_CRYPTO_H
