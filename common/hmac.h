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

#ifndef VAPIDSSL_COMMON_HMAC_H
#define VAPIDSSL_COMMON_HMAC_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "common/hmac_internal.h"

#include "base/buf.h"
#include "crypto/hash.h"
#include "public/error.h"

// Opaque hash-based message authentication code structure, as defined in
// hmac_internal.h.
typedef struct hmac_st HMAC;

// hmac_size returns the total memory needed to generate an HMAC using the given
// |hash|.
size_t hmac_size(const HASH *hash);

// hmac_init prepares |out| using the given |hash| and |secret|.  It allocates
// no more than |hmac_size| bytes from |region|.
tls_result_t hmac_init(BUF *region, const HASH *hash, BUF *secret, HMAC *out);

// hmac_copy prepares |dst| using the existing HMAC |src|.  It allocates
// no more than |hmac_size| bytes from |region|.
tls_result_t hmac_copy(BUF *region, const HMAC *src, HMAC *dst);

// hmac_update appends |data| to the |hmac|.  The |data| is not altered in any
// way.
void hmac_update(HMAC *hmac, const BUF *data);

// hmac_final produces an HMAC tag into |out| using |hmac|, before freeing the
// memory allocated from |region| by |hmac_init| or |hmac_copy|.
tls_result_t hmac_final(BUF *region, HMAC *hmac, BUF *out);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_COMMON_HMAC_H
