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

#ifndef VAPIDSSL_TLS1_2_PRF_H
#define VAPIDSSL_TLS1_2_PRF_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "base/buf.h"
#include "crypto/hash.h"
#include "public/error.h"

// This file contains |prf|, a function used to generate a cryptographically
// secure random byte stream.

// prf_size returns the number of bytes needed for a call to |prf| to be
// successful for a given |hash|.
size_t prf_size(const HASH *hash);

// prf generates cryptographically secure pseudorandom data in |out| using a
// secret |key| and up to 3 seeds: |label|, |seed1|, and optionally |seed2|. The
// key and seeds are combined using |hash| and memory from |region| according to
// https://tools.ietf.org/html/rfc5246#section-5.
tls_result_t prf(BUF *region, const HASH *hash, BUF *key, const char *label,
                 BUF *seed1, BUF *seed2, BUF *out);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_PRF_H
