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

#ifndef VAPIDSSL_BASE_PLATFORM_RANDOM_H
#define VAPIDSSL_BASE_PLATFORM_RANDOM_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

#include "base/buf.h"

// This is the platform and/or OS specific interface for RNGs.

// random_buf fills a buffer's available space with random data.  With the
// exception of implementation specifically designed for testing, bytes
// generated must be uniformly distributed and unpredictable without additional
// seeding, even to attacker with fine grained information about the library's
// external state, such as the exact timing of calls to |random_buf|.
void random_buf(BUF *out);

#if defined(__cplusplus)
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_PLATFORM_RANDOM_H
