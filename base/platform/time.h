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

#ifndef VAPIDSSL_BASE_PLATFORM_TIME_H
#define VAPIDSSL_BASE_PLATFORM_TIME_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

// time_now returns the current number of seconds since the start of the epoch,
// normally midnight (UTC), January 1, 1970.  It uses |int64_t| instead of
// |time_t| to be unambiguous; platforms must provide up to 63 bits of time.
int64_t time_now(void);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_PLATFORM_TIME_H
