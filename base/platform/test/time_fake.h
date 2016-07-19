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

#ifndef VAPIDSSL_BASE_PLATFORM_TEST_TIME_FAKE_H
#define VAPIDSSL_BASE_PLATFORM_TEST_TIME_FAKE_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

// time_fake presents an implementation of base/platform/time.h that is suitable
// for testing.  In particular, it is platform independent and allows unit tests
// to modify what time is returned.

// time_fake_set resets the internal clock so that subsequent calls to
// |time_now| will return |seconds| plus the time elapsed between the calls to
// |time_fake_set| and |time_now|.
void time_fake_set(uint64_t seconds);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_PLATFORM_TEST_TIME_FAKE_H
