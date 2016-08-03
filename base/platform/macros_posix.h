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

#ifndef VAPIDSSL_BASE_PLATFORM_MACROS_POSIX_H_
#define VAPIDSSL_BASE_PLATFORM_MACROS_POSIX_H_

#include <errno.h>

#define MAX_EINTR_RETRIES 100

#define HANDLE_EINTR(expr)                                          \
  ({                                                                \
    int _eintr_result;                                              \
    for (size_t _i##__LINE__ = 0; _i##__LINE__ < MAX_EINTR_RETRIES; \
         ++_i##__LINE__) {                                          \
      _eintr_result = (expr);                                       \
      if (_eintr_result != -1 || errno != EINTR) {                  \
        break;                                                      \
      }                                                             \
    }                                                               \
    _eintr_result;                                                  \
  })

#endif // VAPIDSSL_BASE_PLATFORM_MACROS_POSIX_H_
