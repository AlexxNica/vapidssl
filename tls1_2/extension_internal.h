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

#ifndef VAPIDSSL_TLS1_2_EXTENSION_INTERNAL_H
#define VAPIDSSL_TLS1_2_EXTENSION_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>

#include "common/stream.h"
#include "public/error.h"
#include "public/tls.h"

struct extension_st {
  tls_result_t (*next)(struct extension_st *extension);
  STREAM *stream;
  uint8_t index;
  uint8_t sent;
  uint8_t received;

  TLS *tls;
  BUF *region;
  BUF *data;
  BUF internal;
};

typedef tls_result_t (*extension_f)(struct extension_st *extension);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_EXTENSION_INTERNAL_H
