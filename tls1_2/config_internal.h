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

#ifndef VAPIDSSL_TLS1_2_CONFIG_INTERNAL_H
#define VAPIDSSL_TLS1_2_CONFIG_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "tls1_2/config.h"

#include <stddef.h>

#include "base/list.h"
#include "base/types.h"
#include "public/error.h"

struct tls_config_st {
  BUF region;
  config_fragment_size_t fragment;
  uint16_t ticket_size;
  LIST ciphersuites;
  LIST eccurves;
  LIST truststore;
  size_t max_name_len;
  size_t max_key_len;
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_CONFIG_INTERNAL_H
