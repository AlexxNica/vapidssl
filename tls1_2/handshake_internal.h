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

#ifndef VAPIDSSL_TLS1_2_HANDSHAKE_INTERNAL_H
#define VAPIDSSL_TLS1_2_HANDSHAKE_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "crypto/keyex.h"
#include "public/config.h"
#include "public/error.h"
#include "public/tls.h"
#include "tls1_2/extension.h"
#include "x509v3/certificate.h"

struct handshake_st {
  TLS *tls;
  BUF *region;
  tls_result_t (*next)(struct handshake_st *handshake);
  size_t message_len;
  BUF message_buf1;
  BUF message_buf2;
  uint8_t resumed : 1;
  uint8_t certreq : 1;
  EXTENSION extension;
  BUF client_random;
  BUF server_random;
  uint16_t curve;
  const SIGN *sign;
  BUF leaf_key;
  BUF offer;
  BUF secret;
  BUF client_write_key;
  BUF server_write_key;
  BUF client_write_iv;
  BUF server_write_iv;
  //  BUF digest;
  LIST hashes;
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_HANDSHAKE_INTERNAL_H
