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

#ifndef VAPIDSSL_TLS1_2_TLS_INTERNAL_H
#define VAPIDSSL_TLS1_2_TLS_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "base/buf.h"
#include "public/config.h"
#include "tls1_2/handshake.h"
#include "tls1_2/message.h"
#include "tls1_2/ticket.h"

enum tls_state_t {
  kTlsClosed = 0,
  kTlsConnecting,
  kTlsEstablished,
  kTlsShuttingDown,
};

struct tls_st {
  BUF region;
  const TLS_CONFIG *config;
  enum tls_state_t state;
  BUF connect;
  BUF sni;
  BUF master;
  TICKET ticket;
  MESSAGE send;
  BUF send_retry;
  MESSAGE recv;
  BUF recv_retry;
  tls_ciphersuite_t ciphersuite;
  BUF aead_states;
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_TLS_INTERNAL_H
