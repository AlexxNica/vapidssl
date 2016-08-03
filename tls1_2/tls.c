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

#include "tls1_2/tls.h"
#include "tls1_2/tls_internal.h"

#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "public/config.h"
#include "public/error.h"
#include "tls1_2/config.h"
#include "tls1_2/ticket.h"

// TODO(aarongreen): The API level needs to be made thread safe, with separate
// locks for both reading and writing.

// TODO(aarongreen): Error handling is incomplete; TLS alerts should be sent and
// tickets and master secrets cleared on error.

// TODO(aarongreen): Clean shutdown needs to be implemented.

// TODO(aarongreen): We could decouple this file from extension.c and
// handshake.c by splitting it between an api.c and a connection.c.

static const size_t kMasterSize = 48;

// Public API

size_t TLS_size(const TLS_CONFIG *config) {
  if (!config) {
    return 0;
  }
  size_t size = sizeof(TLS);
  size += config_get_max_name_length(config);
  size += kMasterSize;
  size += config_get_ticket_length(config);
  size += message_size(config, kSend);
  size += message_size(config, kRecv);
  size += config_get_max_aead_size(config) * 2;
  size += config_get_max_nonce_len(config) * 2;
  return size;
}

size_t TLS_connect_size(const TLS_CONFIG *config) {
  return sizeof(HANDSHAKE) + handshake_size(config);
}

tls_result_t TLS_init(const TLS_CONFIG *config, void *mem, size_t len,
                      tls_connection_id_t cid, const char *server, TLS **out) {
  if (!config || !mem || !server || len < TLS_size(config)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidArgument);
  }
  size_t sni_len = strlen(server);
  if (config_get_max_name_length(config) < sni_len) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidArgument);
  }
  memset(mem, 0, len);
  TLS *tls = (TLS *)mem;
  buf_wrap(mem, len, sizeof(TLS), &tls->region);
  tls->config = config;
  size_t aead_size = config_get_max_aead_size(config) * 2;
  aead_size += config_get_max_nonce_len(config) * 2;
  if (!buf_malloc(&tls->region, sni_len, &tls->sni) ||
      !buf_malloc(&tls->region, kMasterSize, &tls->master) ||
      !message_init(config, &tls->region, cid, kSend, &tls->send) ||
      !message_init(config, &tls->region, cid, kRecv, &tls->recv) ||
      !buf_malloc(&tls->region, aead_size, &tls->aead_states)) {
    return kTlsFailure;
  }
  uint8_t *sni_raw = NULL;
  buf_produce(&tls->sni, sni_len, &sni_raw);
  memcpy(sni_raw, server, sni_len);
  ticket_erase(&tls->ticket);
  *out = tls;
  return kTlsSuccess;
}

tls_result_t TLS_connect(TLS *tls, void *mem, size_t len) {
  if (!tls || !mem || len < handshake_size(tls->config)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidArgument);
  }
  if (tls->state == kTlsClosed) {
    memset(mem, 0, len);
  }
  if (!buf_wrap(mem, len, sizeof(HANDSHAKE), &tls->connect)) {
    return kTlsFailure;
  }
  HANDSHAKE *handshake = (HANDSHAKE *)mem;
  if (tls->state == kTlsClosed) {
    if (!handshake_init(&tls->connect, tls, handshake)) {
      return kTlsFailure;
    }
    tls->state = kTlsConnecting;
  }
  if (tls->state != kTlsConnecting) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
  if (!handshake_connect(handshake)) {
    return kTlsFailure;
  }
  buf_unwrap(&tls->connect, kDoWipe);
  tls->state = kTlsEstablished;
  return kTlsSuccess;
}

tls_result_t TLS_read(TLS *tls, void *out, size_t *out_len, size_t num) {
  if (!tls || !out || num == 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidArgument);
  }
  if (tls->state != kTlsEstablished) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
  if (!buf_wrap(out, num, 0, &tls->recv_retry)) {
    return kTlsFailure;
  }
  message_recv_appdata(&tls->recv, &tls->recv_retry);
  if (out_len) {
    *out_len = buf_size(&tls->recv_retry) - buf_available(&tls->recv_retry);
  }
  buf_unwrap(&tls->recv_retry, kDoNotWipe);
  return kTlsSuccess;
}

tls_result_t TLS_write(TLS *tls, const void *buf, size_t num) {
  if (!tls || !buf || num == 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidArgument);
  }
  if (tls->state != kTlsEstablished) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
  // Discard const-ness; we won't touch the memory.
  if (!buf_wrap((void *)buf, num, num, &tls->send_retry)) {
    return kTlsFailure;
  }
  if (!message_send_appdata(&tls->send, &tls->send_retry)) {
    return kTlsFailure;
  }
  buf_unwrap(&tls->send_retry, kDoWipe);
  return kTlsSuccess;
}

tls_result_t TLS_shutdown(TLS *tls) {
  return ERROR_SET(kTlsErrVapid, kTlsErrNotImplemented);
}

void *TLS_cleanup(TLS *tls) {
  void *raw = NULL;
  if (tls && buf_size(&tls->region) != 0) {
    // This call flattens *everything* within |tls|!
    raw = buf_unwrap(&tls->region, kDoWipe);
  }
  return raw;
}

// Library routines.

BUF *tls_get_region(TLS *tls) {
  assert(tls);
  return &tls->region;
}

const TLS_CONFIG *tls_get_config(TLS *tls) {
  assert(tls);
  return tls->config;
}

BUF *tls_get_sni(TLS *tls) {
  assert(tls);
  assert(buf_size(&tls->sni) != 0);
  buf_reset(&tls->sni, 0);
  buf_produce(&tls->sni, buf_size(&tls->sni), NULL);
  return &tls->sni;
}

BUF *tls_get_master_secret(TLS *tls) {
  assert(tls);
  return &tls->master;
}

TICKET *tls_get_ticket(TLS *tls) {
  assert(tls);
  return &tls->ticket;
}

MESSAGE *tls_get_message(TLS *tls, direction_t direction) {
  assert(tls);
  if (direction == kSend) {
    return &tls->send;
  } else {
    return &tls->recv;
  }
}

STREAM *tls_get_stream(TLS *tls, direction_t direction) {
  MESSAGE *message = tls_get_message(tls, direction);
  return message_get_stream(message);
}

tls_ciphersuite_t tls_get_ciphersuite(TLS *tls) {
  assert(tls);
  return tls->ciphersuite;
}

void tls_set_ciphersuite(TLS *tls, tls_ciphersuite_t ciphersuite) {
  assert(tls);
  tls->ciphersuite = ciphersuite;
}

BUF *tls_get_aead_states(TLS *tls) {
  assert(tls);
  return &tls->aead_states;
}
