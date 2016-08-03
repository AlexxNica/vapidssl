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

#ifndef VAPIDSSL_TLS1_2_MESSAGE_H
#define VAPIDSSL_TLS1_2_MESSAGE_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "tls1_2/message_internal.h"

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/types.h"
#include "crypto/aead.h"
#include "public/config.h"
#include "public/error.h"
#include "tls1_2/record.h"

// This file provides an abstraction for the TLS 1.2 message layer, as defined
// in https://tools.ietf.org/html/rfc5246#section-6

// Opaque TLS message layer structure, defined in base/message_internal.h.
typedef struct message_st MESSAGE;

// message_handshake_t lists the different handshake message types in TLS 1.2.
typedef enum message_handshake_t {
  kHelloRequest = 0,
  kClientHello = 1,
  kServerHello = 2,
  kNewSessionTicket = 4,
  kCertificate = 11,
  kServerKeyExchange = 12,
  kCertificateRequest = 13,
  kServerHelloDone = 14,
  kCertificateVerify = 15,
  kClientKeyExchange = 16,
  kFinished = 20,
} message_handshake_t;

// message_alert_level_t indicates the severity of an alert.
typedef enum message_alert_level_t {
  kWarning = 1,
  kFatal = 2,
} message_alert_level_t;

// kSegments, kRecvNesting, and kSendNesting are stream parameters for a TLS 1.2
// message.  They are externed to allow testing.
extern const uint8_t kSegments;
extern const uint8_t kRecvNesting;
extern const uint8_t kSendNesting;

// message_size returns the number of bytes needed for a call to |message_init|
// to be successful given a particular |config| and a |direction| for the
// underlying stream.
size_t message_size(const TLS_CONFIG *config, direction_t direction);

// message_init takes a message in |out| and uses the current |config| and
// memory from |region| to configure its streams to transparently handle the TLS
// 1.2 message layer for a connection identified by |cid| in a given
// |direction|.
tls_result_t message_init(const TLS_CONFIG *ctx, BUF *region,
                          tls_connection_id_t cid, direction_t direction,
                          MESSAGE *out);

// message_get_stream returns the underlying stream from a |message| object.
STREAM *message_get_stream(MESSAGE *message);

// message_peek_type returns the ContentType of the record containing the next
// data to be received on |message|.  If the current record has more data, it
// will use the current record.  Otherwise, it attempts to read the record layer
// header or the next record without consuming the record payload itself.
tls_result_t message_peek_type(MESSAGE *message, record_content_t *out);

// message_recv_ccs attempts to read a record with ContentType of
// kChangeCipherSpec and enable the given |ciphersuite| on the |message|'s
// record layer.
tls_result_t message_recv_ccs(MESSAGE *message, BUF *region,
                              tls_ciphersuite_t ciphersuite, BUF *key, BUF *iv);

// message_recv_alert causes all received data to be silently discarded until a
// TLS 1.2 alert is encountered.  It returns true if and only if it received an
// alert matching |alert|.
tls_result_t message_recv_alert(MESSAGE *message, tls_alert_t alert);

// message_recv_handshake reads the header of a handshake message from |message|
// and returns its handshake type in |out|.  It will read a new record if the
// current record type is not |kHandshake|.
tls_result_t message_recv_handshake(MESSAGE *message, message_handshake_t *out);

// message_recv_appdata reads application data from |message| and into |data|.
tls_result_t message_recv_appdata(MESSAGE *message, BUF *data);

// message_send_ccs sends a record with ContentType of kChangeCipherSpec and
// enables the given |ciphersuite| on the |message|'s record layer.
tls_result_t message_send_ccs(MESSAGE *message, BUF *region,
                              tls_ciphersuite_t ciphersuite, BUF *key,
                              BUF *nonce);

// message_send_alert writes an |alert| to |message|.  The alert may be either a
// |fatal| error or warning.
tls_result_t message_send_alert(MESSAGE *message, message_alert_level_t level,
                                tls_alert_t alert);

// message_send_handshake sends the header of a handshake message of the given
// |type| and |length| to |message|.
tls_result_t message_send_handshake(MESSAGE *message, message_handshake_t type,
                                    uint24_t length);

// message_send_appdata sends application data from |data| to |message|.
tls_result_t message_send_appdata(MESSAGE *message, BUF *data);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_MESSAGE_H
