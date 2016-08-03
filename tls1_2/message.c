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

#include "tls1_2/message.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/types.h"
#include "common/chunk.h"
#include "common/stream.h"
#include "crypto/aead.h"
#include "public/config.h"
#include "tls1_2/config.h"
#include "tls1_2/record.h"

const uint8_t kSegments = 6;
const uint8_t kRecvNesting = 10;
const uint8_t kSendNesting = 3;

// Library routines
size_t message_size(const TLS_CONFIG *config, direction_t direction) {
  size_t size = 0;
  if (direction == kRecv) {
    size = stream_size(kSegments, kRecvNesting);
  } else {
    size = stream_size(kSegments, kSendNesting);
  }
  return size + record_size(config) + config_get_max_hash_size(config) +
         config_get_hashes_size(config);
}

tls_result_t message_init(const TLS_CONFIG *config, BUF *region,
                          tls_connection_id_t cid, direction_t direction,
                          MESSAGE *out) {
  assert(config);
  assert(region);
  assert(out);
  memset(out, 0, sizeof(*out));
  // Initialize for a particular direction
  if ((direction == kRecv &&
       !stream_init(region, cid, kRecv, kSegments, kRecvNesting,
                    &out->stream)) ||
      (direction == kSend &&
       !stream_init(region, cid, kSend, kSegments, kSendNesting,
                    &out->stream))) {
    return kTlsFailure;
  }
  // Configure the record layer.
  out->record = stream_get_chunk(&out->stream);
  if (!record_init(config, region, direction, out->record)) {
    return kTlsFailure;
  }
  // Since the initial type is |kHandshake|, act like we just sent or received a
  // zero-length handshake message.
  if (!stream_nested_begin(&out->stream, 0)) {
    return kTlsFailure;
  }
  return kTlsSuccess;
}

tls_result_t message_peek_type(MESSAGE *message, record_content_t *out) {
  assert(message);
  if (!stream_peek(&message->stream)) {
    return kTlsFailure;
  }
  *out = record_get_type(message->record);
  return kTlsSuccess;
}

STREAM *message_get_stream(MESSAGE *message) {
  assert(message);
  return &message->stream;
}

tls_result_t message_recv_ccs(MESSAGE *message, BUF *region,
                              tls_ciphersuite_t ciphersuite, BUF *key,
                              BUF *iv) {
  assert(message);
  uint8_t ccs = 0;
  switch (message->stage) {
    case 0:
      // CCS messages may not follow application data
      // CCS messages may not follow another CCS signal
      // CCS messages may follow completed handshake messages.
      if (record_get_type(message->record) == kApplicationData ||
          record_get_type(message->record) == kChangeCipherSpec ||
          (record_get_type(message->record) == kHandshake &&
           !stream_nested_finish(&message->stream))) {
        return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
      }
      // Fall-through
      ++message->stage;
    case 1:
      // Check that is the correct type of message.
      if (!stream_peek(&message->stream)) {
        return kTlsFailure;
      }
      if (record_get_type(message->record) != kChangeCipherSpec) {
        return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
      }
      stream_set_hashing(&message->stream, kOff);
      // Fall-through
      ++message->stage;
    case 2:
      // Receive the CCS signal
      if (!stream_recv_u8(&message->stream, &ccs)) {
        return kTlsFailure;
      }
      if (ccs != 1) {
        return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
      }
      // Reconfigure the record to use the AEAD
      if (!record_set_ciphersuite(message->record, region, ciphersuite, key,
                                  iv)) {
        return kTlsFailure;
      }
      message->stage = 0;
      return kTlsSuccess;
    default:
      return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
}

tls_result_t message_recv_alert(MESSAGE *message, tls_alert_t alert) {
  assert(message);
  BUF *text = chunk_get_text(message->record);
  // Bypass the usual stream methods to discard everything until we see an
  // alert.  An alert will cause |chunk_recv| to fail and break the loop.
  do {
    buf_consume(text, buf_ready(text), NULL);
  } while (chunk_recv(message->record));
  tls_error_source_t source;
  int reason = 0;
  TLS_ERROR_get(&source, &reason, NULL, NULL);
  if (source != kTlsErrPeer || reason != (int)alert) {
    return kTlsFailure;
  }
  error_clear();
  return kTlsSuccess;
}

tls_result_t message_recv_handshake(MESSAGE *message,
                                    message_handshake_t *out) {
  assert(message);
  assert(out);
  uint32_t type_and_len = 0;
  switch (message->stage) {
    case 0:
      // Handshake messages may not follow application data
      // Handshake messages may follow completed handshake messages.
      if (record_get_type(message->record) == kApplicationData ||
          (record_get_type(message->record) == kHandshake &&
           !stream_nested_finish(&message->stream))) {
        return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
      }
      // Fall-through
      ++message->stage;
    case 1:
      // Check that is the correct type of message.
      if (!stream_peek(&message->stream)) {
        return kTlsFailure;
      }
      if (record_get_type(message->record) != kHandshake) {
        return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
      }
      stream_set_hashing(&message->stream, kOn);
      // Fall-through
      ++message->stage;
    case 2:
      // We need to get type and length in a single read.
      if (!stream_recv_u32(&message->stream, &type_and_len)) {
        return kTlsFailure;
      }
      *out = (message_handshake_t)(type_and_len >> 24);
      if (!stream_nested_begin(&message->stream, (type_and_len & 0xFFFFFF))) {
        return kTlsFailure;
      }
      message->stage = 0;
      return kTlsSuccess;
    default:
      return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
}

tls_result_t message_recv_appdata(MESSAGE *message, BUF *data) {
  assert(message);
  assert(data);
  switch (message->stage) {
    case 0:
      // Application data messages may not follow a CCS signal
      // Application data messages may follow completed handshake messages.
      if (record_get_type(message->record) == kChangeCipherSpec ||
          (record_get_type(message->record) == kHandshake &&
           !stream_nested_finish(&message->stream))) {
        return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
      }
      // Fall-through
      ++message->stage;
    case 1:
      // Check that is the correct type of message.
      if (!stream_peek(&message->stream)) {
        return kTlsFailure;
      }
      if (record_get_type(message->record) != kApplicationData) {
        return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
      }
      stream_set_hashing(&message->stream, kOff);
      // Fall-through
      ++message->stage;
    case 2:
      if (!stream_recv_buf(&message->stream, NULL, 0, data)) {
        return kTlsFailure;
      }
      message->stage = 0;
      return kTlsSuccess;
    default:
      return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
}

tls_result_t message_send_ccs(MESSAGE *message, BUF *region,
                              tls_ciphersuite_t ciphersuite, BUF *key,
                              BUF *nonce) {
  assert(message);
  switch (message->stage) {
    case 0:
      // CCS messages may not follow application data
      // CCS messages may not follow another CCS signal
      // CCS messages may follow completed handshake messages.
      assert(record_get_type(message->record) != kApplicationData);
      assert(record_get_type(message->record) != kChangeCipherSpec);
      if (record_get_type(message->record) == kHandshake &&
          !stream_nested_finish(&message->stream)) {
        assert(ERROR_SET(kTlsErrVapid, kTlsErrInternalError));
      }
      // Fall-through
      ++message->stage;
    case 1:
      if (!record_set_type(message->record, kChangeCipherSpec)) {
        return kTlsFailure;
      }
      stream_set_hashing(&message->stream, kOff);
      // Fall-through
      ++message->stage;
    case 2:
      if (!stream_send_u8(&message->stream, 1)) {
        return kTlsFailure;
      }
      // Fall-through
      ++message->stage;
    case 3:
      // Make sure the CCS signal was completely sent
      if (!stream_flush(&message->stream)) {
        return kTlsFailure;
      }
      // Reconfigure the record layer to use the AEAD
      if (!record_set_ciphersuite(message->record, region, ciphersuite, key,
                                  nonce)) {
        return kTlsFailure;
      }
      message->stage = 0;
      return kTlsSuccess;
    default:
      return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
}

tls_result_t message_send_alert(MESSAGE *message, message_alert_level_t level,
                                tls_alert_t alert) {
  assert(message);
  switch (message->stage) {
    case 0:
      // Alert messages may follow completed handshake messages.
      if (record_get_type(message->record) == kHandshake &&
          !stream_nested_finish(&message->stream)) {
        assert(ERROR_SET(kTlsErrVapid, kTlsErrInternalError));
      }
      // Fall-through
      ++message->stage;
    case 1:
      if (!record_set_type(message->record, kAlert)) {
        return kTlsFailure;
      }
      stream_set_hashing(&message->stream, kOff);
      // Fall-through
      ++message->stage;
    case 2:
      if (!stream_send_u8(&message->stream, (uint8_t)level)) {
        return kTlsFailure;
      }
      // Fall-through
      ++message->stage;
    case 3:
      if (!stream_send_u8(&message->stream, alert)) {
        return kTlsFailure;
      }
      // Fall-through
      ++message->stage;
    case 4:
      // Make sure the alert signal was completely sent
      if (!stream_flush(&message->stream)) {
        return kTlsFailure;
      }
      message->stage = 0;
      return kTlsSuccess;
    default:
      return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
}

tls_result_t message_send_handshake(MESSAGE *message, message_handshake_t type,
                                    uint24_t len) {
  assert(message);
  assert(len < 0x01000000);
  switch (message->stage) {
    case 0:
      // Handshake messages may not follow application data
      // Handshake messages may follow completed handshake messages.
      assert(record_get_type(message->record) != kApplicationData);
      if (record_get_type(message->record) == kHandshake &&
          !stream_nested_finish(&message->stream)) {
        assert(ERROR_SET(kTlsErrVapid, kTlsErrInternalError));
      }
      // Fall-through
      ++message->stage;
    case 1:
      if (!record_set_type(message->record, kHandshake)) {
        return kTlsFailure;
      }
      stream_set_hashing(&message->stream, kOn);
      // Fall-through
      ++message->stage;
    case 2:
      if (!stream_send_u8(&message->stream, type)) {
        return kTlsFailure;
      }
      // Fall-through
      ++message->stage;
    case 3:
      if (!stream_send_u24(&message->stream, len)) {
        return kTlsFailure;
      }
      // Fall-through
      ++message->stage;
    case 4:
      if (!stream_nested_begin(&message->stream, len)) {
        return kTlsFailure;
      }
      message->stage = 0;
      return kTlsSuccess;
    default:
      return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
}



tls_result_t message_send_appdata(MESSAGE *message, BUF *data) {
  assert(message);
  assert(data);
  switch (message->stage) {
    case 0:
      // Application data messages may not follow CCS messages
      // Application data messages may follow completed handshake messages.
      assert(record_get_type(message->record) != kChangeCipherSpec);
      if (record_get_type(message->record) == kHandshake &&
          !stream_nested_finish(&message->stream)) {
        assert(ERROR_SET(kTlsErrVapid, kTlsErrInternalError));
      }
      // Fall-through
      ++message->stage;
    case 1:
      if (!record_set_type(message->record, kApplicationData)) {
        return kTlsFailure;
      }
      stream_set_hashing(&message->stream, kOff);
      // Fall-through
      ++message->stage;
    case 2:
      if (!stream_send_buf(&message->stream, 0, data)) {
        return kTlsFailure;
      }
      // Fall-through
      ++message->stage;
    case 3:
      if (!stream_flush(&message->stream)) {
        return kTlsFailure;
      }
      message->stage = 0;
      return kTlsSuccess;
    default:
      return ERROR_SET(kTlsErrVapid, kTlsErrInvalidState);
  }
}

// Static functions
