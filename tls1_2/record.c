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

#include "tls1_2/record.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "common/chunk.h"
#include "crypto/aead.h"
#include "tls1_2/ciphersuite.h"
#include "tls1_2/config.h"

enum alert_level_t {
  kAlertWarning = 1,
  kAlertFatal = 2,
};

enum record_field_t {
  kContentType = 0,
  kVersion = 1,
  kLength = 2,
  kVarNonce = 3,
  kText = 4,
  kSeqNum = 5,
};

const uint16_t kTlsVersion1_2 = 0x0303;
const size_t kVersionLen = 2;

static const uint16_t kMaxWarnings = 4;

static const size_t kSeqNumLen = 8;
static const size_t kTypeLen = 1;
static const size_t kLengthLen = 2;

static const size_t kAlertLevelLen = 1;
static const size_t kAlertDescLen = 1;

// Forward declarations

static size_t record_unprotected_size(void);
static size_t record_authenticated_size(void);
static size_t record_encrypted_size(const TLS_CONFIG *config);
static tls_result_t record_set_nonce(CHUNK *record, direction_t direction,
                                     bool_t precrypto);
static tls_result_t record_recv_preprocess(CHUNK *chunk);
static tls_result_t record_recv_process(CHUNK *chunk);
static tls_result_t record_recv_postprocess(CHUNK *chunk);
static tls_result_t record_send_preprocess(CHUNK *chunk);
static tls_result_t record_send_process(CHUNK *chunk);

// Library routines

size_t record_size(const TLS_CONFIG *config) {
  return config_get_max_aead_size(config) + config_get_max_nonce_len(config) +
         record_unprotected_size() + record_authenticated_size() +
         record_encrypted_size(config);
}

tls_result_t record_init(const TLS_CONFIG *config, BUF *region,
                         direction_t direction, CHUNK *out) {
  assert(out);
  // Don't memset; |out| has already been partially initialized via
  // |stream_init|.
  // The only unprotected field may be the explicit nonce after the AEAD is set
  size_t size = record_unprotected_size();
  if (!chunk_set_region(out, region, size, kUnprotected)) {
    return kTlsFailure;
  }
  // The authenticated fields are the type, version, length, and possibly the
  // sequence number after the AEAD is set (which is authenticated, but won't be
  // sent).
  size = record_authenticated_size();
  if (!chunk_set_region(out, region, size, kAuthenticated) ||
      !chunk_set_segment(out, kSeqNum, kSeqNumLen, kAuthenticated) ||
      !chunk_set_segment(out, kContentType, kTypeLen, kAuthenticated) ||
      !chunk_set_segment(out, kVersion, kVersionLen, kAuthenticated) ||
      !chunk_set_segment(out, kLength, kLengthLen, kAuthenticated)) {
    return kTlsFailure;
  }
  // The only encrypted field is the text
  size = record_encrypted_size(config);
  if (!chunk_set_region(out, region, size, kEncrypted) ||
      !chunk_set_text(out, kText, record_get_length)) {
    return kTlsFailure;
  }
  // Set up initial data and callbacks
  record_set_type(out, kHandshake);
  if (direction == kRecv) {
    chunk_set_processing(out, record_recv_preprocess, record_recv_process,
                         record_recv_postprocess);
  } else {
    BUF *version = chunk_get_segment(out, kVersion);
    buf_put_val(version, kVersionLen, kTlsVersion1_2);
    chunk_set_processing(out, record_send_preprocess, record_send_process,
                         NULL);
  }
  return kTlsSuccess;
}

record_content_t record_get_type(CHUNK *record) {
  BUF *type = chunk_get_segment(record, kContentType);
  assert(buf_size(type) == kTypeLen);
  buf_reset(type, 0);
  buf_produce(type, kTypeLen, NULL);
  uint32_t value = 0;
  buf_get_val(type, kTypeLen, &value);
  return (record_content_t)value;
}

tls_result_t record_get_length(CHUNK *record, size_t *out) {
  BUF *var_nonce = chunk_get_segment(record, kVarNonce);
  size_t var_nonce_len = buf_size(var_nonce);
  BUF *length = chunk_get_segment(record, kLength);
  uint32_t len = 0;
  if (!buf_get_val(length, kLengthLen, &len) || len < var_nonce_len) {
    return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
  }
  buf_reset(length, 0);
  buf_produce(length, kLengthLen, NULL);
  *out = len - var_nonce_len;
  return kTlsSuccess;
}

tls_result_t record_set_type(CHUNK *record, record_content_t new_type) {
  record_content_t old_type = record_get_type(record);
  if (old_type == new_type) {
    return kTlsSuccess;
  }
  BUF *text = chunk_get_text(record);
  if (buf_ready(text) != 0 && !chunk_send(record)) {
    return kTlsFailure;
  }
  BUF *type = chunk_get_segment(record, kContentType);
  buf_reset(type, 0);
  buf_put_val(type, kTypeLen, new_type);
  return kTlsSuccess;
}

void record_set_length(CHUNK *record, size_t len) {
  BUF *length = chunk_get_segment(record, kLength);
  buf_reset(length, 0);
  buf_put_val(length, kLengthLen, len);
}

tls_result_t record_set_ciphersuite(CHUNK *record, BUF *region,
                                    tls_ciphersuite_t ciphersuite, BUF *key,
                                    BUF *iv) {
  assert(record);
  // For all the AEAD ciphers we support, the variable nonce is the sequence
  // number.  If the ciphersuite does not indicate that the nonce should be
  // created by exclusive-ORing the sequence number with the |iv|, then the
  // sequence number will be included in the record as an explicit nonce.
  size_t nonce_len = buf_ready(iv);
  assert(ciphersuite_var_nonce_length(ciphersuite) == kSeqNumLen);
  assert(ciphersuite_fix_nonce_length(ciphersuite) == nonce_len);
  if (!ciphersuite_xor_nonce(ciphersuite)) {
    nonce_len += kSeqNumLen;
  }
  // Set the AEAD.
  const AEAD *aead = ciphersuite_get_aead(ciphersuite);
  assert(aead);

  if (!chunk_set_aead(record, region, aead, key, iv, nonce_len)) {
    return kTlsFailure;
  }
  // Reconfigure the segments.
  if (!ciphersuite_xor_nonce(ciphersuite) &&
      !chunk_set_segment(record, kVarNonce, kSeqNumLen, kUnprotected)) {
    return kTlsFailure;
  }
  if (!chunk_set_text(record, kText, record_get_length)) {
    return kTlsFailure;
  }
  buf_zero(chunk_get_segment(record, kSeqNum));
  return kTlsSuccess;
}

// Static functions

static size_t record_unprotected_size() {
  // See the comment in |record_set_ciphersuite|.  For all AEAD ciphers we
  // support, the largest variable nonce is a sequence number.
  return kSeqNumLen;
}

static size_t record_authenticated_size() {
  return kSeqNumLen + kTypeLen + kVersionLen + kLengthLen;
}

static size_t record_encrypted_size(const TLS_CONFIG *config) {
  return config_get_fragment_length(config);
}

static tls_result_t record_set_nonce(CHUNK *record, direction_t direction,
                                     bool_t precrypto) {
  // These values don't matter pre-CCS
  const AEAD *aead = chunk_get_aead(record);
  if (!aead) {
    return kTlsSuccess;
  }
  // Make sure |seq_num| is available
  BUF *seq_num = chunk_get_segment(record, kSeqNum);
  buf_reset(seq_num, 0);
  buf_produce(seq_num, kSeqNumLen, NULL);

  // See the comment in |record_set_ciphersuite|.  All the AEAD ciphers we
  // support either XOR the sequence number with the existing nonce, or included
  // the sequence number as an explicit variable nonce.
  BUF *nonce = chunk_get_nonce(record);
  BUF *var_nonce = chunk_get_segment(record, kVarNonce);

  // How is the variable nonce constructed?
  buf_reset(nonce, buf_size(nonce) - kSeqNumLen);
  if (buf_size(var_nonce) == 0) {
    // Nonce is made by XOR'ing the fixed nonce and sequence number
    buf_produce(nonce, kSeqNumLen, NULL);
    buf_xor(seq_num, nonce);
  } else if (precrypto && direction == kRecv) {
    // Nonce is included in the record
    buf_copy(var_nonce, nonce);
  } else if (precrypto) {
    // Nonce is seq_num, and should be included in the record
    buf_copy(seq_num, nonce);
    buf_copy(seq_num, var_nonce);
  }
  buf_reset(nonce, 0);
  buf_produce(nonce, buf_size(nonce), NULL);
  // Done if we haven't opened or sealed
  if (precrypto) {
    return kTlsSuccess;
  }
  // Increment the sequence number and consume it to prevent it be written
  if (!buf_counter(seq_num)) {
    return kTlsFailure;
  }
  buf_consume(seq_num, kSeqNumLen, NULL);
  return kTlsSuccess;
}

// Before recv
static tls_result_t record_recv_preprocess(CHUNK *record) {
  // Make sure seq_num is filled so it isn't read
  BUF *seq_num = chunk_get_segment(record, kSeqNum);
  buf_produce(seq_num, buf_available(seq_num), NULL);
  return kTlsSuccess;
}

// After recv, but before open
static tls_result_t record_recv_process(CHUNK *record) {
  // Modify the length to match what was present when the record was sealed.
  size_t len = 0;
  if (!record_get_length(record, &len)) {
    return kTlsFailure;
  }
  const AEAD *aead = chunk_get_aead(record);
  size_t tag_size = 0;
  if (aead) {
    tag_size = aead_get_tag_size(aead);
  }
  if (tag_size > len) {
    return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
  }
  assert(tag_size <= len);
  record_set_length(record, len - tag_size);
  // Make sure nonce is ready
  return record_set_nonce(record, kRecv, kTrue);
}

// After open
static tls_result_t record_recv_postprocess(CHUNK *record) {
  // Check version
  uint32_t version = 0;
  BUF *version_buf = chunk_get_segment(record, kVersion);
  if (!buf_get_val(version_buf, kVersionLen, &version)) {
    return kTlsFailure;
  }
  if (version != kTlsVersion1_2) {
    return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
  }
  // Check for alerts.
  if (record_get_type(record) == kAlert) {
    BUF *text = chunk_get_text(record);
    uint32_t level = 0;
    uint32_t desc = 0;
    if (!buf_get_val(text, kAlertLevelLen, &level) ||
        !buf_get_val(text, kAlertDescLen, &desc)) {
      return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
    }
    // Is this alert a fatal error or a closure notification?
    if (level == kAlertFatal || desc == kTlsErrCloseNotify) {
      return ERROR_SET(kTlsErrPeer, desc);
    }
    // Ignore warnings unless badly formed or we've seen too many.
    if (chunk_get_warnings(record) >= kMaxWarnings) {
      return ERROR_SET(kTlsErrVapid, kTlsErrTooManyWarnings);
    }
    chunk_add_warning(record);
  }
  // Separate seq_num and nonce, if necessary
  return record_set_nonce(record, kRecv, kFalse);
}

// Before seal
static tls_result_t record_send_preprocess(CHUNK *record) {
  // Fill in type
  BUF *type = chunk_get_segment(record, kContentType);
  buf_reset(type, 0);
  buf_produce(type, kTypeLen, NULL);
  // Fill in version
  BUF *version = chunk_get_segment(record, kVersion);
  buf_reset(version, 0);
  buf_produce(version, kVersionLen, NULL);
  // Fill in length
  BUF *length = chunk_get_segment(record, kLength);
  BUF *text = chunk_get_text(record);
  uint16_t len = (uint16_t)buf_ready(text);
  buf_reset(length, 0);
  buf_put_val(length, kLengthLen, len);
  // Make sure nonce is ready
  return record_set_nonce(record, kSend, kTrue);
}

// After seal, before send
static tls_result_t record_send_process(CHUNK *record) {
  // Reset the length, which should now include the nonce and auth tag.
  BUF *var_nonce = chunk_get_segment(record, kVarNonce);
  BUF *text = chunk_get_text(record);
  uint16_t len = (uint16_t)(buf_ready(var_nonce) + buf_ready(text));
  BUF *length = chunk_get_segment(record, kLength);
  buf_reset(length, 0);
  buf_put_val(length, kLengthLen, len);
  // Separate seq_num and nonce, if necessary
  return record_set_nonce(record, kSend, kFalse);
}
