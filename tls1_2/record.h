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

#ifndef VAPIDSSL_TLS1_2_RECORD_H
#define VAPIDSSL_TLS1_2_RECORD_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "common/chunk.h"
#include "public/error.h"

// This file provides an abstraction for the TLS 1.2 record layer, as described
// in https://tools.ietf.org/html/rfc5246#section-6.2

// record_content_t lists the different types of records as specified in
// in https://tools.ietf.org/html/rfc5246#section-6.2.1
typedef enum record_content_t {
  kChangeCipherSpec = 20,
  kAlert = 21,
  kHandshake = 22,
  kApplicationData = 23,
} record_content_t;

// kTlsVersion1_2 gives the bytes that represents TLS 1.2.
extern const uint16_t kTlsVersion1_2;
// kVersionLen is the version length in bytes.
extern const size_t kVersionLen;

// record_size returns the number of bytes needed for a call to |record_init| to
// succeed, given a particular |config|.
size_t record_size(const TLS_CONFIG *config);

// record_init configures the chunk given by |out| to be a TLS 1.2 record in the
// given |direction|, using memory from |region| and according to the current
// |config|.
tls_result_t record_init(const TLS_CONFIG *config, BUF *region,
                         direction_t direction, CHUNK *out);

// record_get_type examines the |record|'s segments and returns its ContentType.
record_content_t record_get_type(CHUNK *record);

// record_get_length examines the |record|'s segments and returns its length.
tls_result_t record_get_length(CHUNK *record, size_t *out);

// record_set_type writes the given |content_type| to the |record|'s segments.
tls_result_t record_set_type(CHUNK *record, record_content_t content_type);

// record_set_type writes the given |length| to the |record|'s segments.
void record_set_length(CHUNK *record, size_t length);

// record_set_ciphersuite enables the given |ciphersuite| on the |record|.  It
// allocates state for the AEAD from |region| and then initializes it with an
// initial vector |iv| and a |key|.
tls_result_t record_set_ciphersuite(CHUNK *record, BUF *region,
                                    tls_ciphersuite_t ciphersuite, BUF *key,
                                    BUF *iv);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_RECORD_H
