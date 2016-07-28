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

#ifndef VAPIDSSL_TLS1_2_RECORD_INTERNAL_H
#define VAPIDSSL_TLS1_2_RECORD_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

#include "base/buf.h"
#include "base/types.h"
#include "crypto/aead_internal.h"

struct record_st {
  tls_connection_id_t cid;
  direction_t direction;
  const AEAD *aead;
  BUF aead_state;
  BUF nonce;
  // The buffers below represent the different regions of a record. |record->ad|
  // is the additional data.  |record->seq_num| is the current sequence number.
  // |record->header| is the type/length/version record header. |record->body|
  // is the body of the record whose length was specified in the header.
  // |record->var_nonce| is the variable nonce/explicit IV for AEADs that use
  // them (such as AES-GCM). |record->data| is the actual TLS plaintext or
  // ciphertext. These regions overlap as shown:    |-additional-------|
  // |-data-|    |-seq_num-|-header-|-var_nonce-|-envelope---|
  // |-record--------------------------------------------|.
  BUF buffer;
  BUF additional;
  BUF seq_num;
  BUF header;
  BUF var_nonce;
  BUF envelope;
  BUF data;
  uint8_t ccs : 1;
  uint8_t pending : 1;
  uint8_t new_seq : 1;
  uint8_t empty : 5;
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_RECORD_INTERNAL_H
