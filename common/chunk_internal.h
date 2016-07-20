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

#ifndef VAPIDSSL_COMMON_RECORD_INTERNAL_H
#define VAPIDSSL_COMMON_RECORD_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

#include "base/buf.h"
#include "base/list.h"
#include "base/types.h"
#include "public/tls.h"

// A SEGMENT is a portion of a chunk that can either be order by the chunk's
// list structure (for sending and receiving) or by the |allocation_order| (for
// sealing and opening by an AEAD).
typedef struct segment_st {
  // buf contains the data for this segment.
  BUF buf;
  // |allocation_order| sequences buffers allocated from either the
  // |unprotected|, |authenticated|, or |encrypted| regions of a chunk.
  uint8_t allocation_order;
} SEGMENT;

// A chunk_st encapsulates how an individual data transfer is to be sealed and
// sent or received and opened.
struct chunk_st {
  // connection_id identifies the connection to the platform.
  tls_connection_id_t connection_id;
  // direction indicates if the chunk is sending or receiving.
  direction_t direction;
  // aead is the cipher in use.  If it is NULL, all data is unprotected.
  const AEAD *aead;
  // aead_state is the state associated with |aead|.
  BUF aead_state;
  // nonce is the IV used with |aead|.  It must be modified each time
  // |update_nonce| is called for the connection to remain secure.
  BUF nonce;
  // unprotected is the memory region from with unprotected segments are
  // allocated.  This data may be intercepted and modified by an attacker.
  BUF unprotected;
  // authenticated is the memory region from with authenticated segments are
  // allocated.  This data may be intercepted but not modified by an attacker.
  BUF authenticated;
  // encrypted is the memory region from with encrypted segments are
  // allocated.  This data cannot be intercepted or modified by an attacker.
  BUF encrypted;
  // allocated is the number of segments allocated thus far.
  uint8_t allocated;
  // segments is the list of segments this chunk can use.
  LIST segments;
  // preprocess is a callback used to do protocol-specific processing before
  // doing any crypto or I/O.
  chunk_f preprocess;
  // process is a callback used to do protocol-specific processing between
  // doing crypto and I/O, i.e. after receiving but before opening, or after
  // sealing but before sending.
  chunk_f process;
  // postprocess is a callback used to do protocol-specific processing after
  // doing all crypto or I/O.
  chunk_f postprocess;
  // text is a pointer to the special "text" segment.  The |text| segment is the
  // last segment added, and holds the balance of the space in |encrypted|.
  BUF *text;
  // text_size is a callback that uses already read segments to determine the
  // length of the |text| segment.
  text_size_f text_size;
  // extra holds memory that is split from |text| when |text_size| indicates the
  // chunk being read is only partially filled.
  BUF extra;
  // consecutive_empty tracks the number of consecutive chunks in which the
  // |text| field was zero length.  Excessive empty records is almost certainly
  // a DoS attempt.
  uint8_t consecutive_empty;
  // warnings is used by the processing callbacks to track the number of
  // warnings this chunk has encountered.
  uint8_t warnings;
};

// kMaxEmptyChunks gives the maximum number of consecutive empty chunks allowed
// before deciding a DoS attempt is in progress and generating an error.
extern const uint8_t kMaxEmptyChunks;

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_COMMON_RECORD_INTERNAL_H
