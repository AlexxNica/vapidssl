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

#ifndef VAPIDSSL_COMMON_STREAM_INTERNAL_H
#define VAPIDSSL_COMMON_STREAM_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "base/buf.h"
#include "base/list.h"
#include "common/chunk.h"
#include "common/chunk_internal.h"
#include "crypto/hash.h"

// A stream is used to track sequential data being sent or received
struct stream_st {
  // chunk is the structure used to transfer the data.
  CHUNK chunk;
  // value is used to wrap unsigned integers being sent and received.  This is
  // needed because using non-blocking I/O may cause only part of an integer to
  // be received with each |stream_recv_u*| call, and these partial results must
  // be remember across retries.
  BUF value;
  // hashes contains a list of the currently active stream hashes.  Each byte
  // sent or received using this stream will update all the hashes in this list.
  LIST *hashes;
  // num_unselected_hashes is the number of hashes added by |stream_add_hashes|
  size_t num_unselected_hashes;
  // hashing indicates whether data sent or received should be appended to each
  // of the |hashes|.
  bool_t hashing;
  // nestings contains a list of the currently active nesting boundaries.  Each
  // byte received will decrement each element in the list. If any element is
  // zero then no more data may be received until that element is removed.
  LIST nestings;
};

// stream_hash_st combines a hash with a buffer to hold its state.
struct stream_hash_st {
  const HASH *hash;
  BUF state;
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_COMMON_STREAM_INTERNAL_H
