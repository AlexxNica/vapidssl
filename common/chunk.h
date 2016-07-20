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

#ifndef VAPIDSSL_COMMON_RECORD_H
#define VAPIDSSL_COMMON_RECORD_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/types.h"
#include "crypto/aead.h"
#include "public/config.h"
#include "public/error.h"
#include "public/tls.h"

// A chunk is a generic unit of trasnfer for sending and receiving data over the
// network.  Chunks may be authenticated and encrypted with an AEAD.  A chunk is
// made up of a doubly-ordered sequence of buffers referred to as segments:
//    - Each segment has an explicit index.  This dictates the order in which
//      segments are sent.
//    - Each segment has an implicit allocation order, based on the order the
//      segments are added.  This specifies the arragement of segments when
//      sealed or opened by the AEAD, if one is enabled.
//
// There is one special chunk, the "text" chunk.  This must be added after all
// other segments.  It uses the remaining space available, and in the case of a
// receiving chunk includes a callback to determine the amount of data to read
// based on other segments.

// Opaque chunk structure, defined in common/chunk_internal.h.
typedef struct chunk_st CHUNK;

// A chunk_f is a callback that acts on a |chunk|.  Examples include the
// |process_chunk| set in |chunk_set_process|, the |update_nonce| passed to
// |chunk_set_aead|, and the |continue_chunk| set in |stream_init|.
typedef tls_result_t (*chunk_f)(CHUNK *chunk);

// A text_size_f is a callback similar to |chunk_f|, but it also produces a size
// in |out|.  It is used to determine the actual length of data to receive for
// the text segment in |chunk_recv|, and is set in |chunk_set_text|.
typedef tls_result_t (*text_size_f)(CHUNK *chunk, size_t *out);

// chunk_size returns the memory needed to successfully complete a call to
// |chunk_init| with the given limit for |max_segments|.  |max_segments| must be
// non-zero.
size_t chunk_size(uint8_t max_segments);

// chunk_init configures the chunk in |out| to either send or receive data,
// depending on |direction|, to or from the connection identified by |cid|.  It
// uses |region| to allocate a list of segments of length |max_segements|.
// After calling |chunk_init|, specific protocols must configure the chunk
// further.  First they must allocate regions for desired protection levels
// using |chunk_set_region|. Then they must create the individual segments using
// |chunk_set_segment| or |chunk_set_text|.  At this point, data may be
// transferred, but it will be unprotected until |chunk_set_aead| is called.
tls_result_t chunk_init(BUF *region, tls_connection_id_t cid,
                        direction_t direction, uint8_t max_segments,
                        CHUNK *out);

// chunk_get_aead returns the AEAD used by |chunk|, or NULL if the
// |chunk_set_aead| has not been called.
const AEAD *chunk_get_aead(CHUNK *chunk);

// chunk_get_nonce returns a pointer to the nonce buffer used by |chunk|, or
// NULL if the |chunk_set_aead| has not been called.
BUF *chunk_get_nonce(CHUNK *chunk);

// chunk_get_text returns a pointer to the segment of |chunk| with the given
// |index|, or NULL if the |index| is invalid
BUF *chunk_get_segment(CHUNK *chunk, uint8_t index);

// chunk_get_text returns a pointer to the special text segment of |chunk|, or
// NULL if one has not been configured.
BUF *chunk_get_text(CHUNK *chunk);

// chunk_get_warnings returns the number of warnings encountered by this |chunk|
// so far.  The number of warnings can be incremented by the chunk callbacks
// using |chunk_add_warning| below.
size_t chunk_get_warnings(CHUNK *chunk);

// chunk_set_region allocates a sub-region of |len| bytes from |region|, and
// registers it with |chunk| as the region to use when allocating segments of a
// given protection |level|.  It is an error to call |chunk_set_region| twice
// for the same protection |level|.
tls_result_t chunk_set_region(CHUNK *chunk, BUF *region, size_t len,
                              data_protection_t level);

// chunk_set_processing sets optional |preprocess|, |process| and |postprocess|
// callbacks on |chunk| to allow specific protocols to modify and/or verify data
// as needed before, between, and after crypto and I/O is performed.
void chunk_set_processing(CHUNK *chunk, chunk_f preprocess, chunk_f process,
                          chunk_f postprocess);

// chunk_set_aead sets and enables the given |aead| with the given |key| and
// |nonce|.  The |aead|'s state is allocated from |region|.
tls_result_t chunk_set_aead(CHUNK *chunk, BUF *region, const AEAD *aead,
                            BUF *key, BUF *nonce, size_t nonce_len);

// chunk_set_segment allocates a segment of |len| bytes to this |chunk| at the
// given |index|.  The segment may be allocated from either the unprotected,
// authenticated, or encrypted data regions, depending on the specified
// protection |level|.  As noted above, the explicit |index| indicates the order
// in which segments will be sent or received, will the order of calls to
// |chunk_set_segment| determine the order of authenticated and encrypted
// segment data when passed to the AEAD.
tls_result_t chunk_set_segment(CHUNK *chunk, uint8_t index, size_t len,
                               data_protection_t level);

// chunk_set_text configures the special "text" segment for |chunk| at the given
// |index|.  This segment uses any remaining space in encrypted data region. If
// the |chunk| is configured to receive data, it also registers the |size|
// callback used to determine how much data is available for the text segment
// based on other segments (e.g. a length segment).
tls_result_t chunk_set_text(CHUNK *chunk, uint8_t index, text_size_f size);

// chunk_reset_segments zeros each segment in |chunk|, effectively undoing any
// previous calls to |chunk_set_segment| or |chunk_set_text|.  The |chunk| must
// be reconfigured before it can be used to transfer data.
void chunk_reset_segments(CHUNK *chunk);

// chunk_add_warning increments the number of warnings seen by this |chunk|.  It
// is intended to be used by the processing callbacks to track warnings.
void chunk_add_warning(CHUNK *chunk);

// chunk_recv sends the data in each segment to the network.  It will first
// invoke the AEAD, if enabled, on that data. Specific protocols should not call
// this directly, and use the |stream_send_*| functions instead.
tls_result_t chunk_send(CHUNK *chunk);

// chunk_recv fills each segment with data from the network.  It will
// subsequently invoke the AEAD, if enabled, on that data. Specific protocols
// should not call this directly, and use the |stream_send_*| functions instead.
tls_result_t chunk_recv(CHUNK *chunk);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_COMMON_RECORD_H
