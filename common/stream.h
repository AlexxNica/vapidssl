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

#ifndef VAPIDSSL_COMMON_STREAM_H
#define VAPIDSSL_COMMON_STREAM_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "common/stream_internal.h"

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/types.h"
#include "common/chunk.h"
#include "crypto/hash.h"
#include "public/error.h"

// stream.c contains functions for sending and receiving sequential data.  It
// uses an underlying chunk to transfer data.
//
// It has functions to keep rolling hashes of data being sent or received,
// including means to defer selecting the exact hash until a later time.  This
// is useful for calculating digests of streams that specify the digest type
// partway through, such as the TLS 1.2 handshake or X.509v3 certificates.
//
// Finally, it can track the alignment of nested data structures within the
// stream, such as DER-encoded ASN.1 sequences.  Callers can set "nesting
// boundaries" by specifying the size of the nested structures.  The stream will
// not read across these boundaries unless they are checked and cleared,
// ensuring lengths match up correctly.

// Opaque stream structures, defined in common/stream_internal.h.
typedef struct stream_st STREAM;
typedef struct stream_hash_st STREAM_HASH;

// stream_size returns the memory needed to successfully complete a call to
// |stream_init| with the given limits for |max_segments|, and |max_nesting|.
// |max_segments| must be non-zero.
size_t stream_size(uint8_t max_segments, uint8_t max_nesting);

// stream_init prepares the stream object named |out| for use in streaming data
// in the given |direction| using the connection identified by |cid|.  It sets
// the limits using the various |max_*| parameters.  It allocates no more than
// |stream_size| bytes from |region|.
tls_result_t stream_init(BUF *region, tls_connection_id_t cid,
                         direction_t direction, uint8_t max_segments,
                         uint8_t max_nesting, STREAM *out);

// stream_get_chunk returns the |stream|'s underlying chunk.  This method is
// exposed to allow specific protocols to configure the segment buffers, and
// should not be used otherwise.  To enforce this, |stream_get_chunk|
// automatically resets the chunk's segments before returning it.
CHUNK *stream_get_chunk(STREAM *stream);

// stream_set_hashes registers a list of |hashes| with a |stream|.  |hashes| may
// be NULL, in which case hashing is implicitly disabled.
void stream_set_hashes(STREAM *stream, LIST *hashes);

// stream_set_hashing determines whether bytes sent or received by the |stream|
// will be added to its hashes or skipped.
void stream_set_hashing(STREAM *stream, bool_t enabled);

// stream_add_hash allocates state for the given |hash| from |region|, and adds
// it to the list of hashes that |stream| is updating.  It can fail if there is
// not enough memory, or if the maximum number of hashes has been exceeded.
tls_result_t stream_add_hashes(STREAM *stream, BUF *region);

// stream_add_hashes is similar to |stream_add_hash|, but it adds one of each
// supported hash to the |stream|.  This is useful when some or all of data to
// be hashed precedes the specification of the hash algorithm.  If this function
// is used, a caller must call |stream_select_hash| before calling
// |stream_clone_digest| or |stream_final_digest|, or before calling
// |stream_add_hashes| again.
tls_result_t stream_add_hash(STREAM *stream, BUF *region, const HASH *hash);

// stream_select_hash selects which one |hash| of the multiple added by
// |stream_add_hashes| to the |stream| should be kept, and discards the rest.
// This function must not be called without first calling |stream_add_hashes|.
// This function must be called between calls to |stream_add_hashes| and either
// |stream_clone_digest| or |stream_final_digest|.
tls_result_t stream_select_hash(STREAM *stream, const HASH *hash);

// stream_clone_digest returns the digest in |out| of the data sent or received
// by this |stream| corresponding to the most recently added or selected hash,
// without removing that hash.  Since finalizing a hash state prevents further
// updates, it uses |region| to make a temporary copy of the hash's state.
tls_result_t stream_clone_digest(STREAM *stream, BUF *region, BUF *out);

// stream_clone_digest returns the digest in |out| of the data sent or received
// by this |stream| corresponding to the most recently added or selected hash,
// and removes that hash.
void stream_final_digest(STREAM *stream, BUF *out);

// stream_nested_begin marks the |stream| as beginning a nested structure of
// length |nested_len|.  This may fail if the maximum nesting depth has already
// been reached.  Once the nesting has been set, attempts to receive data that
// cross the nesting boundary will cause an error.  To cross a nesting boundary,
// a caller must read |nested_len| bytes of data, then call
// |stream_nested_finish|
// before proceeding.
tls_result_t stream_nested_begin(STREAM *stream, uint32_t nested_len);

// stream_nested_finish returns whether |stream| is at a nesting boundary
// previously set by |stream_nested_begin|.  If it is, it decreases the nesting
// depth before returning.  It is possible to have multiple nesting boundaries
// at the same point in the stream; in this case, |stream_nested_finish| must be
// called once for each boundary.
bool_t stream_nested_finish(STREAM *stream);

// stream_peek calls |chunk_recv| on the |stream|'s chunk if the current chunk
// is complete.  This allows higher levels to take action based on the non-text
// chunk fields without touching the chunk's text.
tls_result_t stream_peek(STREAM *stream);

// stream_recv_u8 reads 1 byte from the |stream| and places its value in |out|.
// If the call fails due to data not being available (e.g. EAGAIN), the caller
// may retry.
tls_result_t stream_recv_u8(STREAM *stream, uint8_t *out);

// stream_recv_u16 reads 2 bytes in network order from the |stream| and places
// their value in |out|.  If the call fails due to data not being available
// (e.g. EAGAIN), the caller may retry.
tls_result_t stream_recv_u16(STREAM *stream, uint16_t *out);

// stream_recv_u24 reads 3 bytes in network order from the |stream| and places
// their value in |out|.  If the call fails due to data not being available
// (e.g. EAGAIN), the caller may retry.
tls_result_t stream_recv_u24(STREAM *stream, uint24_t *out);

// stream_recv_u32 reads 4 bytes in network order from the |stream| and places
// their value in |out|.  If the call fails due to data not being available
// (e.g. EAGAIN), the caller may retry.
tls_result_t stream_recv_u32(STREAM *stream, uint32_t *out);

// stream_recv_uint reads |len| bytes in network order from the |stream| and
// places their value in |out|.  If the call fails due to data not being
// available (e.g. EAGAIN), the caller may retry.
tls_result_t stream_recv_uint(STREAM *stream, uint8_t len, uint32_t *out);

// stream_recv_buf fills the available space in |out| with data from the
// |stream|.  If |len_len| is not 0, it first reads |len_len| bytes in network
// order as the length of the data to follow, then allocates that much space for
// |out| using |region|.  If the call fails due to data not being available
// (e.g. EAGAIN), the caller may retry.
tls_result_t stream_recv_buf(STREAM *stream, BUF *region, uint8_t len_len,
                             BUF *out);

// stream_recv_u8 sends |value| as 1 byte to the |stream|.  If the call fails
// due to data not being able to be sent (e.g. EAGAIN), the caller may retry.
tls_result_t stream_send_u8(STREAM *stream, uint8_t value);

// stream_recv_u16 sends |value| as 2 bytes in network order to the |stream|.
// If the call fails due to data not being able to be sent (e.g. EAGAIN), the
// caller may retry.
tls_result_t stream_send_u16(STREAM *stream, uint16_t value);

// stream_recv_u24 sends |value| as 3 bytes in network order to the |stream|.
// If the call fails due to data not being able to be sent (e.g. EAGAIN), the
// caller may retry.
tls_result_t stream_send_u24(STREAM *stream, uint24_t value);

// stream_recv_u32 sends |value| as 4 bytes in network order to the |stream|.
// If the call fails due to data not being able to be sent (e.g. EAGAIN), the
// caller may retry.
tls_result_t stream_send_u32(STREAM *stream, uint32_t value);

// stream_send_uint sends |value| as |len| bytes in network order to the
// |stream|. If the call fails due to data not being able to be sent (e.g.
// EAGAIN), the caller may retry.
tls_result_t stream_send_uint(STREAM *stream, uint8_t len, uint32_t value);

// stream_send_buf sends the ready data in |buf| to the |stream|.  If |len_len|
// is not 0, it first sends the length of the data as |len_len| bytes in network
// order.  If the call fails due to data not being able to be sent (e.g.
// EAGAIN), the caller may retry.
tls_result_t stream_send_buf(STREAM *stream, uint8_t len_len, BUF *buf);

// stream_flush sends pending data to the |stream|.  Normally, the various
// |stream_send_*| functions only call |chunk_send| once the chunk is full.
// When a client is sending some data to a server and then waiting for a
// response, this can leave a final, partially-filled chunk waiting to be sent.
// In this case, the caller needs this function to signal the chunk should be
// sent without waiting to be full.  If the call fails due to data not being
// able to be sent (e.g. EAGAIN), the caller may retry.
tls_result_t stream_flush(STREAM *stream);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_COMMON_STREAM_H
