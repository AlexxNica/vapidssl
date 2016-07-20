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

#include "common/stream.h"
#include "common/stream_internal.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/types.h"
#include "common/chunk.h"
#include "crypto/hash.h"
#include "public/error.h"

// Forward declarations

// stream_is_valid checks conditions which should be invariant.
static void stream_is_valid(STREAM *stream);
// stream_reset clears the |stream|'s |hashes| and |nestings|, and zeros its
// |chunk|'s text segment.
static void stream_reset(STREAM *stream);
// stream_get_hash gets the most recently added hash for the |stream|.
static STREAM_HASH *stream_get_hash(STREAM *stream);
// stream_postprocess copies as much data as it can from |src| to |dst|, and
// updates all of |stream|'s hashes with whatever data was copied.  It returns
// the length of data copied.  It updates all of the |stream|'s nestings to
// indicate how much data has been sent or received.  If a nesting boundary
// would be crossed, it calls |stream_reset| and returns an error.
static tls_result_t stream_postprocess(STREAM *stream, BUF *src, BUF *dst);
// stream_recv fills the available space in |buf| with data from the |stream|.
// If needed, it will call |chunk_recv| to get more data.
static tls_result_t stream_recv(STREAM *stream, BUF *buf);
// stream_send sends the ready data in |buf| to the |stream|.  If needed, it
// will call |chunk_send| to make space available for more data.
static tls_result_t stream_send(STREAM *stream, BUF *buf);

// Library routines

// We give a very wide berth to simplify the proof that this can't overflow: we
// use the largest element size (and break the '_internal.h' rule a bit to check
// it against chunk_internal.h) and check a stream with four lists instead of 3.
static_assert(sizeof(uint32_t) <= sizeof(SEGMENT),
              "stream_size overflow calculation not using largest size");
static_assert(sizeof(SEGMENT) <
                  (1ULL << (((sizeof(size_t) - sizeof(uint8_t)) * 8) - 2)),
              "stream_size may overflow");
size_t stream_size(uint8_t max_segments, uint8_t max_nesting) {
  size_t nesting_size = LIST_SIZE(uint32_t, max_nesting);
  return chunk_size(max_segments) + sizeof(uint24_t) + nesting_size;
}

tls_result_t stream_init(BUF *region, tls_connection_id_t cid,
                         direction_t direction, uint8_t max_segments,
                         uint8_t max_nesting, STREAM *out) {
  assert(out);
  memset(out, 0, sizeof(*out));
  if (!chunk_init(region, cid, direction, max_segments, &out->chunk) ||
      !buf_malloc(region, sizeof(uint24_t), &out->value) ||
      (max_nesting != 0 &&
       !LIST_NEW(uint32_t, region, max_nesting, &out->nestings))) {
    return kTlsFailure;
  }
  if (direction == kRecv) {
    buf_reset(&out->value, sizeof(uint24_t));
  }
  return kTlsSuccess;
}

CHUNK *stream_get_chunk(STREAM *stream) {
  stream_is_valid(stream);
  chunk_reset_segments(&stream->chunk);
  return &stream->chunk;
}

void stream_set_hashes(STREAM *stream, LIST *hashes) {
  stream_is_valid(stream);
  if (!hashes) {
    stream->hashing = kFalse;
  }
  stream->hashes = hashes;
}

void stream_set_hashing(STREAM *stream, bool_t enabled) {
  stream_is_valid(stream);
  assert(!enabled || stream->hashes);
  stream->hashing = enabled;
}

tls_result_t stream_add_hash(STREAM *stream, BUF *region, const HASH *hash) {
  assert(region);
  assert(hash);
  stream_is_valid(stream);
  assert(stream->hashes);
  assert(stream->num_unselected_hashes == 0);
  STREAM_HASH *stream_hash = LIST_ADD(STREAM_HASH, stream->hashes);
  if (!stream_hash) {
    stream_reset(stream);
    return ERROR_SET(kTlsErrVapid, kTlsErrOutOfBounds);
  }
  stream_hash->hash = hash;
  if (!buf_malloc(region, hash_get_state_size(hash), &stream_hash->state)) {
    stream_reset(stream);
    return kTlsFailure;
  }
  hash_init(hash, &stream_hash->state);
  return kTlsSuccess;
}

tls_result_t stream_add_hashes(STREAM *stream, BUF *region) {
  assert(region);
  stream_is_valid(stream);
  size_t num_unselected_hashes = 0;
  for (const HASH *hash = hash_next(NULL); hash; hash = hash_next(hash)) {
    if (!stream_add_hash(stream, region, hash)) {
      return kTlsFailure;
    }
    num_unselected_hashes++;
  }
  stream->num_unselected_hashes = num_unselected_hashes;
  return kTlsSuccess;
}

tls_result_t stream_select_hash(STREAM *stream, const HASH *hash) {
  assert(hash);
  stream_is_valid(stream);
  assert(stream->hashes);
  size_t len = LIST_LEN(STREAM_HASH, stream->hashes);
  size_t num = stream->num_unselected_hashes;
  assert(num <= len);
  STREAM_HASH *elem = LIST_BEGIN(STREAM_HASH, stream->hashes);
  for (size_t i = 0; i + num < len; ++i) {
    elem = LIST_NEXT(STREAM_HASH, stream->hashes);
  }
  assert(elem);
  STREAM_HASH *selected = elem;
  selected->hash = hash;
  len = 0;
  for (elem = LIST_NEXT(STREAM_HASH, stream->hashes); elem;
       elem = LIST_NEXT(STREAM_HASH, stream->hashes)) {
    buf_merge(&elem->state, &selected->state);
    if (elem->hash == hash) {
      len = hash_get_state_size(hash);
      buf_reset(&selected->state, buf_size(&selected->state) - len);
      buf_produce(&selected->state, len, NULL);
    }
  }
  len = buf_ready(&selected->state);
  if (len < buf_size(&selected->state)) {
    buf_recycle(&selected->state);
    BUF trash = buf_init();
    buf_split(&selected->state, len, &trash);
    buf_free(&trash);
  }
  for (; num > 1; --num) {
    LIST_DEL(STREAM_HASH, stream->hashes);
  }
  stream->num_unselected_hashes = 0;
  assert(len == buf_size(&selected->state));
  assert(len == hash_get_state_size(hash));
  return kTlsSuccess;
}

tls_result_t stream_clone_digest(STREAM *stream, BUF *region, BUF *out) {
  assert(region);
  stream_is_valid(stream);
  assert(stream->num_unselected_hashes == 0);
  assert(out);
  STREAM_HASH *stream_hash = stream_get_hash(stream);
  BUF state = buf_init();
  if (!buf_malloc(region, hash_get_state_size(stream_hash->hash), &state)) {
    return kTlsFailure;
  }
  buf_copy(&stream_hash->state, &state);
  hash_final(stream_hash->hash, &state, out);
  buf_free(&state);
  return kTlsSuccess;
}

void stream_final_digest(STREAM *stream, BUF *out) {
  stream_is_valid(stream);
  assert(stream->hashes);
  assert(stream->num_unselected_hashes == 0);
  STREAM_HASH *stream_hash = stream_get_hash(stream);
  if (out) {
    hash_final(stream_hash->hash, &stream_hash->state, out);
  }
  buf_free(&stream_hash->state);
  LIST_DEL(STREAM_HASH, stream->hashes);
}

tls_result_t stream_nested_begin(STREAM *stream, uint32_t nested_len) {
  stream_is_valid(stream);
  uint32_t *nested = LIST_ADD(uint32_t, &stream->nestings);
  if (!nested) {
    stream_reset(stream);
    return ERROR_SET(kTlsErrVapid, kTlsErrOutOfBounds);
  }
  *nested = nested_len;
  return kTlsSuccess;
}

bool_t stream_nested_finish(STREAM *stream) {
  stream_is_valid(stream);
  size_t len = LIST_LEN(uint32_t, &stream->nestings);
  assert(len != 0);
  uint32_t *nested = LIST_GET(uint32_t, &stream->nestings, len - 1);
  if (*nested != 0) {
    return kFalse;
  }
  LIST_DEL(uint32_t, &stream->nestings);
  return kTrue;
}

tls_result_t stream_peek(STREAM *stream) {
  stream_is_valid(stream);
  BUF *text = chunk_get_text(&stream->chunk);
  if (buf_ready(text) == 0 && !chunk_recv(&stream->chunk)) {
    return kTlsFailure;
  }
  return kTlsSuccess;
}

tls_result_t stream_recv_u8(STREAM *stream, uint8_t *out_value) {
  stream_is_valid(stream);
  assert(out_value);
  uint32_t value = 0;
  if (!stream_recv_uint(stream, 1, &value)) {
    return kTlsFailure;
  }
  *out_value = (uint8_t)value;
  return kTlsSuccess;
}

tls_result_t stream_recv_u16(STREAM *stream, uint16_t *out_value) {
  stream_is_valid(stream);
  assert(out_value);
  uint32_t value = 0;
  if (!stream_recv_uint(stream, 2, &value)) {
    return kTlsFailure;
  }
  *out_value = (uint16_t)value;
  return kTlsSuccess;
}

tls_result_t stream_recv_u24(STREAM *stream, uint24_t *out_value) {
  stream_is_valid(stream);
  assert(out_value);
  uint32_t value = 0;
  if (!stream_recv_uint(stream, 3, &value)) {
    return kTlsFailure;
  }
  *out_value = (uint24_t)value;
  return kTlsSuccess;
}

tls_result_t stream_recv_u32(STREAM *stream, uint32_t *out_value) {
  stream_is_valid(stream);
  return stream_recv_uint(stream, 4, out_value);
}

tls_result_t stream_recv_uint(STREAM *stream, uint8_t len, uint32_t *out) {
  stream_is_valid(stream);
  assert(out);
  if (buf_available(&stream->value) == 0) {
    buf_reset(&stream->value, buf_size(&stream->value) - len);
  }
  if (!stream_recv(stream, &stream->value)) {
    return kTlsFailure;
  }
  return buf_get_val(&stream->value, len, out);
}

tls_result_t stream_recv_buf(STREAM *stream, BUF *region, uint8_t len_len,
                             BUF *out) {
  stream_is_valid(stream);
  assert(len_len < sizeof(uint32_t));
  assert(len_len == 0 || region);
  assert(len_len != 0 || buf_available(out) != 0);
  assert(out);
  if (buf_size(out) == 0) {
    uint32_t len = 0;
    if (!stream_recv_uint(stream, len_len, &len)) {
      return kTlsFailure;
    }
    if (len == 0) {
      return kTlsSuccess;
    }
    if (!buf_malloc(region, len, out)) {
      return kTlsFailure;
    }
  }
  return stream_recv(stream, out);
}

tls_result_t stream_send_u8(STREAM *stream, uint8_t value) {
  stream_is_valid(stream);
  if (!stream_send_uint(stream, 1, value)) {
    return kTlsFailure;
  }
  buf_reset(&stream->value, 0);
  return kTlsSuccess;
}

tls_result_t stream_send_u16(STREAM *stream, uint16_t value) {
  stream_is_valid(stream);
  if (!stream_send_uint(stream, 2, value)) {
    return kTlsFailure;
  }
  buf_reset(&stream->value, 0);
  return kTlsSuccess;
}

tls_result_t stream_send_u24(STREAM *stream, uint24_t value) {
  stream_is_valid(stream);
  if (!stream_send_uint(stream, 3, value)) {
    return kTlsFailure;
  }
  buf_reset(&stream->value, 0);
  return kTlsSuccess;
}

tls_result_t stream_send_u32(STREAM *stream, uint24_t value) {
  stream_is_valid(stream);
  if (!stream_send_uint(stream, 4, value)) {
    return kTlsFailure;
  }
  buf_reset(&stream->value, 0);
  return kTlsSuccess;
}

tls_result_t stream_send_uint(STREAM *stream, uint8_t len, uint32_t value) {
  stream_is_valid(stream);
  if (buf_consumed(&stream->value) == 0) {
    buf_put_val(&stream->value, len, value);
  }
  return stream_send(stream, &stream->value);
}

tls_result_t stream_send_buf(STREAM *stream, uint8_t len_len, BUF *buf) {
  stream_is_valid(stream);
  assert(len_len < sizeof(uint32_t));
  assert(buf);
  assert(buf_ready(buf) != 0);
  if (len_len != 0) {
    assert(buf_ready(buf) < (1UL << (len_len * 8)));
    if (!stream_send_uint(stream, len_len, buf_ready(buf))) {
      return kTlsFailure;
    }
  }
  if (!stream_send(stream, buf)) {
    return kTlsFailure;
  }
  buf_reset(&stream->value, 0);
  return kTlsSuccess;
}

tls_result_t stream_flush(STREAM *stream) {
  stream_is_valid(stream);
  BUF *text = chunk_get_text(&stream->chunk);
  if (buf_ready(text) != 0 && !chunk_send(&stream->chunk)) {
    return kTlsFailure;
  }
  return kTlsSuccess;
}

// Static functions

static void stream_is_valid(STREAM *stream) {
  assert(stream);
}

static void stream_reset(STREAM *stream) {
  BUF *text = chunk_get_text(&stream->chunk);
  if (text) {
    buf_zero(text);
  }
  buf_zero(&stream->value);
  while (LIST_LEN(uint32_t, &stream->nestings) != 0) {
    LIST_DEL(uint32_t, &stream->nestings);
  }
  if (!stream->hashes) {
    return;
  }
  while (LIST_LEN(STREAM_HASH, stream->hashes) != 0) {
    LIST_DEL(STREAM_HASH, stream->hashes);
  }
}

static STREAM_HASH *stream_get_hash(STREAM *stream) {
  stream_is_valid(stream);
  assert(stream->hashes);
  size_t len = LIST_LEN(STREAM_HASH, stream->hashes);
  assert(len != 0);
  STREAM_HASH *stream_hash = LIST_GET(STREAM_HASH, stream->hashes, len - 1);
  assert(stream_hash);
  return stream_hash;
}

static tls_result_t stream_postprocess(STREAM *stream, BUF *src, BUF *dst) {
  stream_is_valid(stream);
  // Copy the data.
  size_t consumed = buf_consumed(src);
  size_t ready = buf_ready(src);
  size_t copied = buf_copy(src, dst);
  // Mark only the copied bytes in |src| as ready.
  buf_reset(src, consumed);
  buf_produce(src, copied, NULL);
  //.Update the nested lengths.
  for (uint32_t *nested = LIST_BEGIN(uint32_t, &stream->nestings); nested;
       nested = LIST_NEXT(uint32_t, &stream->nestings)) {
    if (*nested < copied) {
      stream_reset(stream);
      return ERROR_SET(kTlsErrVapid, kTlsErrLengthMismatch);
    }
    *nested -= copied;
  }
  // Update the active hashes.
  if (stream->hashing) {
    for (STREAM_HASH *hash = LIST_BEGIN(STREAM_HASH, stream->hashes); hash;
         hash = LIST_NEXT(STREAM_HASH, stream->hashes)) {
      hash_update(hash->hash, &hash->state, src);
    }
  }
  // Reset |src| to mark all its ready bytes as ready.
  buf_reset(src, consumed);
  buf_produce(src, ready, NULL);
  buf_consume(src, copied, NULL);
  return kTlsSuccess;
}

static tls_result_t stream_recv(STREAM *stream, BUF *out) {
  stream_is_valid(stream);
  assert(out);
  BUF *text = chunk_get_text(&stream->chunk);
  while (buf_available(out) != 0) {
    if (!stream_peek(stream)) {
      return kTlsFailure;
    }
    assert(buf_ready(text) != 0);
    if (!stream_postprocess(stream, text, out)) {
      return kTlsFailure;
    }
  }
  return kTlsSuccess;
}

static tls_result_t stream_send(STREAM *stream, BUF *buf) {
  stream_is_valid(stream);
  assert(buf);
  BUF *text = chunk_get_text(&stream->chunk);
  const AEAD *aead = chunk_get_aead(&stream->chunk);
  size_t tag_size = 0;
  if (aead) {
    tag_size = aead_get_tag_size(aead);
  }
  while (buf_ready(buf) != 0) {
    if (buf_available(text) == tag_size && !stream_flush(stream)) {
      return kTlsFailure;
    }
    assert(buf_available(text) > tag_size);
    if (!stream_postprocess(stream, buf, text)) {
      return kTlsFailure;
    }
  }
  return kTlsSuccess;
}
