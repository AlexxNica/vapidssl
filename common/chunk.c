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

#include "common/chunk.h"

#include <assert.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/list.h"
#include "base/platform/io.h"
#include "common/chunk_internal.h"
#include "crypto/aead.h"
#include "public/tls.h"

// kMaxEmptyChunks is the number of consecutive, empty chunks that will be
// processed. Without this limit an attacker could send empty chunks at a faster
// rate than we can process and cause chunk processing to loop forever.
const uint8_t kMaxEmptyChunks = 4;

// Forward declarations.

// chunk_is_valid checks conditions which should be invariant.
static void chunk_is_valid(CHUNK *chunk);
// chunk_reset clears |chunk|'s |text| segment.
static void chunk_reset(CHUNK *chunk);
// chunk_ready_segments updates the |authenticated| and |encrypted| regions with
// the correct amount of ready data prior to them being passed to the AEAD.
static void chunk_ready_segments(CHUNK *chunk);

// Library routines

static_assert(sizeof(SEGMENT) <
                  (1ULL << ((sizeof(size_t) - sizeof(uint8_t)) * 8)),
              "chunk_size may overflow");
size_t chunk_size(uint8_t max_segments) {
  assert(max_segments != 0);
  return max_segments * sizeof(SEGMENT);
}

tls_result_t chunk_init(BUF *region, tls_connection_id_t cid,
                        direction_t direction, uint8_t max_segments,
                        CHUNK *out) {
  assert(out);
  memset(out, 0, sizeof(*out));
  if (!LIST_NEW(SEGMENT, region, max_segments, &out->segments)) {
    return kTlsFailure;
  }
  // Prepopulate the list.
  for (size_t i = 0; i < max_segments; ++i) {
    LIST_ADD(SEGMENT, &out->segments);
  }
  out->connection_id = cid;
  out->direction = direction;
  return kTlsSuccess;
}

const AEAD *chunk_get_aead(CHUNK *chunk) {
  chunk_is_valid(chunk);
  return chunk->aead;
}

BUF *chunk_get_nonce(CHUNK *chunk) {
  chunk_is_valid(chunk);
  return &chunk->nonce;
}

BUF *chunk_get_segment(CHUNK *chunk, uint8_t index) {
  chunk_is_valid(chunk);
  SEGMENT *segment = LIST_GET(SEGMENT, &chunk->segments, index);
  assert(segment);
  return &segment->buf;
}

BUF *chunk_get_text(CHUNK *chunk) {
  chunk_is_valid(chunk);
  return chunk->text;
}

size_t chunk_get_warnings(CHUNK *chunk) {
  chunk_is_valid(chunk);
  return chunk->warnings;
}

tls_result_t chunk_set_region(CHUNK *chunk, BUF *region, size_t len,
                              data_protection_t level) {
  chunk_is_valid(chunk);
  BUF *subregion = NULL;
  switch (level) {
    case kUnprotected:
      subregion = &chunk->unprotected;
      break;
    case kAuthenticated:
      subregion = &chunk->authenticated;
      break;
    case kEncrypted:
      subregion = &chunk->encrypted;
      break;
  }
  assert(buf_size(subregion) == 0);
  return buf_malloc(region, len, subregion);
}

void chunk_set_processing(CHUNK *chunk, chunk_f preprocess, chunk_f process,
                          chunk_f postprocess) {
  chunk_is_valid(chunk);
  chunk->preprocess = preprocess;
  chunk->process = process;
  chunk->postprocess = postprocess;
}

tls_result_t chunk_set_aead(CHUNK *chunk, BUF *region, const AEAD *aead,
                            BUF *key, BUF *nonce, size_t nonce_len) {
  chunk_is_valid(chunk);
  assert(aead);
  assert(nonce);
  assert(!LIST_ITER(SEGMENT, &chunk->segments));
  // Allocate and initialize memory.
  if (buf_size(&chunk->aead_state) != 0) {
    buf_free(&chunk->aead_state);
  }
  if (!buf_malloc(region, aead_get_state_size(aead), &chunk->aead_state) ||
      !buf_malloc(region, nonce_len, &chunk->nonce)) {
    return kTlsFailure;
  }
  chunk->aead = aead;
  buf_copy(nonce, &chunk->nonce);
  return aead_init(chunk->aead, &chunk->aead_state, key, chunk->direction);
}

tls_result_t chunk_set_segment(CHUNK *chunk, uint8_t index, size_t len,
                               data_protection_t level) {
  chunk_is_valid(chunk);
  // Return early if nothing needs to be allocated
  if (len == 0) {
    return kTlsSuccess;
  }
  // Find the segment.
  SEGMENT *segment = LIST_GET(SEGMENT, &chunk->segments, index);
  assert(segment);
  assert(buf_size(&segment->buf) == 0);
  // Get the correct memory region.
  BUF *region = NULL;
  switch (level) {
    case kUnprotected:
      region = &chunk->unprotected;
      break;
    case kAuthenticated:
      region = &chunk->authenticated;
      break;
    case kEncrypted:
      assert(!chunk->text);
      region = &chunk->encrypted;
      break;
  }
  // Set up the buffer.
  if (!buf_malloc(region, len, &segment->buf)) {
    return kTlsFailure;
  }
  // Can't overflow since |allocated| is at most |segments->max_elems|.
  chunk->allocated++;
  segment->allocation_order = chunk->allocated;
  return kTlsSuccess;
}

tls_result_t chunk_set_text(CHUNK *chunk, uint8_t index, text_size_f size) {
  chunk_is_valid(chunk);
  // Find the segment.
  SEGMENT *segment = LIST_GET(SEGMENT, &chunk->segments, index);
  assert(segment);
  // |chunk_set_text| can be called before and after |chunk_set_aead|, resulting
  // in different sizes.
  if (chunk->text) {
    assert(chunk->text == &segment->buf);
    assert(buf_size(chunk->text) != 0);
    buf_free(chunk->text);
  } else {
    chunk->text = &segment->buf;
  }
  assert(buf_size(chunk->text) == 0);
  // Set up the buffer.
  size_t len = buf_size(&chunk->encrypted) - buf_allocated(&chunk->encrypted);
  assert(!chunk->aead || aead_get_tag_size(chunk->aead) < len);
  if (!buf_malloc(&chunk->encrypted, len, chunk->text)) {
    return kTlsFailure;
  }
  if (chunk->direction == kRecv) {
    assert(size);
    chunk->text_size = size;
  }
  return kTlsSuccess;
}

void chunk_reset_segments(CHUNK *chunk) {
  chunk_is_valid(chunk);
  while (chunk->allocated != 0) {
    for (SEGMENT *segment = LIST_BEGIN(SEGMENT, &chunk->segments); segment;
         segment = LIST_NEXT(SEGMENT, &chunk->segments)) {
      if (segment->allocation_order == chunk->allocated) {
        buf_free(&segment->buf);
        memset(segment, 0, sizeof(*segment));
        chunk->allocated--;
        break;
      }
    }
  }
  chunk->text = NULL;
  chunk->text_size = NULL;
}

void chunk_add_warning(CHUNK *chunk) {
  chunk_is_valid(chunk);
  ++chunk->warnings;
}

tls_result_t chunk_recv(CHUNK *chunk) {
  chunk_is_valid(chunk);
  assert(chunk->direction == kRecv);
  assert(buf_allocated(&chunk->unprotected) != 0 ||
         buf_allocated(&chunk->authenticated) != 0 ||
         buf_allocated(&chunk->encrypted) != 0);
  assert(chunk->text);
  assert(chunk->text_size);
  size_t size = 0;
  size_t max = 0;
  // Prepare the chunk for receiving if the iterator isn't active.
  SEGMENT *segment = LIST_ITER(SEGMENT, &chunk->segments);
  if (!segment) {
    // All data must be consumed by now.
    assert(buf_ready(chunk->text) == 0);
    // Reset segments to receive data.
    chunk_reset(chunk);
    // Hook onto higher protocol to do preprocessing as needed.
    if (chunk->preprocess && !chunk->preprocess(chunk)) {
      return kTlsFailure;
    }
    segment = LIST_BEGIN(SEGMENT, &chunk->segments);
  }
  // TODO(aarongreen): Measure the improvement from converting this to
  // scatter-gather.
  for (; segment; segment = LIST_NEXT(SEGMENT, &chunk->segments)) {
    // Skip blank segments.
    if (buf_size(&segment->buf) == 0) {
      continue;
    }
    // If this is the |text| segment, and it is full-sized, check if we need to
    // trim its size.
    if (&segment->buf == chunk->text) {
      if (!chunk->text_size(chunk, &size)) {
        return kTlsFailure;
      }
      max = buf_size(chunk->text);
      // How does the length compare to the segment size?
      if (size > max) {
        // Invalid size for this chunk definition.
        chunk_reset(chunk);
        ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
        break;
      } else if (size == 0) {
        // Make the whole buffer unavailable.
        buf_reset(chunk->text, max);
      } else if (size != max) {
        // If |text| is partially full, temporarily split the text buffer to
        // receive the data as close to the front of |encrypted| as possible for
        // the sake of the AEAD.
        buf_split(chunk->text, size, &chunk->extra);
      }
    }
    // Read the data.
    if (!io_data(chunk->connection_id, kRecv, &segment->buf)) {
      break;
    }
  }
  // Put the |text| segment back together.
  if (buf_size(&chunk->extra) != 0) {
    buf_merge(&chunk->extra, chunk->text);
  }
  // If the iterator didn't complete, we broke on an error.
  if (segment) {
    return kTlsFailure;
  }
  // Hook onto higher protocol to do processing as needed.
  if (chunk->process && !chunk->process(chunk)) {
    return kTlsFailure;
  }
  if (chunk->aead) {
    // Ensure there is a full authentication tag.
    chunk_ready_segments(chunk);
    size = buf_ready(chunk->text);
    size_t tag_size = aead_get_tag_size(chunk->aead);
    if (size < tag_size) {
      chunk_reset(chunk);
      return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
    }
    // Invoke the AEAD!
    if (!aead_data(chunk->aead, &chunk->aead_state, &chunk->nonce,
                   &chunk->authenticated, &chunk->encrypted, kRecv)) {
      return kTlsFailure;
    }
    // Reset |text| to reflect stripped authentication tag.
    size -= tag_size;
    buf_reset(chunk->text, 0);
    buf_produce(chunk->text, size, NULL);
  }
  // Check for a run of empty chunks, which may be a DoS attack.
  if (buf_ready(chunk->text) == 0) {
    chunk->consecutive_empty++;
  } else {
    chunk->consecutive_empty = 0;
  }
  if (chunk->consecutive_empty > kMaxEmptyChunks) {
    chunk_reset(chunk);
    return ERROR_SET(kTlsErrVapid, kTlsErrTooManyEmptyChunks);
  }
  // Hook onto higher protocol to do postprocessing as needed.
  if (chunk->postprocess && !chunk->postprocess(chunk)) {
    return kTlsFailure;
  }
  return kTlsSuccess;
}

tls_result_t chunk_send(CHUNK *chunk) {
  chunk_is_valid(chunk);
  assert(chunk->direction == kSend);
  assert(buf_allocated(&chunk->unprotected) != 0 ||
         buf_allocated(&chunk->authenticated) != 0 ||
         buf_allocated(&chunk->encrypted) != 0);
  assert(chunk->text);
  assert(LIST_LEN(SEGMENT, &chunk->segments) != 0);
  // Prepare the chunk for sending if the iterator isn't active.
  SEGMENT *segment = LIST_ITER(SEGMENT, &chunk->segments);
  if (!segment) {
    // Hook onto higher protocol to do preprocessing as needed.
    if (chunk->preprocess && !chunk->preprocess(chunk)) {
      return kTlsFailure;
    }
    if (chunk->aead) {
      size_t tag_size = aead_get_tag_size(chunk->aead);
      assert(tag_size <= buf_available(chunk->text));
      chunk_ready_segments(chunk);
      // Invoke the AEAD!
      if (!aead_data(chunk->aead, &chunk->aead_state, &chunk->nonce,
                     &chunk->authenticated, &chunk->encrypted, kSend)) {
        return kTlsFailure;
      }
      // Update the text length with the authentication tag .
      buf_produce(chunk->text, tag_size, NULL);
    }
    // Hook onto higher protocol to do processing as needed.
    if (chunk->process && !chunk->process(chunk)) {
      return kTlsFailure;
    }
    segment = LIST_BEGIN(SEGMENT, &chunk->segments);
  }
  // TODO(aarongreen): Measure the improvement from converting this to
  // scatter-gather.
  for (; segment; segment = LIST_NEXT(SEGMENT, &chunk->segments)) {
    // Skip blank segments.
    if (buf_size(&segment->buf) == 0) {
      continue;
    }
    // Send the data.
    if (!io_data(chunk->connection_id, kSend, &segment->buf)) {
      return kTlsFailure;
    }
  }
  // Hook onto higher protocol to do postprocessing as needed.
  if (chunk->postprocess && !chunk->postprocess(chunk)) {
    return kTlsFailure;
  }
  // Clear the write buffer.
  chunk_reset(chunk);
  return kTlsSuccess;
}

// Static functions

static void chunk_is_valid(CHUNK *chunk) {
  assert(chunk);
  assert(LIST_LEN(SEGMENT, &chunk->segments) != 0);
}

static void chunk_reset(CHUNK *chunk) {
  for (SEGMENT *segment = LIST_BEGIN(SEGMENT, &chunk->segments); segment;
       segment = LIST_NEXT(SEGMENT, &chunk->segments)) {
    buf_reset(&segment->buf, 0);
  }
}

static void chunk_ready_segments(CHUNK *chunk) {
  // Mark all authenticated segments as ready.
  buf_reset(&chunk->authenticated, 0);
  size_t size = buf_allocated(&chunk->authenticated);
  buf_produce(&chunk->authenticated, size, NULL);
  // Update encrypted with the correct size.
  buf_reset(&chunk->encrypted, 0);
  size = buf_allocated(&chunk->encrypted) - buf_available(chunk->text);
  buf_produce(&chunk->encrypted, size, NULL);
}
