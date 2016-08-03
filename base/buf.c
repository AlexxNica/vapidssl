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

#include "base/buf.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "base/buf_internal.h"
#include "base/error.h"
#include "public/error.h"

// Forward declarations:  The ONLY functions allowed to directly access the
// fields of a |BUF| are these static functions and the accessors
// |buf_consumed|, |buf_ready|, |buf_available|, and |buf_size|.  All other
// methods do not touch BUFs directly, but access them through these functions.

// buf_is_valid checks conditions which should be invariant, including whether
// |buf| is NULL, whether it proper wraps memory, and whether it's consumed,
// ready, and available regions are consistent with its overall length.
static void buf_is_valid(const BUF *buf);

// buf_wraps checks if the given |buf| wraps the memory specified by |region|
// and |len| and returns |kTrue| if it does, |kFalse| otherwise. It can also be
// used to check if |buf| is unwrapped by calling "buf_wraps(NULL, 0)".
static bool_t buf_wraps(const BUF *buf, const void *mem, size_t len);

// buf_get_region returns the memory BUF that either allocated |buf| or that
// allocated the BUF that |buf| was split was split from. This value will be
// NULL for BUFs that directly wrap memory.
static BUF *buf_get_region(const BUF *buf);

// buf_start_raw returns a pointer to the beginning of |buf|'s raw memory.
static uint8_t *buf_start_raw(const BUF *buf);

// buf_ready_raw returns a pointer to |buf|'s ready data.
static uint8_t *buf_ready_raw(const BUF *buf);

// buf_avail_raw returns a pointer to |buf|'s available space.
static uint8_t *buf_avail_raw(const BUF *buf);

// buf_alloc_raw returns a pointer to |buf|'s next allocatable space.
static uint8_t *buf_alloc_raw(const BUF *buf);

// buf_final_raw returns a pointer to the end of |buf|'s raw memory.
static uint8_t *buf_final_raw(const BUF *buf);

// buf_increment_consumed increases the consumed data in |buf| by |num|. This
// has the side effect of decreasing the amount of ready data.
static void buf_increment_consumed(BUF *buf, size_t num);

// buf_increment_allocated increases the space allocated to other buffers from
// |buf| by |num|.
static void buf_increment_allocated(BUF *buf, size_t num);

// buf_increment_allocated decreases the space allocated to other buffers from
// |buf| by |num|.
static void buf_decrement_allocated(BUF *buf, size_t num);

// buf_increment_ready increases the ready data in |buf| by |num|. This has the
// side effect of decreasing the available space.
static void buf_increment_ready(BUF *buf, size_t num);

// buf_set overwrites any existing values in |out| and replaces them with
// |region|, |raw|, |offset|, |length|, and |size|. This function does not relay
// on calls to |assert| to enforce its constraints.  It includes explicit checks
// and a call to |abort| to ensure it dies upon detecting a memory corruption
// even when asserts have been disabled.
static void buf_set(BUF *region, uint8_t *raw, size_t consumed, size_t ready,
                    size_t size, BUF *out);

// buf_unset is an alias for buf_set(NULL, NULL, 0, 0, 0, buf).
static void buf_unset(BUF *buf);

// Library routines: These functions are NOT allowed to access BUF internals
// directly.
BUF buf_init(void) {
  BUF empty = {
      NULL, NULL, 0, 0, 0, 0,
  };
  return empty;
}

tls_result_t buf_wrap(void *mem, size_t len, size_t preallocate, BUF *out) {
  assert(mem);
  assert(len != 0);
  assert(out);
  assert(buf_get_region(out) == NULL);
  if (buf_wraps(out, mem, len)) {
    return kTlsSuccess;
  }
  if (!buf_wraps(out, NULL, 0)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBufferChanged);
  }
  if (preallocate == 0) {
    buf_set(NULL, mem, 0, 0, len, out);
  } else if (preallocate == len) {
    buf_set(NULL, mem, 0, len, len, out);
  } else {
    buf_set(NULL, mem, 0, len, len, out);
    buf_increment_allocated(out, preallocate);
  }
  return kTlsSuccess;
}

void *buf_unwrap(BUF *buf, wipe_t wipe_memory) {
  if (buf_wraps(buf, NULL, 0)) {
    return NULL;
  }
  assert(buf_get_region(buf) == NULL);
  void *mem = buf_start_raw(buf);
  if (wipe_memory == kDoWipe) {
    memset(mem, 0, buf_size(buf));
  }
  memset(buf, 0, sizeof(*buf));
  return mem;
}

tls_result_t buf_malloc(BUF *region, size_t size, BUF *out) {
  assert(buf_wraps(out, NULL, 0));
  if (size > buf_size(region) - buf_allocated(region)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrOutOfMemory);
  }
  uint8_t *raw = buf_alloc_raw(region);
  buf_increment_allocated(region, size);
  buf_set(region, raw, 0, 0, size, out);
  return kTlsSuccess;
}

void buf_free(BUF *buf) {
  assert(buf_allocated(buf) == 0);
  assert(!buf_wraps(buf, NULL, 0));
  BUF *region = buf_get_region(buf);
  uint8_t *region_alloc = buf_alloc_raw(region);
  uint8_t *buf_end = buf_final_raw(buf);
  assert(region_alloc == buf_end);
  size_t size = buf_size(buf);
  buf_zero(buf);
  buf_unset(buf);
  buf_decrement_allocated(region, size);
}

void buf_split(BUF *in, size_t in_size, BUF *out) {
  BUF *region = buf_get_region(in);
  assert(region != NULL);
  assert(in_size < buf_size(in));
  assert(buf_allocated(in) <= in_size);
  const size_t out_size = buf_size(in) - in_size;
  size_t in_consumed = buf_consumed(in);
  size_t out_consumed = 0;
  size_t in_ready = buf_ready(in);
  size_t out_ready = 0;
  if (in_consumed > in_size) {
    out_consumed = in_consumed - in_size;
    out_ready = in_ready;
    in_consumed = in_size;
    in_ready = 0;
  } else if (in_ready > in_size - in_consumed) {
    out_ready = in_consumed + in_ready - in_size;
    in_ready = in_size - in_consumed;
  }
  buf_reset(in, in_size);
  uint8_t *in_raw = buf_start_raw(in);
  uint8_t *out_raw = buf_ready_raw(in);
  buf_set(region, in_raw, in_consumed, in_ready, in_size, in);
  buf_set(region, out_raw, out_consumed, out_ready, out_size, out);
}

void buf_merge(BUF *in, BUF *out) {
  assert(buf_allocated(in) == 0);
  assert(buf_allocated(out) == 0);
  BUF *region = buf_get_region(in);
  assert(region == buf_get_region(out));
  uint8_t *raw = NULL;
  uint8_t *in_raw = buf_start_raw(in);
  uint8_t *out_raw = buf_start_raw(out);
  size_t consumed = buf_consumed(out);
  if (in_raw < out_raw) {
    assert(buf_final_raw(in) == buf_start_raw(out));
    raw = in_raw;
    // Can't overflow since |consumed| < |size|
    consumed += buf_size(in);
  } else {
    assert(buf_final_raw(out) == buf_start_raw(in));
    raw = out_raw;
  }
  size_t ready = buf_ready(out);
  // Can't overflow since it is the length of a contiguous chunk of memory
  size_t size = buf_size(in) + buf_size(out);
  buf_unset(in);
  buf_set(region, raw, consumed, ready, size, out);
}

void buf_reset(BUF *buf, size_t consumed) {
  if (consumed == buf_consumed(buf) && 0 == buf_ready(buf)) {
    return;
  }
  BUF *region = buf_get_region(buf);
  uint8_t *raw = buf_start_raw(buf);
  const size_t size = buf_size(buf);
  buf_set(region, raw, consumed, 0, size, buf);
}

void buf_recycle(BUF *buf) {
  size_t offset = buf_consumed(buf);
  if (offset == 0) {
    return;
  }
  size_t size = buf_ready(buf);
  uint8_t *src = buf_ready_raw(buf);
  buf_reset(buf, 0);
  uint8_t *dst = NULL;
  buf_produce(buf, size, &dst);
  memmove(dst, src, size);
  uint8_t *avail = buf_avail_raw(buf);
  memset(avail, 0, buf_available(buf));
}

tls_result_t buf_consume(BUF *buf, size_t len, uint8_t **out) {
  if (!buf_may_consume(buf, len, out)) {
    return kTlsFailure;
  }
  buf_did_consume(buf, len);
  return kTlsSuccess;
}

tls_result_t buf_may_consume(const BUF *buf, size_t len, uint8_t **out) {
  if (len > buf_ready(buf)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrOutOfBounds);
  }
  if (len != 0 && out) {
    *out = buf_ready_raw(buf);
  }
  return kTlsSuccess;
}

void buf_did_consume(BUF *buf, size_t len) {
  buf_increment_consumed(buf, len);
}

void buf_produce(BUF *buf, size_t len, uint8_t **out) {
  buf_may_produce(buf, len, out);
  buf_did_produce(buf, len);
}

void buf_may_produce(const BUF *buf, size_t len, uint8_t **out) {
  assert(len <= buf_available(buf));
  if (len != 0) {
    uint8_t *raw = buf_avail_raw(buf);
    if (out) {
      *out = raw;
    }
  }
}

void buf_did_produce(BUF *buf, size_t len) {
  buf_increment_ready(buf, len);
}

tls_result_t buf_get_val(BUF *buf, uint8_t len, uint32_t *out) {
  assert(out);
  assert(len != 0);
  assert(len <= sizeof(uint32_t));
  if (buf_ready(buf) < len) {
    return ERROR_SET(kTlsErrVapid, kTlsErrOutOfBounds);
  }
  uint8_t *raw = NULL;
  buf_consume(buf, len, &raw);
  uint32_t val = raw[0];
  uint8_t i;
  for (i = 1; i < len; ++i) {
    val <<= 8;
    val |= raw[i];
  }
  *out = val;
  return kTlsSuccess;
}

void buf_put_val(BUF *buf, uint8_t len, uint32_t val) {
  assert(len != 0);
  assert(len <= sizeof(uint32_t));
  assert(len <= buf_available(buf));
  uint8_t *raw = NULL;
  buf_produce(buf, len, &raw);
  for (uint8_t i = len; i > 0; i--) {
    raw[i - 1] = val & 0xFF;
    val >>= 8;
  }
}

bool_t buf_equal(const BUF *a, const BUF *b) {
  size_t ready = buf_ready(a);
  if (ready != buf_ready(b)) {
    return kFalse;
  }
  if (ready != 0) {
    uint8_t *a_raw = buf_ready_raw(a);
    uint8_t *b_raw = buf_ready_raw(b);
    if (memcmp(a_raw, b_raw, ready) != 0) {
      return kFalse;
    }
  }
  return kTrue;
}

void buf_zero(BUF *buf) {
  if (!buf_wraps(buf, NULL, 0)) {
    memset(buf_start_raw(buf), 0, buf_size(buf));
  }
  buf_reset(buf, 0);
}

void buf_fill(BUF *buf, uint8_t val) {
  size_t avail = buf_available(buf);
  uint8_t *raw = NULL;
  buf_produce(buf, avail, &raw);
  memset(raw, val, avail);
}

void buf_xor(const BUF *src, BUF *dst) {
  size_t len = buf_ready(dst);
  if (buf_ready(src) < len) {
    len = buf_ready(src);
  }
  uint8_t *dst_raw = buf_ready_raw(dst);
  uint8_t *src_raw = buf_ready_raw(src);
  for (size_t i = 0; i < len; ++i) {
    dst_raw[i] ^= src_raw[i];
  }
}

tls_result_t buf_counter(BUF *buf) {
  uint8_t *raw = buf_ready_raw(buf);
  size_t i = buf_ready(buf);
  do {
    if (i == 0) {
      return ERROR_SET(kTlsErrVapid, kTlsErrIntegerOverflow);
    }
    i--;
    raw[i] += 1;
  } while (raw[i] == 0);
  return kTlsSuccess;
}

tls_result_t buf_atou(BUF *buf, uint8_t len, uint32_t *out) {
  assert(out);
  // 1-9 digits prevents overflowing uint32_t.
  assert(0 < len && len < 10);
  uint32_t val = 0;
  uint32_t digit;
  while (len--) {
    if (!buf_get_val(buf, 1, &digit)) {
      return kTlsFailure;
    } else if (digit < '0' || digit > '9') {
      return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
    }
    val *= 10;
    val += (digit - '0');
  }
  *out = val;
  return kTlsSuccess;
}

size_t buf_copy(const BUF *src, BUF *dst) {
  size_t len = buf_available(dst);
  if (buf_ready(src) < len) {
    len = buf_ready(src);
  }
  if (len != 0) {
    uint8_t *dst_raw = NULL;
    buf_produce(dst, len, &dst_raw);
    uint8_t *src_raw = buf_ready_raw(src);
    memmove(dst_raw, src_raw, len);
  }
  return len;
}

void buf_move(BUF *src, BUF *dst) {
  assert(buf_allocated(src) == 0);
  assert(buf_size(dst) == 0);
  buf_set(buf_get_region(src), buf_start_raw(src), buf_consumed(src),
          buf_ready(src), buf_size(src), dst);
  buf_unset(src);
}

// Accessor functions: These functions are allowed to access BUF internals
// directly.
size_t buf_size(const BUF *buf) {
  buf_is_valid(buf);
  return buf->max;
}

size_t buf_consumed(const BUF *buf) {
  buf_is_valid(buf);
  return buf->offset;
}

size_t buf_ready(const BUF *buf) {
  buf_is_valid(buf);
  return buf->length - buf->offset;
}

size_t buf_available(const BUF *buf) {
  buf_is_valid(buf);
  return buf->max - buf->length;
}

size_t buf_allocated(const BUF *buf) {
  buf_is_valid(buf);
  return buf->allocated;
}

uint8_t *buf_as(BUF *buf, size_t min) {
  buf_is_valid(buf);
  buf_reset(buf, 0);
  uint8_t *out = NULL;
  buf_produce(buf, min, &out);
  return out;
}

// Static functions: These functions are allowed to access BUF internals
// directly.
static void buf_is_valid(const BUF *buf) {
  assert(buf);
  assert((!buf->raw && buf->max == 0) || (buf->raw && buf->max != 0));
  assert(buf->offset <= buf->length);
  assert(buf->length <= buf->max);
  assert(buf->allocated <= buf->max);
}

static bool_t buf_wraps(const BUF *buf, const void *mem, size_t len) {
  buf_is_valid(buf);
  return (buf->raw == mem && buf->max == len ? kTrue : kFalse);
}

static BUF *buf_get_region(const BUF *buf) {
  buf_is_valid(buf);
  return buf->region;
}

static uint8_t *buf_start_raw(const BUF *buf) {
  buf_is_valid(buf);
  assert(buf->raw);
  return buf->raw;
}

static uint8_t *buf_ready_raw(const BUF *buf) {
  buf_is_valid(buf);
  assert(buf->raw);
  return &buf->raw[buf->offset];
}

static uint8_t *buf_avail_raw(const BUF *buf) {
  buf_is_valid(buf);
  assert(buf->raw);
  return &buf->raw[buf->length];
}

static uint8_t *buf_alloc_raw(const BUF *buf) {
  buf_is_valid(buf);
  assert(buf->raw);
  return &buf->raw[buf->allocated];
}

static uint8_t *buf_final_raw(const BUF *buf) {
  buf_is_valid(buf);
  assert(buf->raw);
  return &buf->raw[buf->max];
}

static void buf_increment_consumed(BUF *buf, size_t num) {
  buf_is_valid(buf);
  assert(num <= buf->length);
  assert(buf->offset <= (buf->length - num));
  buf->offset += num;
}

static void buf_increment_allocated(BUF *buf, size_t num) {
  buf_is_valid(buf);
  assert(num <= (buf->max - buf->allocated));
  buf->allocated += num;
}

static void buf_decrement_allocated(BUF *buf, size_t num) {
  buf_is_valid(buf);
  assert(num <= buf->allocated);
  buf->allocated -= num;
}

static void buf_increment_ready(BUF *buf, size_t num) {
  buf_is_valid(buf);
  assert(num <= buf->max);
  assert(buf->length <= (buf->max - num));
  buf->length += num;
}

static void buf_set(BUF *region, uint8_t *raw, size_t consumed, size_t ready,
                    size_t size, BUF *out) {
  // Use asserts to unit test and help in debugging.
  assert(out);
  assert((!raw && size == 0) || (raw && size != 0));
  assert(consumed <= consumed + ready);
  assert(consumed + ready <= size);
  assert(out->allocated == 0 || (out->raw == raw && out->allocated <= size));
  // Use |abort| are to die at runtime in the event of memory corruption.
  if (!out || (raw && size == 0) || (!raw && size != 0) ||
      (consumed + ready < consumed) || (size < consumed + ready) ||
      (out->allocated != 0 && (out->raw != raw || out->allocated > size))) {
    abort();
  }
  out->region = region;
  out->raw = raw;
  out->offset = consumed;
  out->length = consumed + ready;
  out->max = size;
}

static void buf_unset(BUF *buf) {
  buf_set(NULL, NULL, 0, 0, 0, buf);
}
