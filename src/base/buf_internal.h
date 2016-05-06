/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef VAPIDSSL_BASE_BUF_INTERNAL_H
#define VAPIDSSL_BASE_BUF_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stddef.h>
#include <stdint.h>

/* buf_st memory region containing bytes that are being produced and/or consumed
 * by callers.  It tracks a memory region, its maximum size, the offset of bytes
 * consumed, and the length of bytes produced thus far. This struct is not
 * opaque to reduce overhead; it should be treated as if it were. */
struct buf_st {
  /* Allocating buffer. It is not NULL unless |raw| is NULL or the wrapped
   * memory was passed in via the public API.  Only buffers with an |region| of
   * NULL may be used as the |region| argument in |buf_malloc|. */
  struct buf_st *region;
  /* Pointer to the actual memory region. */
  uint8_t *raw;
  /* Offset into the buffer, i.e. the number of bytes consumed thus far. */
  size_t offset;
  /* Length of the buffer, i.e. the number of bytes produced thus far. */
  size_t length;
  /* Size of the wrapped memory region, in bytes. */
  size_t max;
  /* The number of bytes allocated to other buffers from this buffer.  */
  size_t allocated;
};

/* buf_as returns a pointer to underlying memory of this struct. It is NOT
 * meant to be called; callers other than |list_init| should use the |BUF_AS|
 * macro instead. */
uint8_t *buf_as(struct buf_st *buf, size_t size);

#if defined(__cplusplus)
}
#endif /* __cplusplus */
#endif /* VAPIDSSL_BASE_BUF_INTERNAL_H */
