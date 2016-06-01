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

#include "base/list.h"
#include "base/list_internal.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "base/buf.h"
#include "base/types.h"
#include "public/error.h"

/* Forward declarations. */

/* list_is_valid asserts several invariants about a LIST structure, such as
 * |iterator| <= |num_elems| <= |max_elems| and |size| == |elem_size|. */
static void list_is_valid(LIST *list, size_t size);
/* list_at returns a pointer to the element at the given |index|.  |index| must
 * be within |max_elems|, but does not have to be within |num_elems|. */
static void *list_at(LIST *list, size_t index);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Library routines. */

tls_result_t list_new(BUF *region, size_t elem_size, uint8_t max_elems,
                      LIST *out) {
  assert(out);
  size_t size = elem_size * max_elems;
  assert(size != 0);
  assert(size / elem_size == max_elems); /* Overflow. */
  BUF tmp = buf_init();
  if (!buf_malloc(region, size, &tmp)) {
    return kTlsFailure;
  }
  out->elem_size = elem_size;
  out->elems = buf_as(&tmp, size); /* Special exception to BUF_AS rule. */
  out->iterator = 0;
  out->num_elems = 0;
  out->max_elems = max_elems;
  return kTlsSuccess;
}

uint8_t list_len(struct list_st *list, size_t size) {
  list_is_valid(list, size);
  return list->num_elems;
}

void *list_get(LIST *list, size_t size, uint8_t index) {
  list_is_valid(list, size);
  void *elem = NULL;
  if (index < list->num_elems) {
    elem = list_at(list, index);
  }
  return elem;
}

void *list_add(LIST *list, size_t size, end_t end) {
  list_is_valid(list, size);
  if (list->num_elems == list->max_elems) {
    return NULL;
  }
  size_t index = list->num_elems;
  if (end == kFront) {
    index = 0;
    memmove(list_at(list, 1), list_at(list, 0),
            list->num_elems * list->elem_size);
  }
  void *elem = list_at(list, index);
  memset(elem, 0, size);
  list->num_elems++;
  list->iterator = list->num_elems;
  return elem;
}

void list_del(LIST *list, size_t size, end_t end) {
  list_is_valid(list, size);
  assert(list->num_elems > 0);
  list->num_elems--;
  if (end == kFront) {
    memmove(list_at(list, 0), list_at(list, 1),
            list->num_elems * list->elem_size);
  }
  memset(list_at(list, list->num_elems), 0, list->elem_size);
  list->iterator = list->num_elems;
}

void list_swap(struct list_st *list, size_t size, uint8_t i, uint8_t j) {
  list_is_valid(list, size);
  assert(i < list->num_elems);
  assert(j < list->num_elems);
  uint8_t *a = list_at(list, i);
  uint8_t *b = list_at(list, j);
  uint8_t c = 0;
  for (size_t k = 0; k < size; ++k) {
    c = *a;
    *a++ = *b;
    *b++ = c;
  }
}

void *list_begin(LIST *list, size_t size) {
  list_is_valid(list, size);
  list->iterator = 0;
  return list_iter(list, size);
}

void *list_iter(LIST *list, size_t size) {
  list_is_valid(list, size);
  void *elem = NULL;
  if (list->iterator < list->num_elems) {
    elem = list_at(list, list->iterator);
  }
  return elem;
}

void *list_next(LIST *list, size_t size) {
  list_is_valid(list, size);
  if (list->iterator == list->num_elems) {
    return NULL;
  }
  list->iterator++;
  return list_iter(list, size);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Static functions. */

static void list_is_valid(LIST *list, size_t size) {
  assert(list);
  assert(list->elem_size == size);
  assert(list->iterator <= list->num_elems);
  assert(list->num_elems <= list->max_elems);
}

static void *list_at(LIST *list, size_t index) {
  assert(index < list->max_elems);
  /* No overflow: |index| is less than |num_elems|, |num_elems| is less than
   * |max_elems|, and (|max_elems|*|elem_size|) was checked against overflow in
   * |list_init|. */
  return list->elems + (index * list->elem_size);
}
