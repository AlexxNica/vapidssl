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

#ifndef VAPIDSSL_BASE_LIST_INTERNAL_H
#define VAPIDSSL_BASE_LIST_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/types.h"
#include "public/error.h"

// list_st represents a sequence of elements. The list is actually a simple
// array of elements, with some fields to track how much is in use.
struct list_st {
  // The size of elements in this list. This is set in |list_new| and checked in
  // all other calls.
  size_t elem_size;
  // The memory backing the element array. An important note is that this memory
  // cannot be freed as the BUF that allocated it from a memory |region| is
  // temporary and discard.  The memory can only be released using |buf_unwrap|
  // on the memory |region|.
  void *elems;
  // iterator tracks the next element to be returned by |list_next|.  It is
  // never exceeds |num_elems|. It is set to |num_elems| by |list_new|,
  // |list_add|, and |list_del|, to 0 by |list_iter|, and to |iterator| + 1 by
  // |list_next|.
  uint8_t iterator;
  // The number of elements currently in the list.  It is initially 0 and never
  // exceeds |max_elems|.
  uint8_t num_elems;
  // The maximum number of elements this list can hold, i.e. the length of the
  // |elems| array, in elements of |elem_size|.
  uint8_t max_elems;
};

// list_new initializes |out| with memory allocated from |region| to hold
// |max_elems| of |elem_size| bytes each.  This function should not be called
// directly; use the LIST_NEW macro instead.
tls_result_t list_new(BUF *region, size_t elem_size, uint8_t max_elems,
                      struct list_st *out);

// list_len returns the number of elements of a given |size| currently in the
// |list|. This function should not be called directly; use the LIST_LEN macro
// instead.
uint8_t list_len(struct list_st *list, size_t size);

// list_get returns a pointer to the element of the given |size| at the given
// |index| in the |list|, or NULL if the |list| is empty. This function should
// not be called directly; use the LIST_GET macro instead.
void *list_get(struct list_st *list, size_t size, uint8_t index);

// list_add inserts a zero-initialized element of the given |size| at the given
// |end| of the |list|.  This function should not be called directly; use the
// LIST_ADD or LIST_PUSH macros instead.
void *list_add(struct list_st *list, size_t size, end_t end);

// list_del deletes an element of the given |size| at the given |end| of the
// |list|.  This function should not be called directly; use the LIST_DEL or
// LIST_POP macros instead.
void list_del(struct list_st *list, size_t size, end_t end);

// list_swap exchanges the |i|th and |j|th elements of a given |size| within a
// |list|.  This function should not be called directly; use the LIST_SWAP macro
// instead.
void list_swap(struct list_st *list, size_t size, uint8_t i, uint8_t j);

// list_begin resets the list iterator to the beginning of the |list| of
// elements of a given |size|.  It returns a pointer to the first element or
// NULL if the list is empty. This function should not be called directly; use
// the LIST_BEGIN macro instead.
void *list_begin(struct list_st *list, size_t size);

// list_iter returns the element of a given |size| that is currently indexed by
// list iterator, or NULL if the iterator has already iterated over all
// available elements. This function should not be called directly; use the
// LIST_ITER macro instead.
void *list_iter(struct list_st *list, size_t size);

// list_next advances the list iterator to the next element of the given |type|
// from the |list|, if any available elements remain.  It returns |kTrue| if the
// iterator advanced, and false otherwise. This function should not be called
// directly; use the LIST_NEXT macro instead.
void *list_next(struct list_st *list, size_t size);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_LIST_INTERNAL_H
