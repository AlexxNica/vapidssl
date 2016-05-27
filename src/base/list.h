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

#ifndef VAPIDSSL_BASE_LIST_H
#define VAPIDSSL_BASE_LIST_H
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "base/list_internal.h"

/* The LIST structure represents a simple sequence of elements.  It provides
 * methods for retrieval, insertion and deletion at either end, and for forward
 * traversal. Unlike C++/STL lists, modification resets the list iterator.
 *
 * The LIST structure doesn't know any details about the elements it is storing
 * beyond their size.  To make interacting with a list safer, four CRUD-like
 * macros that take the element incorporate the element type and ensure sizes
 * match.  As an example, the following code, given a memory |region|, creates a
 * list of |BUF|s, adds an element, retrieves, the element, and deletes it :
 *    LIST list;
 *    BUF* buf = NULL;
 *    LIST_NEW(BUF, region, 4, &list);
 *    LIST_ADD(BUF, &list, &buf);
 *    buf = LIST_GET(BUF, 0, &list);
 *    LIST_DEL(BUF, &list);
 */

/* List structure defined in src/base/list_internal.h. */
typedef struct list_st LIST;

/* LIST_NEW initializes |list| with memory allocated from |region| to hold
 * |max_elems| of the given |type|. It returns a |tls_result_t| to indicate
 * success or failure. */
#define LIST_NEW(type, region, max, list) \
  list_new(region, sizeof(type), max, list)

/* LIST_LEN returns the number of elements of a given |type| currently in the
 * |list|. */
#define LIST_LEN(type, list) list_len(list, sizeof(type))

/* LIST_GET returns a pointer to the element of the given |type| at the given
 * |index| in the |list|, or NULL if the |list| is empty. */
#define LIST_GET(type, list, index) (type *)list_get(list, sizeof(type), index)

/* LIST_ADD inserts a zero-initialized element of the given |type| at the end of
 * the |list|.  It returns the added element, or NULL on error. */
#define LIST_ADD(type, list) (type *)list_add(list, sizeof(type), kBack)

/* LIST_ADD_FRONT inserts a zero-initialized element of the given |type| at the
 * front of the |list|.  It returns the added element, or NULL on error. */
#define LIST_ADD_FRONT(type, list) (type *)list_add(list, sizeof(type), kFront)

/* LIST_DEL deletes an element of the given |type| from the end of the |list|.
 * It returns void. */
#define LIST_DEL(type, list) list_del(list, sizeof(type), kBack)

/* LIST_DEL_FRONT deletes an element of the given |type| from the front of the
 * |list|. It returns void. */
#define LIST_DEL_FRONT(type, list) list_del(list, sizeof(type), kFront)

/* LIST_SWAP exchanges the |i|th and |j|th elements of a given |type| within a
 * |list|.  */
#define LIST_SWAP(type, list, i, j) list_swap(list, sizeof(type), i, j)

/* LIST_BEGIN resets the list iterator to the beginning of the |list| of
 * elements of a given |type|.  It returns a pointer to the first element or
 * NULL if the list is empty. */
#define LIST_BEGIN(type, list) (type *)list_begin(list, sizeof(type))

/* LIST_ITER returns the element of a given |type| that is currently indexed by
 * list iterator, or NULL if the iterator has already iterated over all
 * available elements. */
#define LIST_ITER(type, list) (type *)list_iter(list, sizeof(type))

/* LIST_NEXT advances the list iterator to the next element of the given |type|
 * from the |list|, if any available elements remain.  It returns |kTrue| if the
 * iterator advanced, and false otherwise. */
#define LIST_NEXT(type, list) (type *)list_next(list, sizeof(type))

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* VAPIDSSL_BASE_LIST_H */
