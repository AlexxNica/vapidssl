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

#ifndef VAPIDSSL_BASE_BUF_H
#define VAPIDSSL_BASE_BUF_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "base/buf_internal.h"

#include <stddef.h>
#include <stdint.h>

#include "base/types.h"
#include "public/error.h"

// The BUF structure is used to abstract and mediate interaction with raw memory
// regions.  A BUF wraps a region of memory and then tracks the contents of the
// memory as either being space available for data, data that is ready to be
// used, or data that has already been consumed.
//
// New BUFs must be created using |buf_init|. These are empty and do not wrap
// any memory.  The BUF structure can wrap a memory region in one of 3 ways:
// - It can "directly" wrap an explicit memory region using |buf_wrap|.
// - It can "allocate" memory using |buf_malloc| on another BUF.
// - It can use |buf_split| on an allocated BUF.
// Each of these has a correspond function to tear down BUFs with additional
// special usages:
// - Any BUF can stop tracking memory using |buf_unwrap|.
// - An allocated BUF can be deallocated using |buf_free|, but calls to
//   |buf_free| *MUST* be made in reverse order of calls to |buf_malloc|, with
//   the exception noted below.
// - Any two adjacent BUFs may be combined using |buf_merge|.
// BUFs are adjacent if they were |buf_malloc|d sequentially from the same
// directly wrapped BUF or were the result of a call to |buf_split|. BUFs
// allocated from a directly wrapped region form a LIFO stack.  This may not be
// strict given the use of
// |buf_split| and/or |buf_merge|.  As an example, the following is valid, given
// a memory region |mem| of length 3:
//    BUF region = buf_init();
//    buf_wrap(mem, 3, 0, &region);
//    BUF buf1 = buf_init();
//    BUF buf2 = buf_init();
//    BUF buf3 = buf_init();
//    buf_malloc(&region, 1, &buf1);
//    buf_malloc(&region, 2, &buf2);
//    buf_split(&buf2, 1, &buf3);
//    buf_free(&buf3);
//    buf_merge(&buf1, &buf2);
//    buf_free(&buf2);
// Note that in the case of |buf_split|, the new BUF is considered to have been
// allocated later.
//
// The remaining functions in this file are useful for producing and consuming
// data within the BUFs.
//
// TODO(aarongreen): This hides a lot of information from ASAN, so we will need
// additional debug instrumentation to catch bugs.

// Memory buffer structure, defined in src/base/buf_internal.h.
typedef struct buf_st BUF;

// wipe_t indicates whether memory should be wiped or not.
typedef enum wipe_t {
  kDoWipe,
  kDoNotWipe,
} wipe_t;

// BUF_AS casts a wrapped memory region to a specific type. This is useful for
// storing and retrieving data structures using BUFs.  As an example, a
// structure |foo| of type |struct foo_st| can be stored and retrieved using the
// following:
//    BUF foo_buf = buf_init();
//    buf_wrap(&foo_buf, &foo,
//    sizeof(struct foo_st));
//    struct foo_st* bar = BUF_AS(struct foo_st, &foo_buf);
#define BUF_AS(type, buf) ((type *)(buf_as(buf, sizeof(type))))

// Memory manipulation functions: These functions configure buffer structs their
// consumed, ready, and available regions.

// buf_init returns an initially empty BUF that does not wrap any memory.
BUF buf_init(void);

// buf_wrap takes a region of memory pointed to by |mem| with length |len| and
// configures |buf| to track it.  If |preallocate| is not equal to |len|, it
// will configure |buf| as if it had already allocated |preallocate| bytes. As a
// special case, if |preallocate| equals |len|, it is understood that |mem|
// contains data and it will mark all of |buf| as ready.
// If this buffer already wraps a different region of memory, |buf_wrap| fails
// with |kTlsErrBufferChanged|. This function is only intended to be used by API
// functions that borrow memory from the API consumer.
tls_result_t buf_wrap(void *mem, size_t len, size_t preallocate, BUF *out);

// buf_unwrap stops |buf| from tracking a memory region.  It returns |buf|'s
// memory if it was directly wrapped using |buf_wrap| or NULL if |buf| is
// already unwrapped.  If |wipe_memory| is |kDoWipe| it will wipe the memory
// before returning it. It is an error to call |buf_unwrap| on a |buf| that was
// passed to |buf_malloc|.
void *buf_unwrap(BUF *buf, wipe_t wipe_memory);

// buf_malloc configures |out| to track |len| bytes from |region|.  This memory
// can be returned by calling |buf_free|. It is an error to call |buf_malloc|
// with an |out| that already wraps memory.
tls_result_t buf_malloc(BUF *region, size_t len, BUF *out);

// buf_free zeros the memory wrapped by |buf| and makes it available to be
// distributed by again.  |buf| must be the BUF most recently returned by
// |buf_malloc| or have been |buf_merge|d with that BUF. See the comment at the
// top of this file for more details.
void buf_free(BUF *buf);

// buf_split truncates |in| to |in_size| and configures |out| to wrap the
// truncated memory.
void buf_split(BUF *in, size_t in_size, BUF *out);

// buf_merge combines two adjacent BUFs into |out| and |buf_unwrap|s |in|. BUFs
// are adjacent if they were |buf_malloc|d sequentially or are the result of a
// |buf_split|.
void buf_merge(BUF *in, BUF *out);

// buf_reset modifies |buf| to be as if it had already consumed |num| bytes and
// had no data ready.
void buf_reset(BUF *buf, size_t num);

// buf_recycle modifies |buf| by making the number of bytes in the consumed
// region available for new data again.
void buf_recycle(BUF *buf);

// Accessors: These functions return the internal state of the BUF struct.

// buf_size returns the length of the memory wrapped by |buf|.
size_t buf_size(const BUF *buf);

// buf_consumed returns the amount of space already consumed in |buf|, in bytes.
// A call to |buf_recycle| will make this memory available.
size_t buf_consumed(const BUF *buf);

// buf_ready returns the number of bytes of data that are presently in |buf|.  A
// call to |buf_consume| up to this number will not fail.
size_t buf_ready(const BUF *buf);

// buf_available returns the amount of space remaining in |buf|, in bytes. A
// call to |buf_produce| up to this number will not fail.
size_t buf_available(const BUF *buf);

// buf_allocated gets the total space currently allocated from |buf|.
size_t buf_allocated(const BUF *buf);

// Data transfer primitives: These functions are useful for transferring data to
// and from memory wrapped in a buffer struct.

// buf_consume sets |out| to a pointer to where data can be taken from this BUF.
// It decreases the amount of ready data by |len|. |out| may be NULL, in which
// case the |buf| simply skips |len| bytes of ready data.
tls_result_t buf_consume(BUF *buf, size_t len, uint8_t **out);

// buf_may_consume is similar to |buf_consume|, except that it does not change
// the amount of ready data.  It is used when the actual memory needed isn't
// known before using it, e.g. with a network write.  Each call to
// |buf_may_consume| must be paired with a call to |buf_did_consume| to record
// the actual data consumed.
tls_result_t buf_may_consume(const BUF *buf, size_t len, uint8_t **out);

// buf_did_consume records the actual |len| bytes of data that were consumed as
// a result of an earlier call to |buf_may_consume|.
void buf_did_consume(BUF *buf, size_t len);

// buf_produce sets |out| to a pointer to where data can be added to this BUF.
// It decreases the amount of available space by |len|. |out| may be NULL in
// which case the |buf| simply marks |len| bytes as ready.
void buf_produce(BUF *buf, size_t len, uint8_t **out);

// buf_may_produce is similar to |buf_produce|, except that it does not change
// the amount of available space.  It is used when the actual memory used isn't
// known before filling it, e.g. with a network read.  Each call to
// |buf_may_produce| must be paired with a call to |buf_did_produce| to record
// the actual data [produced].
void buf_may_produce(const BUF *buf, size_t len, uint8_t **out);

// buf_did_produce records the actual |len| bytes of data that were produced as
// a result of an earlier call to |buf_may_produce|.
void buf_did_produce(BUF *buf, size_t len);

// buf_get_val consumes |len| bytes from |buf|'s memory and converts it to a
// value using network byte order, which it writes to |out|. It decreases the
// amount of ready data by |len|. It returns |kTlsFailure| if there is not
// enough data ready, and |kTlsSuccess| otherwise.
tls_result_t buf_get_val(BUF *buf, uint8_t len, uint32_t *out);

// buf_put_val produces |len| bytes in network order from |val| and adds them to
// to |buf|'s memory.  It decreases the amount of space available by |len|.
void buf_put_val(BUF *buf, uint8_t len, uint32_t val);

// Data routines: These functions provide further ways of examining and
// modifying the contents of buffer structs.

// buf_equal compares |a| and |b| and returns a non-zero value if and only if
// their ready data have the same length and contents.
bool_t buf_equal(const BUF *a, const BUF *b);

// buf_zero zeros any memory wrapped by |buf| and makes it all available space./
void buf_zero(BUF *buf);

// buf_fill puts |val| in every byte of |buf|'s available space.
void buf_fill(BUF *buf, uint8_t val);

// buf_xor exclusive-ors each byte of |dst|'s ready data with a corresponding
// byte of |src|'s ready data.
void buf_xor(const BUF *src, BUF *dst);

// buf_counter increments |buf|'s ready data as if it were one long value in
// network byte order.
tls_result_t buf_counter(BUF *buf);

// buf_atou interprets the |len| bytes of |buf|'s ready data as an ASCII decimal
// number and places in |out|. It decreases the amount of ready data by |len|.
// It returns |kTlsFailure| if there is not enough data ready or the data
// includes non-decimal characters, and |kTlsSuccess| otherwise.
tls_result_t buf_atou(BUF *buf, uint8_t len, uint32_t *out);

// buf_copy copies as much of |src|'s ready data as possible into |dst|'s
// available space.
size_t buf_copy(const BUF *src, BUF *dst);

// buf_move moves |src|'s data and state to |dst|.  |dst| must not wrap any
// memory. |dst| inherits all aspects of |src|, including its memory region,
// offsets, and parent region.  After this call, |src| is unset and doesn't wrap
// any memory.
void buf_move(BUF *src, BUF *dst);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_BUF_H
