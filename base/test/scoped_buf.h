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

#ifndef VAPIDSSL_BASE_TEST_SCOPED_BUF_H
#define VAPIDSSL_BASE_TEST_SCOPED_BUF_H

#include <stddef.h>
#include <stdint.h>
#include <iostream>
#include <set>
#include <vector>

#include "base/buf.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

/* ScopedBuf is a helper class for managing memory during unit tests.  BUF
 * structures returned by the methods this class are guaranteed to have proper
 * memory backing and to be automatically cleaned up on helper destruction. */
class ScopedBuf {
 public:
  /* ScopedBuf() creates a buffer that does not wrap any memory. */
  ScopedBuf();

  /* ScopedBuf(size_t) creates a buffer that wraps |len| bytes of newly
   * allocated and zeroed memory. */
  ScopedBuf(size_t len);

  virtual ~ScopedBuf();
  ScopedBuf &operator=(const ScopedBuf &) = delete;
  ScopedBuf(const ScopedBuf &) = delete;

  /* Get returns a pointer to the underlying buffer.  It never returns NULL. */
  BUF *Get();

  /* Reset() deallocates the buffer's memory (if applicable), allocates and
   * zeroes |len| bytes of new memory, and wraps the memory with the buffer. */
  void Reset(size_t len);

  /* Reset(BUF) acts like |Reset(size_t)| with the size of |buf|, and then
   * copies the contents of |buf| to this object's buffer.  */
  void Reset(ScopedBuf &buf);

  /* Reset(vector) acts like |Reset(size_t)| with the length of the vector, then
   * copies the contents of |bytes| to the buffer. */
  void Reset(const std::vector<uint8_t> &bytes);

 private:
  /* buf_ is wrapped by this object, so that the object's destructor guarantees
   * it is properly unwrapped when the object goes out of scope. */
  BUF buf_;
};

} /* namespace vapidssl */

/* operator<< prints the contents of |buf| using |os|.  This operator is here
 * because it must be in the same namespace as BUF.  See Google Test's
 * AdvancedGuide.md#teaching-google-test-how-to-print-your-values. */
::std::ostream &operator<<(::std::ostream &os, const BUF *buf);

#endif /* VAPIDSSL_BASE_TEST_SCOPED_BUF_H */
