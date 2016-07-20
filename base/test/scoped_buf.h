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

// ScopedBuf is a helper class for managing memory during unit tests.  BUF
// structures returned by the methods this class are guaranteed to have proper
// memory backing and to be automatically cleaned up on helper destruction.
class ScopedBuf {
 public:
  // ScopedBuf() creates a buffer that does not wrap any memory.
  ScopedBuf();

  // ScopedBuf(size_t) creates a buffer that wraps |len| bytes of newly
  // allocated and zeroed memory.
  explicit ScopedBuf(size_t len);

  // ScopedBuf(vector) creates a buffer makes and wraps a copy of the data in
  // |bytes|./
  explicit ScopedBuf(void *bytes, size_t len);

  // ScopedBuf(vector) creates a buffer makes and wraps a copy of the data in
  // |bytes|./
  explicit ScopedBuf(const std::vector<uint8_t> &bytes);

  virtual ~ScopedBuf();
  ScopedBuf &operator=(const ScopedBuf &) = delete;
  ScopedBuf(const ScopedBuf &) = delete;

  // Get returns a pointer to the underlying buffer.  It never returns NULL.
  BUF *Get();

  // Raw returns a pointer to the memory wrapped by the underlying buffer.
  void *Raw();

  // Len returns the size of the underlying buffer; i.e. |buf_size(Get())|.
  size_t Len();

  // Reset acts like |Reset(size_t)| with the size of |Len()|.
  void Reset(void);

  // Reset() deallocates the buffer's memory (if applicable), allocates and
  // zeroes |len| bytes of new memory, and wraps the memory with the buffer.
  void Reset(size_t len);

  // Reset(BUF) acts like |Reset(size_t)| with the size of |buf|, and then
  // copies the contents of |buf| to this object's buffer.
  void Reset(ScopedBuf &buf);

  // Reset(vector) acts like |Reset(size_t)| with the length of the vector, then
  // copies the contents of |bytes| to the buffer.
  void Reset(const std::vector<uint8_t> &bytes);

 private:
  // buf_ is wrapped by this object, so that the object's destructor guarantees
  // it is properly unwrapped when the object goes out of scope.
  BUF buf_;
};

}  // namespace vapidssl

// operator<< prints the contents of |buf| using |os|.  This operator is here
// because it must be in the same namespace as BUF.  See Google Test's
// AdvancedGuide.md#teaching-google-test-how-to-print-your-values.
::std::ostream &operator<<(::std::ostream &os, const BUF *buf);

#endif  // VAPIDSSL_BASE_TEST_SCOPED_BUF_H
