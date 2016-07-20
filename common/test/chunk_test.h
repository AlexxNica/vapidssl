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

#ifndef VAPIDSSL_COMMON_TEST_CHUNK_TEST_H
#define VAPIDSSL_COMMON_TEST_CHUNK_TEST_H

#include "crypto/test/aead_test.h"

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/platform/random.h"
#include "base/platform/test/io_mock.h"
#include "base/platform/test/platform_helper.h"
#include "base/test/scoped_buf.h"
#include "base/types.h"
#include "common/chunk.h"
#include "common/chunk_internal.h"
#include "public/error.h"
#include "public/tls.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// ChunkTest is intended to make it easier to write and run unit tests that
// involve sending and receiving chunks of data as defined in common/chunk.h.
// It abstracts the set up of the chunk fragments, both before and after
// enabling an AEAD cipher.
class ChunkTest : public AeadTest {
 public:
  ~ChunkTest() override = default;
  ChunkTest &operator=(const ChunkTest &) = delete;
  ChunkTest(const ChunkTest &) = delete;

 protected:
  // kDataLen, kNumSegments, and kRandomLen are constants defining the chunk
  // structure that are used by the unit tests.
  static const size_t kDataLen;
  static const size_t kNumSegments;
  static const size_t kRandomLen;

  ChunkTest() = default;

  // Setup overrides |AeadTest::SetUp| to additionally set up the loopback
  // buffer and configure io_mock.c to use it.
  void SetUp() override;

  // SetupPreKey configures the chunk without enabling the AEAD cipher. The
  // chunk format used is:
  //    Length : 4 bytes, authenticated.
  //    Random: 3 bytes, unprotected.
  //    Data: Up to 80 bytes, encrypted.
  virtual void SetupPreKey(direction_t dir);

  // SetupPostKey enables the AEAD cipher and configures the chunk. The chunk
  // format used is:
  //    Length : 4 bytes, authenticated.
  //    Magic: 4 bytes, always 0xdeadbeef, encrypted.
  //    Random: 3 bytes, unprotected.
  //    Data: Up to 80 bytes, encrypted.
  //    Sequence Number: 4 bytes, authenticated.
  virtual void SetupPostKey(direction_t dir);

  // ReadNext acts like |AeadTest::ReadNext| except that it skips zero-length
  // plaintexts.
  bool ReadNext() override;

  // GetPlaintext returns the chunk's "text" buffer used to hold the plaintext
  // or ciphertext.  It will make the entire buffer 'ready', less the |reserved|
  // bytes.  The |reserved| bytes are left available, can can be used to hold
  // the AEAD authentication tag upon encrypting.
  BUF *GetPlaintext(size_t reserved);

  // region_ holds the memory to use when testing.
  ScopedBuf region_;
  // loopback_ is the buffer used to hold I/O data.
  ScopedBuf loopback_;
  // rx_ is the receiving chunk.
  CHUNK rx_;
  // tx_ is the transmitting chunk.
  CHUNK tx_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_COMMON_TEST_CHUNK_TEST_H
