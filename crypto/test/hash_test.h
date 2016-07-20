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

#ifndef VAPIDSSL_CRYPTO_TEST_HASH_TEST_H
#define VAPIDSSL_CRYPTO_TEST_HASH_TEST_H

#include "crypto/test/crypto_test.h"

#include "base/test/scoped_buf.h"
#include "crypto/hash.h"

namespace vapidssl {

// HashTest is a test fixture for src/crypto/hash_unittest.cc.  It is separated
// into its own translation unit to facilitate other test fixtures which derive
// from it (notably src/common/stream_unittest.cc)
class HashTest : public CryptoTest {
 public:
  ~HashTest() override = default;
  HashTest &operator=(const HashTest &) = delete;
  HashTest(const HashTest &) = delete;

  // GetData defines the cryptographic hash algorithms that can be tested and
  // their associated test data files.
  static const std::vector<TEST_DATA> &GetData();

 protected:
  HashTest();

  // SetUp is called at the start of each test to set up the test fixture.  It
  // opens its test data file and registers the attributes it expects to use. It
  // also allocates working buffers that will be needed during testing.
  void SetUp() override;

  // hash_ defines the algorithm under test.
  const HASH *hash_;
  // state_ is the memory used by the algorithm under test.
  ScopedBuf state_;
  // in_ is the data to be hashed.
  ScopedBuf in_;
  // digest_ is the expected digest to be produced from |in_|.
  ScopedBuf digest_;
  // out_ is a buffer to hold the actual digest produced from |in_|.
  ScopedBuf out_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_CRYPTO_TEST_HASH_TEST_H
