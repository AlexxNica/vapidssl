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

#ifndef VAPIDSSL_CRYPTO_TEST_AEAD_TEST_H
#define VAPIDSSL_CRYPTO_TEST_AEAD_TEST_H

#include "crypto/test/crypto_test.h"

#include "base/test/scoped_buf.h"
#include "crypto/aead.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// AeadTest is a test fixture for src/crypto/aead_unittest.cc.  It is separated
// into its own translation unit to facilitate other test fixtures which derive
// from it (notably src/common/chunk_unittest.cc)
class AeadTest : public CryptoTest {
 public:
  virtual ~AeadTest() = default;
  AeadTest &operator=(const AeadTest &) = delete;
  AeadTest(const AeadTest &) = delete;

  // GetData defines the authenticated encryption and decryption algorithms
  // that can be tested and their associated test data files.
  static const std::vector<TEST_DATA> &GetData();

 protected:
  AeadTest();

  // SetUp is called at the start of each test to set up the test fixture.  It
  // opens its test data file and registers the attributes it expects to use. It
  // also allocates working buffers that will be needed during testing.
  void SetUp() override;

  // ReadNext records if the test data file contains a truncated authentication
  // tag, combines the ciphertext and authentication tag, and lengthens of the
  // plaintext buffer to match the combined ciphertext buffer.
  bool ReadNext() override;

  // aead_ defines the algorithm under test.
  const AEAD *aead_;
  // state_ is the memory used by the algorithm under test.
  ScopedBuf state_;
  // key is the cipher's symmetric key.
  ScopedBuf key_;
  // nonce_ is the "number-used-once" that yields different ciphertexts for the
  // same plaintext.
  ScopedBuf nonce_;
  // additional_data_ is the additional data that is authenticated but not
  // encrypted.
  ScopedBuf additional_data_;
  // plaintext_ is the plaintext that is either encrypted into a ciphertext, or
  // compared against a decrypted ciphertext.
  ScopedBuf plaintext_;
  // ciphertext_ is the ciphertext that is either decrypted into a plaintext, or
  // compared against a encrypted plaintext.
  ScopedBuf ciphertext_;
  // tag_ is the authentication tag appended to the ciphertext.
  ScopedBuf tag_;
  // truncated_tag_ is true when only a partial tag is present in the gold file.
  // While a general AEAD can have variable length tags, within a protocol like
  // TLS the tag length is agreed upon and fixed.
  bool truncated_tag_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_CRYPTO_TEST_AEAD_TEST_H
