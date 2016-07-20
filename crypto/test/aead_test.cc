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

#include "crypto/test/aead_test.h"

#include "base/buf.h"
#include "base/platform/test/platform_helper.h"
#include "base/test/scoped_buf.h"
#include "crypto/aead.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// Public Methods

const std::vector<TEST_DATA> &AeadTest::GetData() {
  static const std::vector<TEST_DATA> kTestData = {
      {
          .algorithm = kAeadAes128Gcm,
          .parameter = 0,
          .path =
              "third_party/boringssl/crypto/cipher/test/aes_128_gcm_tests.txt",
      },
      {
          .algorithm = kAeadAes256Gcm,
          .parameter = 0,
          .path =
              "third_party/boringssl/crypto/cipher/test/aes_256_gcm_tests.txt",
      },
      {
          .algorithm = kAeadChaCha20Poly1305,
          .parameter = 0,
          .path = "third_party/boringssl/crypto/cipher/test/"
                  "chacha20_poly1305_tests.txt",
      },
  };
  return kTestData;
}

// Protected Methods

AeadTest::AeadTest() : aead_(nullptr), truncated_tag_(false) {}

// SetUp is called at the start of each test to set up the test fixture.  It
// opens its test data file and registers the attributes it expects to use. It
// also allocates working buffers that will be needed during testing.
void AeadTest::SetUp() {
  CryptoTest::SetUp();
  const struct test_data_st &test_data = GetParam();
  aead_ = aead_find(test_data.algorithm);
  ASSERT_FALSE(aead_ == nullptr);
  state_.Reset(aead_get_state_size(aead_));
  AddHexAttribute("KEY", key_);
  AddHexAttribute("NONCE", nonce_);
  AddHexAttribute("IN", plaintext_);
  AddHexAttribute("AD", additional_data_);
  AddHexAttribute("CT", ciphertext_);
  AddHexAttribute("TAG", tag_);
}

// ReadNext extends the |CryptoHelper::ReadNext| in three ways: it records if
// the gold file contains a truncated authentication tag, it combines the
// ciphertext and authentication tag, and it lengthens of the plaintext buffer
// to match the combined ciphertext buffer.
bool AeadTest::ReadNext() {
  if (!CryptoTest::ReadNext()) {
    return false;
  }
  // While the crypto library can handle variable length tags, at the protocol
  // level we insist they be a fixed length.
  truncated_tag_ = false;
  size_t tag_size = aead_get_tag_size(aead_);
  if (tag_.Len() != tag_size) {
    truncated_tag_ = true;
  }
  // Concatenate ciphertext and tag.
  size_t ciphertext_len = ciphertext_.Len() + tag_size;
  ScopedBuf tmp(ciphertext_len);
  buf_copy(ciphertext_.Get(), tmp.Get());
  buf_copy(tag_.Get(), tmp.Get());
  ciphertext_.Reset(ciphertext_len);
  buf_copy(tmp.Get(), ciphertext_.Get());
  // Ensure plaintext has enough headroom for a tag.
  tmp.Reset(ciphertext_len);
  buf_copy(plaintext_.Get(), tmp.Get());
  plaintext_.Reset(ciphertext_len);
  buf_copy(tmp.Get(), plaintext_.Get());
  buf_reset(plaintext_.Get(), 0);
  buf_produce(plaintext_.Get(), ciphertext_len - tag_size, nullptr);
  return true;
}

}  // namespace vapidssl
