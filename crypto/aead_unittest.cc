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

#include "crypto/aead.h"
#include "crypto/aead_internal.h"
#include "crypto/test/aead_test.h"

#include <iostream>
#include <map>

#include "base/buf.h"
#include "base/error.h"
#include "base/platform/test/platform_helper.h"
#include "base/test/scoped_buf.h"
#include "crypto/test/crypto_test.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

using AeadDeathTest = AeadTest;

TEST_P(AeadTest, CheckDefinition) {
  EXPECT_NE(aead_, nullptr);
  EXPECT_NE(aead_get_state_size(aead_), 0U);
  EXPECT_NE(aead_get_key_size(aead_), 0U);
}

TEST_P(AeadDeathTest, SealInitWithBadState) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(aead_init(nullptr, state_.Get(), key_.Get(), kSend));
  EXPECT_ASSERT(aead_init(aead_, nullptr, key_.Get(), kSend));
  AEAD dummy;
  memcpy(&dummy, aead_, sizeof(*aead_));
  dummy.algorithm++;
  EXPECT_ASSERT(aead_init(&dummy, state_.Get(), key_.Get(), kSend));
  state_.Reset(aead_get_state_size(aead_) - 1);
  EXPECT_ASSERT(aead_init(aead_, state_.Get(), key_.Get(), kSend));
}

TEST_P(AeadDeathTest, SealInitWithBadKey) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(aead_init(aead_, state_.Get(), nullptr, kSend));
  ScopedBuf bad_key(key_.Len() - 1);
  EXPECT_ASSERT(aead_init(aead_, state_.Get(), bad_key.Get(), kSend));
}

TEST_P(AeadDeathTest, SealDataWithBadState) {
  ASSERT_TRUE(ReadNext());
  ASSERT_TRUE(aead_init(aead_, state_.Get(), key_.Get(), kSend));
  EXPECT_ASSERT(aead_data(nullptr, state_.Get(), nonce_.Get(),
                          additional_data_.Get(), plaintext_.Get(), kSend));
  EXPECT_ASSERT(aead_data(aead_, nullptr, nonce_.Get(), additional_data_.Get(),
                          plaintext_.Get(), kSend));
  state_.Reset(aead_get_state_size(aead_) - 1);
  EXPECT_ASSERT(aead_data(aead_, state_.Get(), nonce_.Get(),
                          additional_data_.Get(), plaintext_.Get(), kSend));
}

TEST_P(AeadDeathTest, SealDataWithBadNonce) {
  ASSERT_TRUE(ReadNext());
  ASSERT_TRUE(aead_init(aead_, state_.Get(), key_.Get(), kSend));
  EXPECT_ASSERT(aead_data(aead_, state_.Get(), nullptr, additional_data_.Get(),
                          plaintext_.Get(), kSend));
}

TEST_P(AeadDeathTest, SealDataWithBadData) {
  ASSERT_TRUE(ReadNext());
  ASSERT_TRUE(aead_init(aead_, state_.Get(), key_.Get(), kSend));
  EXPECT_ASSERT(aead_data(aead_, state_.Get(), nonce_.Get(),
                          additional_data_.Get(), nullptr, kSend));
  EXPECT_ASSERT(aead_data(aead_, state_.Get(), nonce_.Get(), nullptr,
                          plaintext_.Get(), kSend));
}

TEST_P(AeadTest, SealData) {
  while (ReadNext()) {
    EXPECT_TRUE(aead_init(aead_, state_.Get(), key_.Get(), kSend));
    EXPECT_TRUE(aead_data(aead_, state_.Get(), nonce_.Get(),
                          additional_data_.Get(), plaintext_.Get(), kSend));
    if (truncated_tag_) {
      buf_reset(plaintext_.Get(), 0);
      buf_produce(plaintext_.Get(), buf_ready(ciphertext_.Get()), nullptr);
    }
    EXPECT_PRED2(buf_equal, plaintext_.Get(), ciphertext_.Get());
  }
}

TEST_P(AeadDeathTest, OpenInitWithBadState) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(aead_init(nullptr, state_.Get(), key_.Get(), kRecv));
  EXPECT_ASSERT(aead_init(aead_, nullptr, key_.Get(), kRecv));
  state_.Reset(aead_get_state_size(aead_) - 1);
  EXPECT_ASSERT(aead_init(aead_, state_.Get(), key_.Get(), kRecv));
}

TEST_P(AeadDeathTest, OpenInitWithBadKey) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(aead_init(aead_, state_.Get(), nullptr, kRecv));
  ScopedBuf bad_key(key_.Len() - 1);
  EXPECT_ASSERT(aead_init(aead_, state_.Get(), bad_key.Get(), kRecv));
}

TEST_P(AeadDeathTest, OpenDataWithBadState) {
  ASSERT_TRUE(ReadNext());
  ASSERT_TRUE(aead_init(aead_, state_.Get(), key_.Get(), kRecv));
  EXPECT_ASSERT(aead_data(nullptr, state_.Get(), nonce_.Get(),
                          additional_data_.Get(), ciphertext_.Get(), kRecv));
  EXPECT_ASSERT(aead_data(aead_, nullptr, nonce_.Get(), additional_data_.Get(),
                          ciphertext_.Get(), kRecv));
  state_.Reset(aead_get_state_size(aead_) - 1);
  EXPECT_ASSERT(aead_data(aead_, state_.Get(), nonce_.Get(),
                          additional_data_.Get(), ciphertext_.Get(), kRecv));
}

TEST_P(AeadDeathTest, OpenDataWithBadNonce) {
  ASSERT_TRUE(ReadNext());
  ASSERT_TRUE(aead_init(aead_, state_.Get(), key_.Get(), kRecv));
  EXPECT_ASSERT(aead_data(aead_, state_.Get(), nullptr, additional_data_.Get(),
                          ciphertext_.Get(), kRecv));
}

TEST_P(AeadDeathTest, OpenDataWithBadData) {
  ASSERT_TRUE(ReadNext());
  ASSERT_TRUE(aead_init(aead_, state_.Get(), key_.Get(), kRecv));
  EXPECT_ASSERT(aead_data(aead_, state_.Get(), nonce_.Get(),
                          additional_data_.Get(), nullptr, kRecv));
  EXPECT_ASSERT(aead_data(aead_, state_.Get(), nonce_.Get(), nullptr,
                          ciphertext_.Get(), kRecv));
}

TEST_P(AeadTest, OpenData) {
  tls_error_source_t source;
  while (ReadNext()) {
    EXPECT_TRUE(aead_init(aead_, state_.Get(), key_.Get(), kRecv));
    if (truncated_tag_) {
      EXPECT_FALSE(aead_data(aead_, state_.Get(), nonce_.Get(),
                             additional_data_.Get(), ciphertext_.Get(), kRecv));
      EXPECT_TRUE(TLS_ERROR_get(&source, nullptr, nullptr, nullptr));
      EXPECT_EQ(source, kTlsErrCrypto);
      error_clear();
    } else {
      EXPECT_TRUE(aead_data(aead_, state_.Get(), nonce_.Get(),
                            additional_data_.Get(), ciphertext_.Get(), kRecv));
      EXPECT_PRED2(buf_equal, plaintext_.Get(), ciphertext_.Get());
    }
  }
}

INSTANTIATE_TEST_CASE_P(Crypto, AeadTest,
                        ::testing::ValuesIn(AeadTest::GetData()));
INSTANTIATE_TEST_CASE_P(Crypto, AeadDeathTest,
                        ::testing::Values(AeadDeathTest::GetData()[0]));

}  // namespace vapidssl
