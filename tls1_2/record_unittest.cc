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

#include "tls1_2/test/record_test.h"

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
#include "public/error.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"
#include "tls1_2/config.h"
#include "tls1_2/record.h"
#include "tls1_2/test/record_test.h"

namespace vapidssl {

using RecordDeathTest = RecordTest;

TEST_P(RecordDeathTest, InitWithBadParameters) {
  EXPECT_ASSERT(record_size(nullptr));
  // Null parameters
  EXPECT_ASSERT(record_init(nullptr, region_.Get(), kRecv, &rx_));
  EXPECT_ASSERT(record_init(GetConfig(), nullptr, kRecv, &rx_));
  EXPECT_ASSERT(record_init(GetConfig(), region_.Get(), kRecv, nullptr));
  // Insufficient memory
  region_.Reset(record_size(GetConfig()) - 1);
  EXPECT_TRUE(
      chunk_init(region_.Get(), kIoLoopback, kRecv, kNumFragments, &rx_));
  EXPECT_FALSE(record_init(GetConfig(), region_.Get(), kRecv, &rx_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  // Too few segments
  region_.Reset(record_size(GetConfig()) + chunk_size(1));
  EXPECT_TRUE(chunk_init(region_.Get(), kIoLoopback, kRecv, 1, &rx_));
  EXPECT_ASSERT(record_init(GetConfig(), region_.Get(), kRecv, &rx_));
}

TEST_P(RecordDeathTest, SetAeadWithBadParameters) {
  ResetRecords();
  ASSERT_TRUE(ReadNext());
  // Bad state
  EXPECT_ASSERT(record_set_ciphersuite(nullptr, region_.Get(), GetCiphersuite(),
                                       key_.Get(), nonce_.Get()));
  EXPECT_ASSERT(record_set_ciphersuite(&tx_, nullptr, GetCiphersuite(),
                                       key_.Get(), nonce_.Get()));
  BUF tmp = buf_init();
  EXPECT_TRUE(buf_malloc(region_.Get(),
                         region_.Len() - buf_allocated(region_.Get()), &tmp));
  EXPECT_FALSE(record_set_ciphersuite(&tx_, region_.Get(), GetCiphersuite(),
                                      key_.Get(), nonce_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  buf_free(&tmp);
  // Bad key
  EXPECT_ASSERT(record_set_ciphersuite(&tx_, region_.Get(), GetCiphersuite(),
                                       nullptr, nonce_.Get()));
  ScopedBuf bad_key(key_.Len() - 1);
  EXPECT_ASSERT(record_set_ciphersuite(&tx_, region_.Get(), GetCiphersuite(),
                                       bad_key.Get(), nonce_.Get()));
  // Bad nonce
  EXPECT_ASSERT(record_set_ciphersuite(&tx_, region_.Get(), GetCiphersuite(),
                                       key_.Get(), nullptr));
}

TEST_P(RecordTest, SetAndGetType) {
  ResetRecords();
  ASSERT_TRUE(ReadNext());
  // Initial type is alert
  EXPECT_EQ(record_get_type(&tx_), kHandshake);
  // Can change if no data pending
  EXPECT_TRUE(record_set_type(&tx_, kAlert));
  EXPECT_EQ(record_get_type(&tx_), kAlert);
  // Changing the type with pending data causes the record to be flushed
  BUF *text = chunk_get_text(&tx_);
  EXPECT_NE(text, nullptr);
  random_buf(text);
  io_mock_init(1, loopback_.Get(), loopback_.Get());
  EXPECT_FALSE(record_set_type(&tx_, kApplicationData));
  EXPECT_ERROR(kTlsErrPlatform, io_mock_retry());
}

TEST_P(RecordTest, SendAndRecvWithoutAead) {
  // Set up.
  BUF *tx_text = nullptr;
  BUF *rx_text = nullptr;
  // Send and receive chunks.
  while (ReadNext()) {
    ResetRecords();
    EXPECT_TRUE(record_set_type(&tx_, kHandshake));
    // Send data.
    tx_text = chunk_get_text(&tx_);
    buf_reset(tx_text, 0);
    buf_copy(plaintext_.Get(), tx_text);
    while (!chunk_send(&tx_)) {
      ASSERT_ERROR(kTlsErrPlatform, io_mock_retry());
    }
    // Send the data.
    rx_text = chunk_get_text(&rx_);
    while (!chunk_recv(&rx_)) {
      ASSERT_ERROR(kTlsErrPlatform, io_mock_retry());
    }
    EXPECT_PRED2(buf_equal, rx_text, plaintext_.Get());
  }
}

TEST_P(RecordTest, SendAndRecvWithAead) {
  // Set up.
  BUF *tx_text = nullptr;
  BUF *rx_text = nullptr;
  // Send and receive chunks.
  while (ReadNext()) {
    ResetRecords();
    EXPECT_TRUE(record_set_type(&tx_, kApplicationData));
    EXPECT_TRUE(record_set_ciphersuite(&tx_, region_.Get(), GetCiphersuite(),
                                       key_.Get(), nonce_.Get()));
    EXPECT_TRUE(record_set_ciphersuite(&rx_, region_.Get(), GetCiphersuite(),
                                       key_.Get(), nonce_.Get()));
    // Send data.
    tx_text = chunk_get_text(&tx_);
    buf_reset(tx_text, 0);
    buf_copy(plaintext_.Get(), tx_text);
    while (!chunk_send(&tx_)) {
      ASSERT_ERROR(kTlsErrPlatform, io_mock_retry());
    }
    // Send the data.
    rx_text = chunk_get_text(&rx_);
    while (!chunk_recv(&rx_)) {
      ASSERT_ERROR(kTlsErrPlatform, io_mock_retry());
    }
    EXPECT_PRED2(buf_equal, rx_text, plaintext_.Get());
  }
}

INSTANTIATE_TEST_CASE_P(Tls1_2, RecordTest,
                        ::testing::ValuesIn(RecordTest::GetData()));
INSTANTIATE_TEST_CASE_P(Tls1_2, RecordDeathTest,
                        ::testing::Values(RecordTest::GetData()[0]));

}  // namespace vapidssl
