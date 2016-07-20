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

#include "common/test/chunk_test.h"

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

using ChunkDeathTest = ChunkTest;

TEST_P(ChunkDeathTest, InitWithBadState) {
  EXPECT_ASSERT(
      chunk_init(nullptr, kIoLoopback, kSend, ChunkTest::kNumSegments, &tx_));
  EXPECT_ASSERT(chunk_init(region_.Get(), kIoLoopback, kSend,
                           ChunkTest::kNumSegments, nullptr));
  EXPECT_ASSERT(chunk_init(region_.Get(), kIoLoopback, kSend, 0, &tx_));
  BUF tmp = buf_init();
  EXPECT_TRUE(buf_malloc(region_.Get(),
                         region_.Len() - buf_allocated(region_.Get()), &tmp));
  EXPECT_FALSE(chunk_init(region_.Get(), kIoLoopback, kSend,
                          ChunkTest::kNumSegments, &tx_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  buf_free(&tmp);
}

TEST_P(ChunkDeathTest, RekeyWithBadState) {
  ASSERT_TRUE(ReadNext());
  EXPECT_TRUE(chunk_init(region_.Get(), kIoLoopback, kSend,
                         ChunkTest::kNumSegments, &tx_));
  EXPECT_ASSERT(chunk_set_aead(nullptr, region_.Get(), aead_, key_.Get(),
                               nonce_.Get(), nonce_.Len()));
  EXPECT_ASSERT(chunk_set_aead(&tx_, nullptr, aead_, key_.Get(), nonce_.Get(),
                               nonce_.Len()));
  BUF tmp = buf_init();
  EXPECT_TRUE(buf_malloc(region_.Get(),
                         region_.Len() - buf_allocated(region_.Get()), &tmp));
  EXPECT_FALSE(chunk_set_aead(&tx_, region_.Get(), aead_, key_.Get(),
                              nonce_.Get(), nonce_.Len()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  buf_free(&tmp);
}

TEST_P(ChunkDeathTest, RekeyWithBadKey) {
  ASSERT_TRUE(ReadNext());
  EXPECT_TRUE(chunk_init(region_.Get(), kIoLoopback, kSend,
                         ChunkTest::kNumSegments, &tx_));
  EXPECT_ASSERT(chunk_set_aead(&tx_, region_.Get(), aead_, nullptr,
                               nonce_.Get(), nonce_.Len()));
  ScopedBuf bad_key(key_.Len() - 1);
  EXPECT_ASSERT(chunk_set_aead(&tx_, region_.Get(), aead_, bad_key.Get(),
                               nonce_.Get(), nonce_.Len()));
}

TEST_P(ChunkDeathTest, RekeyWithBadNonce) {
  ASSERT_TRUE(ReadNext());
  EXPECT_TRUE(chunk_init(region_.Get(), kIoLoopback, kSend,
                         ChunkTest::kNumSegments, &tx_));
  EXPECT_ASSERT(
      chunk_set_aead(&tx_, region_.Get(), aead_, key_.Get(), nullptr, 0));
}

TEST_P(ChunkDeathTest, AddBadSegment) {
  EXPECT_TRUE(chunk_init(region_.Get(), kIoLoopback, kSend,
                         ChunkTest::kNumSegments, &tx_));
  // Check null and out of bounds.
  EXPECT_ASSERT(chunk_set_segment(nullptr, 0, 1, kEncrypted));
  EXPECT_ASSERT(
      chunk_set_segment(&tx_, ChunkTest::kNumSegments, 1, kEncrypted));
  // Check uninitialized and out-of-memory.
  EXPECT_FALSE(chunk_set_segment(&tx_, 0, 1, kEncrypted));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  EXPECT_TRUE(
      chunk_set_region(&tx_, region_.Get(), ChunkTest::kDataLen, kEncrypted));
  EXPECT_FALSE(chunk_set_segment(&tx_, 0, ChunkTest::kDataLen + 1, kEncrypted));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  EXPECT_TRUE(chunk_set_text(&tx_, 0, nullptr));
  EXPECT_ASSERT(chunk_set_segment(&tx_, 1, 1, kEncrypted));
}

TEST_P(ChunkDeathTest, RekeyMidChunk) {
  io_mock_init(1, loopback_.Get(), loopback_.Get());
  SetupPreKey(kSend);
  EXPECT_FALSE(chunk_send(&tx_));
  EXPECT_ERROR(kTlsErrPlatform, EAGAIN);
  EXPECT_ASSERT(chunk_set_aead(&tx_, region_.Get(), aead_, key_.Get(),
                               nonce_.Get(), nonce_.Len()));
}
TEST_P(ChunkDeathTest, IOWithNoSegments) {
  // Check that |chunk_data| asserts if called right after |chunk_init|.
  EXPECT_TRUE(chunk_init(region_.Get(), kIoLoopback, kSend,
                         ChunkTest::kNumSegments, &tx_));
  EXPECT_ASSERT(chunk_send(&tx_));
}

TEST_P(ChunkDeathTest, ReceiveWithUnconsumedData) {
  SetupPreKey(kRecv);
  SetupPreKey(kSend);
  // Send two records.
  BUF *tx_text = chunk_get_text(&tx_);
  buf_reset(tx_text, 0);
  random_buf(tx_text);
  EXPECT_TRUE(chunk_send(&tx_));
  buf_reset(tx_text, 0);
  random_buf(tx_text);
  EXPECT_TRUE(chunk_send(&tx_));
  // Get the first record, then get the second without consuming the data.
  EXPECT_TRUE(chunk_recv(&rx_));
  EXPECT_GT(buf_ready(chunk_get_text(&rx_)), 0U);
  EXPECT_ASSERT(chunk_recv(&rx_));
}

TEST_P(ChunkTest, ReceiveManyEmptyChunks) {
  // Skip ReadNext, so plaintext_ is empty.
  SetupPreKey(kSend);
  SetupPreKey(kRecv);
  for (size_t i = 0; i < kMaxEmptyChunks; ++i) {
    EXPECT_TRUE(chunk_send(&tx_));
    EXPECT_TRUE(chunk_recv(&rx_));
  }
  EXPECT_TRUE(chunk_send(&tx_));
  EXPECT_FALSE(chunk_recv(&rx_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrTooManyEmptyChunks);
}

TEST_P(ChunkTest, SendAndRecv) {
  // Set up.
  io_mock_init(sizeof(uint32_t), loopback_.Get(), loopback_.Get());
  BUF *tx_text = nullptr;
  BUF *rx_text = nullptr;
  size_t tag_size = 0;
  const AEAD *aead = NULL;
  // Send and receive chunks.
  while (ReadNext()) {
    SetupPostKey(kSend);
    // Clip plaintext to fit in chunk with an authentication tag.
    aead = chunk_get_aead(&tx_);
    tag_size = 0;
    if (aead) {
      tag_size = aead_get_tag_size(aead);
    }
    // Send data.
    tx_text = chunk_get_text(&tx_);
    buf_reset(tx_text, 0);
    buf_copy(GetPlaintext(kDataLen - tag_size), tx_text);
    while (!chunk_send(&tx_)) {
      if (!TLS_ERROR_test(kTlsErrPlatform, io_mock_retry())) {
        ADD_FAILURE();
        break;
      }
      error_clear();
    }
    // Send the data.
    SetupPostKey(kRecv);
    rx_text = chunk_get_text(&rx_);
    while (!chunk_recv(&rx_)) {
      if (!TLS_ERROR_test(kTlsErrPlatform, io_mock_retry())) {
        ADD_FAILURE();
        break;
      }
      error_clear();
    }
    EXPECT_PRED2(buf_equal, rx_text, GetPlaintext(kDataLen - tag_size));
  }
}

INSTANTIATE_TEST_CASE_P(Common, ChunkTest,
                        ::testing::ValuesIn(AeadTest::GetData()));
INSTANTIATE_TEST_CASE_P(Common, ChunkDeathTest,
                        ::testing::Values(AeadTest::GetData()[0]));

}  // namespace vapidssl
