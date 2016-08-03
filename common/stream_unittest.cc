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

#include "common/stream.h"
#include "common/stream_internal.h"

#include "base/buf.h"
#include "base/error.h"
#include "base/platform/random.h"
#include "base/platform/test/io_mock.h"
#include "base/test/scoped_buf.h"
#include "common/chunk.h"
#include "common/test/stream_helper.h"
#include "crypto/hash.h"
#include "crypto/test/hash_test.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

class StreamTest : public HashTest {
 public:
  ~StreamTest() override = default;
  StreamTest &operator=(const StreamTest &) = delete;
  StreamTest(const StreamTest &) = delete;

 protected:
  StreamTest() : recv_(nullptr), send_(nullptr) {}

  // SetUp overrides the parent class to set up sending and receiving streams.
  void SetUp() override {
    HashTest::SetUp();
    region_.Reset(0x1000);
    recv_ = stream_helper_.GetStream(kIoLoopback, kRecv);
    send_ = stream_helper_.GetStream(kIoLoopback, kSend);
  }

  // recv_ is the stream on which data can be received.
  STREAM *recv_;
  // recv_ is the stream on which data can be sent.
  STREAM *send_;
  // region_ is the memory used during testing.
  ScopedBuf region_;
  // stream_helper_ manages the data being sent and received.
  StreamHelper stream_helper_;
  // hashes_ is the list of rolling hashes over the data.
  LIST hashes_;
};

using StreamDeathTest = StreamTest;

TEST_P(StreamDeathTest, InitStreamWithBadParams) {
  // Check null parameters.
  EXPECT_ASSERT(stream_init(nullptr, kIoLoopback, kSend, 0xFF, 0xFF, send_));
  EXPECT_ASSERT(
      stream_init(region_.Get(), kIoLoopback, kSend, 0xFF, 0xFF, nullptr));
  // Check insufficient memory.
  size_t size = stream_size(0xFF, 0xFF);
  region_.Reset(size - 1);
  EXPECT_FALSE(
      stream_init(region_.Get(), kIoLoopback, kSend, 0xFF, 0xFF, send_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  // Check minimal and maximal sizes.
  region_.Reset(size);
  EXPECT_TRUE(
      stream_init(region_.Get(), kIoLoopback, kSend, 0xFF, 0xFF, send_));
  size = stream_size(1, 0);
  region_.Reset(size);
  EXPECT_TRUE(stream_init(region_.Get(), kIoLoopback, kSend, 1, 0, send_));
}

TEST_P(StreamDeathTest, AddHashesWithBadParams) {
  ScopedBuf empty;
  region_.Reset(stream_size(1, 0) +
                LIST_SIZE(STREAM_HASH, VAPIDSSL_HASHES + 1));
  EXPECT_TRUE(stream_init(region_.Get(), kIoLoopback, kSend, 1, 0, send_));
  // Check stream with no list
  EXPECT_ASSERT(stream_add_hash(send_, region_.Get(), hash_));
  EXPECT_TRUE(
      LIST_NEW(STREAM_HASH, region_.Get(), VAPIDSSL_HASHES + 1, &hashes_));
  stream_set_hashes(send_, &hashes_);
  // Check null parameters for 1 hash.
  EXPECT_ASSERT(stream_add_hashes(send_, nullptr));
  EXPECT_ASSERT(stream_add_hash(send_, region_.Get(), nullptr));
  EXPECT_ASSERT(stream_add_hash(nullptr, region_.Get(), hash_));
  // Check insufficient memory for 1 hashes.
  EXPECT_FALSE(stream_add_hash(send_, empty.Get(), hash_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  // Check null parameters for 1 hash.
  EXPECT_ASSERT(stream_add_hashes(send_, nullptr));
  EXPECT_ASSERT(stream_add_hashes(nullptr, region_.Get()));
  // Check insufficient memory for N hashes.
  EXPECT_FALSE(stream_add_hashes(send_, region_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
}

TEST_P(StreamDeathTest, AddTooManyHashes) {
  size_t size = stream_size(1, 0);
  size += hash_get_state_size(hash_);
  size += hash_get_state_size(hash_);
  size += hash_get_state_size(hash_);
  size += LIST_SIZE(STREAM_HASH, VAPIDSSL_HASHES + 1);
  EXPECT_TRUE(stream_init(region_.Get(), kIoLoopback, kSend, 1, 0, send_));
  EXPECT_TRUE(
      LIST_NEW(STREAM_HASH, region_.Get(), VAPIDSSL_HASHES + 1, &hashes_));
  stream_set_hashes(send_, &hashes_);
  EXPECT_TRUE(stream_add_hash(send_, region_.Get(), hash_));
  EXPECT_TRUE(stream_add_hash(send_, region_.Get(), hash_));
  EXPECT_TRUE(stream_add_hash(send_, region_.Get(), hash_));
  EXPECT_FALSE(stream_add_hash(send_, region_.Get(), hash_));
}

TEST_P(StreamDeathTest, BadHashSelection) {
  stream_helper_.Reset();
  // Only add a single explicit hash.
  EXPECT_TRUE(stream_add_hash(send_, region_.Get(), hash_));
  EXPECT_ASSERT(stream_select_hash(send_, nullptr));
  EXPECT_ASSERT(stream_select_hash(send_, hash_));
}

TEST_P(StreamDeathTest, BadHashDigest) {
  stream_helper_.Reset();
  ScopedBuf empty;
  // Check null parameters.
  EXPECT_ASSERT(stream_clone_digest(send_, nullptr, out_.Get()));
  EXPECT_ASSERT(stream_clone_digest(nullptr, region_.Get(), out_.Get()));
  EXPECT_ASSERT(stream_clone_digest(send_, empty.Get(), nullptr));
  EXPECT_ASSERT(stream_final_digest(nullptr, out_.Get()));
  EXPECT_ASSERT(stream_final_digest(send_, nullptr));
  // Check digest request without adding a hash.
  EXPECT_ASSERT(stream_clone_digest(send_, empty.Get(), out_.Get()));
  EXPECT_ASSERT(stream_final_digest(send_, out_.Get()));
  // Check final without select for multiple hashes.
  EXPECT_TRUE(stream_add_hashes(send_, region_.Get()));
  EXPECT_ASSERT(stream_final_digest(send_, out_.Get()));
  // Check insufficient memory.
  stream_select_hash(send_, hash_);
  EXPECT_FALSE(stream_clone_digest(send_, empty.Get(), out_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  out_.Reset(hash_get_output_size(hash_) - 1);
  EXPECT_ASSERT(stream_clone_digest(send_, region_.Get(), out_.Get()));
  EXPECT_ASSERT(stream_final_digest(send_, out_.Get()));
}

TEST_P(StreamDeathTest, SetBadNesting) {
  size_t size = stream_size(1, 1);
  region_.Reset(size);
  EXPECT_TRUE(stream_init(region_.Get(), kIoLoopback, kSend, 1, 1, send_));
  // Check null parameters.
  EXPECT_ASSERT(stream_nested_begin(nullptr, 32));
  // Check too deeply nested.
  EXPECT_TRUE(stream_nested_begin(send_, 32));
  EXPECT_FALSE(stream_nested_begin(send_, 16));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfBounds);
}

TEST_P(StreamDeathTest, CheckNesting) {
  stream_helper_.SetNesting(kRecv, 5);
  stream_helper_.Reset();
  uint8_t u8 = 0;
  uint16_t u16 = 0;
  // Start with two levels of nesting.
  EXPECT_TRUE(stream_send_u16(send_, 0xdead));
  EXPECT_TRUE(stream_send_u16(send_, 0xbeef));
  EXPECT_TRUE(stream_flush(send_));
  EXPECT_TRUE(stream_nested_begin(recv_, 4));
  EXPECT_TRUE(stream_nested_begin(recv_, 2));
  // Check reading across a nesting boundary.
  EXPECT_FALSE(stream_nested_finish(recv_));
  EXPECT_TRUE(stream_recv_u8(recv_, &u8));
  EXPECT_FALSE(stream_recv_u16(recv_, &u16));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrLengthMismatch);
  // Check nesting-aligned read.
  stream_helper_.Reset();
  EXPECT_TRUE(stream_send_u16(send_, 0xdead));
  EXPECT_TRUE(stream_send_u16(send_, 0xbeef));
  EXPECT_TRUE(stream_flush(send_));
  EXPECT_TRUE(stream_nested_begin(recv_, 4));
  EXPECT_TRUE(stream_nested_begin(recv_, 2));
  // Read the inner level of nesting.
  EXPECT_TRUE(stream_recv_u8(recv_, &u8));
  EXPECT_FALSE(stream_nested_finish(recv_));
  EXPECT_TRUE(stream_recv_u8(recv_, &u8));
  EXPECT_TRUE(stream_nested_finish(recv_));
  // Read the outer level of nesting.
  EXPECT_FALSE(stream_nested_finish(recv_));
  EXPECT_TRUE(stream_recv_u8(recv_, &u8));
  EXPECT_FALSE(stream_nested_finish(recv_));
  EXPECT_TRUE(stream_recv_u8(recv_, &u8));
  EXPECT_TRUE(stream_nested_finish(recv_));
  // Check for error when we aren't nested.
  EXPECT_ASSERT(stream_nested_finish(recv_));
}

TEST_P(StreamDeathTest, SendAndRecvInts) {
  stream_helper_.Reset();
  uint8_t u8 = 0xFF;
  uint16_t u16 = 0xFFFF;
  uint24_t u24 = 0xFFFFFF;
  uint32_t u32 = 0xFFFFFFFF;
  // Check null send parameters.
  EXPECT_ASSERT(stream_send_u8(nullptr, 0xA1));
  EXPECT_ASSERT(stream_send_u16(nullptr, 0xB1B2));
  EXPECT_ASSERT(stream_send_u24(nullptr, 0xC1C2C3));
  // Send various integers.
  EXPECT_TRUE(stream_send_u8(send_, 0xA1));
  EXPECT_TRUE(stream_send_u8(send_, 0x00));
  EXPECT_TRUE(stream_send_u16(send_, 0xB1B2));
  EXPECT_TRUE(stream_send_u16(send_, 0x0000));
  EXPECT_TRUE(stream_send_u24(send_, 0xC1C2C3));
  EXPECT_TRUE(stream_send_u24(send_, 0x000000));
  EXPECT_TRUE(stream_send_u16(send_, 0x0000));
  EXPECT_TRUE(stream_send_u16(send_, 0x0000));
  EXPECT_TRUE(stream_send_u16(send_, 0xD1D2));
  EXPECT_TRUE(stream_send_u16(send_, 0xD3D4));
  EXPECT_TRUE(stream_flush(send_));
  // Check null send parameters.
  EXPECT_ASSERT(stream_recv_u32(nullptr, &u32));
  EXPECT_ASSERT(stream_recv_u24(nullptr, &u24));
  EXPECT_ASSERT(stream_recv_u16(nullptr, &u16));
  EXPECT_ASSERT(stream_recv_u8(nullptr, &u8));
  EXPECT_ASSERT(stream_recv_u32(recv_, nullptr));
  EXPECT_ASSERT(stream_recv_u24(recv_, nullptr));
  EXPECT_ASSERT(stream_recv_u16(recv_, nullptr));
  EXPECT_ASSERT(stream_recv_u8(recv_, nullptr));
  // Receive various integers and check byte ordering.
  EXPECT_TRUE(stream_recv_u32(recv_, &u32));
  EXPECT_EQ(u32, 0xA100B1B2U);
  EXPECT_TRUE(stream_recv_u24(recv_, &u24));
  EXPECT_EQ(u24, 0x0000C1U);
  EXPECT_TRUE(stream_recv_u16(recv_, &u16));
  EXPECT_EQ(u16, 0xC2C3U);
  EXPECT_TRUE(stream_recv_u8(recv_, &u8));
  EXPECT_EQ(u8, 0x00U);
  EXPECT_TRUE(stream_recv_u32(recv_, &u32));
  EXPECT_EQ(u32, 0x00000000U);
  EXPECT_TRUE(stream_recv_u24(recv_, &u24));
  EXPECT_EQ(u24, 0x0000D1U);
  EXPECT_TRUE(stream_recv_u16(recv_, &u16));
  EXPECT_EQ(u16, 0xD2D3U);
  EXPECT_TRUE(stream_recv_u8(recv_, &u8));
  EXPECT_EQ(u8, 0xD4U);
}

TEST_P(StreamDeathTest, SendAndRecvBufs) {
  stream_helper_.SetPending(4);
  stream_helper_.Reset();
  ScopedBuf empty;
  ScopedBuf tmp(0x100);
  BUF recd = buf_init();
  BUF *sent = tmp.Get();
  random_buf(sent);
  // Check null and invalid send parameters.
  EXPECT_ASSERT(stream_send_buf(nullptr, 0, sent));
  EXPECT_ASSERT(stream_send_buf(send_, 4, sent));
  EXPECT_ASSERT(stream_send_buf(send_, 0, nullptr));
  EXPECT_TRUE(stream_send_buf(send_, 3, sent));
  // Check null and invalid recv parameters.
  EXPECT_ASSERT(stream_recv_buf(nullptr, region_.Get(), 0, &recd));
  EXPECT_ASSERT(stream_recv_buf(recv_, nullptr, 3, &recd));
  EXPECT_ASSERT(stream_recv_buf(recv_, region_.Get(), 4, &recd));
  EXPECT_ASSERT(stream_recv_buf(recv_, region_.Get(), 0, nullptr));
  // Check insufficient memory on receive.
  buf_reset(sent, 0);
  random_buf(sent);
  EXPECT_TRUE(stream_send_buf(send_, 3, sent));
  EXPECT_FALSE(stream_recv_buf(recv_, empty.Get(), 3, &recd));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  // Send buffer with and without length.
  stream_helper_.Reset();
  buf_reset(sent, 0);
  buf_produce(sent, buf_size(sent), nullptr);
  EXPECT_TRUE(stream_send_buf(send_, 3, sent));
  buf_reset(sent, 0);
  buf_produce(sent, buf_size(sent), nullptr);
  EXPECT_TRUE(stream_send_buf(send_, 0, sent));
  buf_reset(sent, 0);
  buf_produce(sent, buf_size(sent), nullptr);
  EXPECT_TRUE(stream_flush(send_));
  // Receive buffer with and without length.
  EXPECT_TRUE(stream_recv_buf(recv_, region_.Get(), 3, &recd));
  EXPECT_PRED2(buf_equal, sent, &recd);
  buf_reset(&recd, 0);
  EXPECT_TRUE(stream_recv_buf(recv_, nullptr, 0, &recd));
  EXPECT_PRED2(buf_equal, sent, &recd);
}

TEST_P(StreamTest, SendAndRecvFragmented) {
  stream_helper_.SetMtu(1);
  stream_helper_.Reset();
  ScopedBuf recd(hash_get_output_size(hash_));
  // Hashes are shared.  Add it to one, but enable it on the other.
  EXPECT_TRUE(stream_add_hash(send_, region_.Get(), hash_));
  stream_set_hashing(recv_, kOn);
  while (ReadNext()) {
    // See test/generate_hash_data.rb.  Each iteration's |digest_| is the digest
    // of all previous iterations digests.
    buf_reset(out_.Get(), 0);
    EXPECT_TRUE(stream_clone_digest(recv_, region_.Get(), out_.Get()));
    EXPECT_PRED2(buf_equal, out_.Get(), digest_.Get());
    buf_reset(out_.Get(), 0);
    EXPECT_TRUE(stream_clone_digest(send_, region_.Get(), out_.Get()));
    EXPECT_PRED2(buf_equal, out_.Get(), digest_.Get());
    // Loop while platform indicates I/O is incomplete.
    while (!stream_send_buf(send_, 0, out_.Get())) {
      EXPECT_ERROR(kTlsErrPlatform, io_mock_retry());
    }
    stream_helper_.Flush();
    buf_reset(recd.Get(), 0);
    while (!stream_recv_buf(recv_, nullptr, 0, recd.Get())) {
      EXPECT_ERROR(kTlsErrPlatform, io_mock_retry());
    }
    EXPECT_PRED2(buf_equal, digest_.Get(), recd.Get());
  }
}

INSTANTIATE_TEST_CASE_P(Common, StreamTest,
                        ::testing::ValuesIn(HashTest::GetData()));
INSTANTIATE_TEST_CASE_P(Common, StreamDeathTest,
                        ::testing::Values(HashTest::GetData()[0]));

}  // namespace vapidssl
