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

#include "common/test/stream_helper.h"

#include <stddef.h>

#include "base/platform/test/io_mock.h"
#include "base/test/scoped_buf.h"
#include "base/types.h"
#include "common/chunk.h"
#include "crypto/hash.h"
#include "crypto/test/hash_test.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

tls_result_t StreamHelper::SetSize(CHUNK *chunk) {
  BUF *buf = chunk_get_segment(chunk, 0);
  BUF *text = chunk_get_text(chunk);
  buf_reset(buf, 0);
  buf_put_val(buf, 4, (uint32_t)buf_ready(text));
  return kTlsSuccess;
}

tls_result_t StreamHelper::GetSize(CHUNK *chunk, size_t *out) {
  BUF *buf = chunk_get_segment(chunk, 0);
  uint32_t len = 0;
  buf_reset(buf, 0);
  buf_produce(buf, 4, NULL);
  if (!buf_get_val(buf, 4, &len)) {
    return kTlsFailure;
  }
  *out = len;
  return kTlsSuccess;
}

StreamHelper::StreamHelper()
    : mtu_(0),
      max_nesting_(4),
      max_pending_(8),
      data_len_(0x100),
      region_(),
      loopback_(),
      rx_(),
      tx_(),
      hashes_() {}

STREAM *StreamHelper::Get(direction_t direction) {
  return (direction == kRecv ? &rx_ : &tx_);
}

void StreamHelper::SetMaxNesting(size_t max_nesting) {
  max_nesting_ = max_nesting;
  Reset();
}

void StreamHelper::SetDataLen(size_t data_len) {
  data_len_ = data_len;
  Reset();
}

void StreamHelper::SetMtu(size_t mtu) {
  mtu_ = mtu;
  Reset();
}

void StreamHelper::SetMaxPending(size_t max_pending) {
  max_pending_ = max_pending;
  Reset();
}

void StreamHelper::Reset() {
  // Free memory used by streams. The easiest way to do this is to nuke the
  // region they were allocated from.
  size_t size = stream_size(2, max_nesting_);
  size += sizeof(uint32_t);
  size += data_len_;
  size *= 2;
  size += LIST_SIZE(STREAM_HASH, VAPIDSSL_HASHES + 1);
  region_.Reset(size);
  loopback_.Reset((sizeof(uint32_t) + data_len_) * max_pending_);
  io_mock_init(mtu_, loopback_.Get(), loopback_.Get());
  // Initialize both streams.
  STREAM *streams[2] = {&rx_, &tx_};
  direction_t dirs[2] = {kRecv, kSend};
  CHUNK *chunk = nullptr;
  EXPECT_TRUE(
      LIST_NEW(STREAM_HASH, region_.Get(), VAPIDSSL_HASHES + 1, &hashes_));
  for (size_t i = 0; i < 2; ++i) {
    EXPECT_TRUE(stream_init(region_.Get(), kIoLoopback, dirs[i], 2,
                            max_nesting_, streams[i]));
    stream_set_hashes(streams[i], &hashes_);
    chunk = stream_get_chunk(streams[i]);
    EXPECT_TRUE(chunk_set_region(chunk, region_.Get(), sizeof(uint32_t),
                                 kAuthenticated));
    EXPECT_TRUE(chunk_set_segment(chunk, 0, sizeof(uint32_t), kAuthenticated));
    EXPECT_TRUE(chunk_set_region(chunk, region_.Get(), data_len_, kEncrypted));
    EXPECT_TRUE(chunk_set_text(chunk, 1, GetSize));
    if (dirs[i] == kSend) {
      chunk_set_processing(chunk, NULL, SetSize, NULL);
    }
  }
}

void StreamHelper::Flush(void) {
  while (!stream_flush(&tx_)) {
    ASSERT_ERROR(kTlsErrPlatform, io_mock_retry());
  }
}

}  // namespace vapidssl
