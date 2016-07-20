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
#include "common/test/chunk_test.h"
#include "public/error.h"
#include "public/tls.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

const size_t ChunkTest::kDataLen = 80;
const size_t ChunkTest::kNumSegments = 5;
const size_t ChunkTest::kRandomLen = 3;

namespace {

tls_result_t ValidateRecv(CHUNK *chunk) {
  BUF *magic = chunk_get_segment(chunk, 1);
  uint32_t val = 0;
  buf_get_val(magic, sizeof(uint32_t), &val);
  if (val != 0xDEADBEEF) {
    return kTlsFailure;
  }
  return kTlsSuccess;
}

tls_result_t PreparePlainSend(CHUNK *chunk) {
  BUF *data_len = chunk_get_segment(chunk, 0);
  BUF *random = chunk_get_segment(chunk, 1);
  BUF *data = chunk_get_segment(chunk, 2);
  buf_reset(data_len, 0);
  buf_put_val(data_len, sizeof(uint32_t), (uint32_t)buf_ready(data));
  buf_reset(random, 0);
  random_buf(random);
  return kTlsSuccess;
}

tls_result_t PrepareAeadSend(CHUNK *chunk) {
  BUF *data_len = chunk_get_segment(chunk, 0);
  BUF *magic = chunk_get_segment(chunk, 1);
  BUF *random = chunk_get_segment(chunk, 2);
  BUF *data = chunk_get_segment(chunk, 3);
  BUF *seqnum = chunk_get_segment(chunk, 4);
  const AEAD *aead = chunk_get_aead(chunk);
  size_t size = buf_ready(data) + aead_get_tag_size(aead);
  buf_reset(data_len, 0);
  buf_put_val(data_len, sizeof(uint32_t), (uint32_t)size);
  buf_reset(magic, 0);
  buf_put_val(magic, sizeof(uint32_t), 0xDEADBEEF);
  buf_reset(random, 0);
  random_buf(random);
  buf_reset(seqnum, 0);
  buf_produce(seqnum, buf_size(seqnum), nullptr);
  buf_counter(seqnum);
  return kTlsSuccess;
}

tls_result_t UpdateNonce(CHUNK *chunk) {
  BUF *nonce = chunk_get_nonce(chunk);
  assert(nonce);
  buf_reset(nonce, 0);
  buf_produce(nonce, buf_size(nonce), nullptr);
  return kTlsSuccess;
  //  return buf_counter(nonce);
}

tls_result_t TextSize(CHUNK *chunk, size_t *out) {
  BUF *header = chunk_get_segment(chunk, 0);
  uint32_t size = 0;
  if (!buf_get_val(header, sizeof(uint32_t), &size)) {
    return kTlsFailure;
  }
  buf_reset(header, 0);
  buf_produce(header, sizeof(uint32_t), nullptr);
  *out = (uint32_t)size;
  return kTlsSuccess;
}

}  // namespace

void ChunkTest::SetUp() {
  AeadTest::SetUp();
  region_.Reset(0x1000);
  loopback_.Reset(0x1000);
  io_mock_init(0, loopback_.Get(), loopback_.Get());
}

void ChunkTest::SetupPreKey(direction_t dir) {
  region_.Reset(0x1000);
  CHUNK *chunk = (dir == kRecv ? &rx_ : &tx_);
  EXPECT_TRUE(chunk_init(region_.Get(), kIoLoopback, dir, kNumSegments, chunk));
  if (dir == kSend) {
    chunk_set_processing(chunk, PreparePlainSend, NULL, NULL);
  }
  // Set up authenticated data segments.
  EXPECT_TRUE(
      chunk_set_region(chunk, region_.Get(), sizeof(uint32_t), kAuthenticated));
  EXPECT_TRUE(chunk_set_segment(chunk, 0, sizeof(uint32_t), kAuthenticated));
  // Set up unprotected data segments.
  EXPECT_TRUE(chunk_set_region(chunk, region_.Get(), kRandomLen, kUnprotected));
  EXPECT_TRUE(chunk_set_segment(chunk, 1, kRandomLen, kUnprotected));
  // Set up encrypted data segments.
  EXPECT_TRUE(chunk_set_region(chunk, region_.Get(), kDataLen, kEncrypted));
  EXPECT_TRUE(chunk_set_text(chunk, 2, TextSize));
}

void ChunkTest::SetupPostKey(direction_t dir) {
  region_.Reset(0x1000);
  CHUNK *chunk = (dir == kRecv ? &rx_ : &tx_);
  EXPECT_TRUE(chunk_init(region_.Get(), kIoLoopback, dir, kNumSegments, chunk));
  if (dir == kRecv) {
    chunk_set_processing(chunk, NULL, UpdateNonce, ValidateRecv);
  } else {
    chunk_set_processing(chunk, PrepareAeadSend, UpdateNonce, NULL);
  }
  // Reset the key and nonce and set the AEAD.
  buf_reset(key_.Get(), 0);
  buf_produce(key_.Get(), key_.Len(), nullptr);
  buf_reset(nonce_.Get(), 0);
  buf_produce(nonce_.Get(), nonce_.Len(), nullptr);
  EXPECT_TRUE(chunk_set_aead(chunk, region_.Get(), aead_, key_.Get(),
                             nonce_.Get(), nonce_.Len()));
  // Set up unprotected data segments.
  EXPECT_TRUE(chunk_set_region(chunk, region_.Get(), kRandomLen, kUnprotected));
  EXPECT_TRUE(chunk_set_segment(chunk, 2, kRandomLen, kUnprotected));
  // Set up authenticated data segments.
  EXPECT_TRUE(chunk_set_region(chunk, region_.Get(), sizeof(uint32_t) * 3,
                               kAuthenticated));
  EXPECT_TRUE(
      chunk_set_segment(chunk, 4, sizeof(uint32_t) * 2, kAuthenticated));
  EXPECT_TRUE(chunk_set_segment(chunk, 0, sizeof(uint32_t), kAuthenticated));
  // Set up encrypted data segments.
  EXPECT_TRUE(chunk_set_region(chunk, region_.Get(),
                               sizeof(uint32_t) + kDataLen, kEncrypted));
  EXPECT_TRUE(chunk_set_segment(chunk, 1, sizeof(uint32_t), kEncrypted));
  EXPECT_TRUE(chunk_set_text(chunk, 3, TextSize));
}

bool ChunkTest::ReadNext() {
  // Since we'll be using this as data to send, skip test data with empty
  // plaintexts.
  while (AeadTest::ReadNext()) {
    if (plaintext_.Len() != 0) {
      return true;
    }
  }
  return false;
}

BUF *ChunkTest::GetPlaintext(size_t max) {
  size_t size = plaintext_.Len();
  if (max != 0 && max < size) {
    size = max;
  }
  buf_reset(plaintext_.Get(), 0);
  buf_produce(plaintext_.Get(), size, nullptr);
  return plaintext_.Get();
}

}  // namespace vapidssl
