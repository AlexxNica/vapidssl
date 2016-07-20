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

#include "crypto/hash.h"
#include "crypto/hash_internal.h"
#include "crypto/test/hash_test.h"

#include "base/buf.h"
#include "base/platform/test/platform_helper.h"
#include "base/test/scoped_buf.h"
#include "crypto/test/crypto_test.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

using HashDeathTest = HashTest;

TEST_P(HashTest, CheckDefinition) {
  EXPECT_NE(hash_, nullptr);
  EXPECT_NE(hash_get_state_size(hash_), 0U);
  EXPECT_NE(hash_get_block_size(hash_), 0U);
  EXPECT_NE(hash_get_output_size(hash_), 0U);
  // Ensure we can iterate over the hashes.
  size_t n = 0;
  for (const HASH *hash = hash_next(NULL); hash; hash = hash_next(hash)) {
    ++n;
  }
  EXPECT_LE(n, (size_t)VAPIDSSL_HASHES);
}

TEST_P(HashDeathTest, InitDigestWithBadState) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(hash_init(nullptr, state_.Get()));
  EXPECT_ASSERT(hash_init(hash_, nullptr));
  HASH dummy;
  memcpy(&dummy, hash_, sizeof(*hash_));
  dummy.algorithm++;
  EXPECT_ASSERT(hash_init(&dummy, state_.Get()));
  state_.Reset(hash_get_state_size(hash_) - 1);
  EXPECT_ASSERT(hash_init(hash_, state_.Get()));
}

TEST_P(HashDeathTest, UpdateDigestWithBadState) {
  ASSERT_TRUE(ReadNext());
  hash_init(hash_, state_.Get());
  EXPECT_ASSERT(hash_update(nullptr, state_.Get(), in_.Get()));
  EXPECT_ASSERT(hash_update(hash_, nullptr, in_.Get()));
  HASH dummy;
  memcpy(&dummy, hash_, sizeof(*hash_));
  dummy.algorithm++;
  EXPECT_ASSERT(hash_update(&dummy, state_.Get(), in_.Get()));
  state_.Reset(hash_get_state_size(hash_) - 1);
  EXPECT_ASSERT(hash_update(hash_, state_.Get(), in_.Get()));
}

TEST_P(HashDeathTest, UpdateDigestWithBadData) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(hash_update(hash_, state_.Get(), nullptr));
}

TEST_P(HashDeathTest, FinalizeDigestWithBadState) {
  ASSERT_TRUE(ReadNext());
  hash_init(hash_, state_.Get());
  hash_update(hash_, state_.Get(), in_.Get());
  EXPECT_ASSERT(hash_final(nullptr, state_.Get(), out_.Get()));
  EXPECT_ASSERT(hash_final(hash_, nullptr, out_.Get()));
  HASH dummy;
  memcpy(&dummy, hash_, sizeof(*hash_));
  dummy.algorithm++;
  EXPECT_ASSERT(hash_final(&dummy, state_.Get(), out_.Get()));
  state_.Reset(hash_get_state_size(hash_) - 1);
  EXPECT_ASSERT(hash_final(hash_, state_.Get(), out_.Get()));
}

TEST_P(HashDeathTest, FinalizeDigestWithBadOutput) {
  ASSERT_TRUE(ReadNext());
  hash_init(hash_, state_.Get());
  hash_update(hash_, state_.Get(), in_.Get());
  EXPECT_ASSERT(hash_final(hash_, state_.Get(), nullptr));
  out_.Reset(hash_get_output_size(hash_) - 1);
  EXPECT_ASSERT(hash_final(hash_, state_.Get(), out_.Get()));
}

TEST_P(HashTest, GetDigestWithoutUpdate) {
  buf_reset(out_.Get(), 0);
  hash_init(hash_, state_.Get());
  hash_final(hash_, state_.Get(), out_.Get());
  // If the test data file includes a case with empty input, check that the
  // digests match
  while (ReadNext()) {
    if (buf_ready(in_.Get()) == 0) {
      EXPECT_PRED2(buf_equal, digest_.Get(), out_.Get());
    }
  }
}

TEST_P(HashTest, GetDigestSingleShot) {
  while (ReadNext()) {
    buf_reset(out_.Get(), 0);
    hash_init(hash_, state_.Get());
    hash_update(hash_, state_.Get(), in_.Get());
    hash_final(hash_, state_.Get(), out_.Get());
    EXPECT_PRED2(buf_equal, digest_.Get(), out_.Get());
  }
}

TEST_P(HashTest, GetDigestMultiShot) {
  while (ReadNext()) {
    hash_init(hash_, state_.Get());
    buf_reset(in_.Get(), 0);
    buf_reset(out_.Get(), 0);
    while (buf_available(in_.Get())) {
      buf_produce(in_.Get(), 1, nullptr);
      hash_update(hash_, state_.Get(), in_.Get());
      buf_consume(in_.Get(), 1, nullptr);
    }
    hash_final(hash_, state_.Get(), out_.Get());
    EXPECT_PRED2(buf_equal, digest_.Get(), out_.Get());
  }
}

INSTANTIATE_TEST_CASE_P(Crypto, HashTest,
                        ::testing::ValuesIn(HashTest::GetData()));
INSTANTIATE_TEST_CASE_P(Crypto, HashDeathTest,
                        ::testing::Values(HashTest::GetData()[0]));

}  // namespace vapidssl
