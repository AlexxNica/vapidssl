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

#include "crypto/test/hash_test.h"

#include "base/buf.h"
#include "base/platform/test/platform_helper.h"
#include "base/test/scoped_buf.h"
#include "crypto/hash.h"
#include "crypto/test/crypto_test.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// Public Methods

const std::vector<TEST_DATA> &HashTest::GetData() {
  static const std::vector<TEST_DATA> kTestData = {
      {
          .algorithm = kTlsHashSHA256,
          .parameter = 0,
          .path = "test/sha256_tests.txt",
      },
      {
          .algorithm = kTlsHashSHA384,
          .parameter = 0,
          .path = "test/sha384_tests.txt",
      },
  };
  return kTestData;
}

// Protected Methods

HashTest::HashTest() : hash_(nullptr) {}

void HashTest::SetUp() {
  CryptoTest::SetUp();
  const struct test_data_st &test_data = GetParam();
  hash_ = hash_find(test_data.algorithm);
  ASSERT_FALSE(hash_ == nullptr);
  state_.Reset(hash_get_state_size(hash_));
  AddHexAttribute("IN", in_);
  AddHexAttribute("DIGEST", digest_);
  out_.Reset(hash_get_output_size(hash_));
}

}  // namespace vapidssl
