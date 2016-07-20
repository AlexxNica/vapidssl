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

#include "common/hmac.h"

#include <string>
#include <vector>

#include "base/buf.h"
#include "base/test/scoped_buf.h"
#include "crypto/hash.h"
#include "crypto/test/crypto_helper.h"
#include "crypto/test/crypto_test.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

class HmacTest : public CryptoTest {
 public:
  virtual ~HmacTest() = default;
  HmacTest &operator=(const HmacTest &) = delete;
  HmacTest(const HmacTest &) = delete;

  // GetData defines the hash message authentication code algorithms that can be
  // tested and their associated test data files.
  static const std::vector<TEST_DATA> &GetData() {
    static const std::vector<TEST_DATA> kTestData = {
        {
            .algorithm = kTlsHashSHA256,
            .parameter = 0,
            .path = "test/hmac_sha256_tests.txt",
        },
        {
            .algorithm = kTlsHashSHA384,
            .parameter = 0,
            .path = "test/hmac_sha384_tests.txt",
        },
    };
    return kTestData;
  }

 protected:
  HmacTest() : hash_(nullptr) {}

  // SetUp prepares the test by registering the necessary attributes.
  void SetUp() override {
    CryptoTest::SetUp();
    const struct test_data_st &test_data = GetParam();
    hash_ = hash_find(test_data.algorithm);
    ASSERT_FALSE(hash_ == nullptr);
    AddStringAttribute("LABEL", label_, true);
    AddHexAttribute("KEY", key_);
    AddHexAttribute("DATA", data_);
    AddHexAttribute("OUTPUT", output_);
  }

  // hash_ is that hash used to generate the HAMCs.
  const HASH *hash_;
  // label_ is an attribute from the data file useful for identifying failures.
  std::string label_;
  // region_ is the memory used during testing.
  ScopedBuf region_;
  // key_ is the HMAC secret.
  ScopedBuf key_;
  // data_ is the data to be authenticated using an HMAC.
  ScopedBuf data_;
  // output_ is the expected HMAC tag.
  ScopedBuf output_;
};

using HmacDeathTest = HmacTest;

TEST_P(HmacDeathTest, NullParameters) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(hmac_size(nullptr));
  HMAC hmac;
  EXPECT_ASSERT(hmac_init(nullptr, hash_, key_.Get(), &hmac));
  EXPECT_ASSERT(hmac_init(region_.Get(), nullptr, key_.Get(), &hmac));
  EXPECT_ASSERT(hmac_init(region_.Get(), hash_, nullptr, &hmac));
  EXPECT_ASSERT(hmac_init(region_.Get(), hash_, key_.Get(), nullptr));
  HMAC copy;
  EXPECT_ASSERT(hmac_copy(nullptr, &hmac, &copy));
  EXPECT_ASSERT(hmac_copy(region_.Get(), nullptr, &copy));
  EXPECT_ASSERT(hmac_copy(region_.Get(), &hmac, nullptr));
  EXPECT_ASSERT(hmac_update(nullptr, data_.Get()));
  ScopedBuf out(output_.Len());
  EXPECT_ASSERT(hmac_final(nullptr, &hmac, out.Get()));
  EXPECT_ASSERT(hmac_final(region_.Get(), nullptr, out.Get()));
  EXPECT_ASSERT(hmac_final(region_.Get(), &hmac, nullptr));
}

TEST_P(HmacDeathTest, OutOfMemory) {
  ASSERT_TRUE(ReadNext());
  ScopedBuf out;
  ScopedBuf empty(1);
  HMAC hmac;
  EXPECT_FALSE(hmac_init(empty.Get(), hash_, key_.Get(), &hmac));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  HMAC copy;
  region_.Reset(hmac_size(hash_));
  EXPECT_TRUE(hmac_init(region_.Get(), hash_, key_.Get(), &hmac)) << label_;
  EXPECT_FALSE(hmac_copy(empty.Get(), &hmac, &copy));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
}

TEST_P(HmacTest, GenerateOutput) {
  HMAC hmac;
  ScopedBuf out1;
  while (ReadNext()) {
    region_.Reset(hmac_size(hash_));
    out1.Reset(output_.Len());
    EXPECT_TRUE(hmac_init(region_.Get(), hash_, key_.Get(), &hmac)) << label_;
    hmac_update(&hmac, data_.Get());
    EXPECT_TRUE(hmac_final(region_.Get(), &hmac, out1.Get()));
    EXPECT_PRED2(buf_equal, out1.Get(), output_.Get()) << label_;
  }
}

TEST_P(HmacTest, GenerateOutputWithCopy) {
  HMAC hmac;
  HMAC copy;
  ScopedBuf out1;
  ScopedBuf out2;
  while (ReadNext()) {
    region_.Reset(hmac_size(hash_) * 2);
    out1.Reset(output_.Len());
    out2.Reset(output_.Len());
    EXPECT_TRUE(hmac_init(region_.Get(), hash_, key_.Get(), &hmac)) << label_;
    EXPECT_TRUE(hmac_copy(region_.Get(), &hmac, &copy)) << label_;
    hmac_update(&copy, data_.Get());
    hmac_update(&hmac, data_.Get());
    EXPECT_TRUE(hmac_final(region_.Get(), &copy, out2.Get()));
    EXPECT_PRED2(buf_equal, out2.Get(), output_.Get()) << label_;
    EXPECT_TRUE(hmac_final(region_.Get(), &hmac, out1.Get()));
    EXPECT_PRED2(buf_equal, out1.Get(), output_.Get()) << label_;
  }
}

INSTANTIATE_TEST_CASE_P(Common, HmacTest,
                        ::testing::ValuesIn(HmacTest::GetData()));
INSTANTIATE_TEST_CASE_P(Common, HmacDeathTest,
                        ::testing::Values(HmacTest::GetData()[0]));

}  // namespace vapidssl
