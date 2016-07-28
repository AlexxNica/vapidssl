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

#include "tls1_2/prf.h"

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

class PrfTest : public CryptoTest {
 public:
  ~PrfTest() override = default;
  PrfTest &operator=(const PrfTest &) = delete;
  PrfTest(const PrfTest &) = delete;

  // GetData lists the test data files containing the pseudo-random function
  // data.
  static const std::vector<TEST_DATA> &GetData() {
    static const std::vector<TEST_DATA> kTestData = {
        {
            .algorithm = kTlsHashSHA256,
            .parameter = 0,
            .path = "test/prf_sha256_tests.txt",
        },
        {
            .algorithm = kTlsHashSHA384,
            .parameter = 0,
            .path = "test/prf_sha384_tests.txt",
        },
    };
    return kTestData;
  }

 protected:
  PrfTest() : hash_(nullptr) {}

  // SetUp prepares the test by registering the necessary attributes.
  void SetUp() override {
    CryptoTest::SetUp();
    const struct test_data_st &test_data = GetParam();
    hash_ = hash_find(test_data.algorithm);
    ASSERT_FALSE(hash_ == nullptr);
    AddHexAttribute("SECRET", secret_);
    AddStringAttribute("LABEL", label_);
    AddHexAttribute("SEED1", seed1_);
    AddHexAttribute("SEED2", seed2_);
    AddHexAttribute("OUTPUT", output_);
  }

  // hash_ is the hash algorithm used by the PRF algorithm
  const HASH *hash_;
  // region_ is the memory used during testing.
  ScopedBuf region_;
  // secret_ is the HMAC secret key.
  ScopedBuf secret_;
  // label_ is the text used as the first part of the seed.
  std::string label_;
  // seed1_ is the second part of the seed.
  ScopedBuf seed1_;
  // seed2_ is the optional third part of the seed.
  ScopedBuf seed2_;
  // output_ is the generated data.
  ScopedBuf output_;
};

using PrfDeathTest = PrfTest;

TEST_P(PrfDeathTest, NullParameters) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(prf_size(nullptr));
  ScopedBuf out;
  EXPECT_ASSERT(prf(nullptr, hash_, secret_.Get(), label_.c_str(), seed1_.Get(),
                    seed2_.Get(), out.Get()));
  EXPECT_ASSERT(prf(region_.Get(), nullptr, secret_.Get(), label_.c_str(),
                    seed1_.Get(), seed2_.Get(), out.Get()));
  EXPECT_ASSERT(prf(region_.Get(), hash_, nullptr, label_.c_str(), seed1_.Get(),
                    seed2_.Get(), out.Get()));
  EXPECT_ASSERT(prf(region_.Get(), hash_, secret_.Get(), nullptr, seed1_.Get(),
                    seed2_.Get(), out.Get()));
  EXPECT_ASSERT(prf(region_.Get(), hash_, secret_.Get(), label_.c_str(),
                    nullptr, seed2_.Get(), out.Get()));
  EXPECT_ASSERT(prf(region_.Get(), hash_, secret_.Get(), label_.c_str(),
                    seed1_.Get(), seed2_.Get(), nullptr));
}

TEST_P(PrfDeathTest, OutOfMemory) {
  ASSERT_TRUE(ReadNext());
  ScopedBuf out;
  ScopedBuf empty;
  EXPECT_FALSE(prf(empty.Get(), hash_, secret_.Get(), label_.c_str(),
                   seed1_.Get(), seed2_.Get(), out.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
}

TEST_P(PrfTest, GenerateOutput) {
  ScopedBuf out;
  while (ReadNext()) {
    region_.Reset(prf_size(hash_));
    out.Reset(output_.Len());
    EXPECT_TRUE(prf(region_.Get(), hash_, secret_.Get(), label_.c_str(),
                    seed1_.Get(), seed2_.Get(), out.Get()));
    EXPECT_PRED2(buf_equal, out.Get(), output_.Get());
  }
}

INSTANTIATE_TEST_CASE_P(Tls1_2, PrfTest,
                        ::testing::ValuesIn(PrfTest::GetData()));
INSTANTIATE_TEST_CASE_P(Tls1_2, PrfDeathTest,
                        ::testing::Values(PrfTest::GetData()[0]));

}  // namespace vapidssl
