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

#include "crypto/keyex.h"
#include "crypto/keyex_internal.h"

#include "base/buf.h"
#include "base/error.h"
#include "base/platform/test/platform_helper.h"
#include "base/test/scoped_buf.h"
#include "crypto/test/crypto_test.h"
#include "public/config.h"
#include "public/error.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// KeyxTest is the test fixture for the unit tests in this file.
class KeyxTest : public CryptoTest {
 public:
  ~KeyxTest() override = default;
  KeyxTest &operator=(const KeyxTest &) = delete;
  KeyxTest(const KeyxTest &) = delete;

  // GetData defines the key exchange algorithms that can be tested and
  // their associated test data files.
  static const std::vector<TEST_DATA> &GetData() {
    static const std::vector<TEST_DATA> kTestData = {
        {
            .algorithm = kKeyxECDHE,
            .parameter = kTlsCurve25519,
            .path = "test/ecdhe_with_curve25519_tests.txt",
        },
    };
    return kTestData;
  }

 protected:
  KeyxTest() = default;

  // SetUp is called at the start of each test to set up the test fixture.  It
  // calls |CryptoHelper::SetUp| to open its associated gold file, and registers
  // the attributes it expects to use.
  void SetUp() override {
    CryptoTest::SetUp();
    const struct test_data_st &test_data = GetParam();
    keyex_ = keyex_find(test_data.algorithm, test_data.parameter);
    ASSERT_FALSE(keyex_ == nullptr);
    AddHexAttribute("SECRET", secret_);
    AddHexAttribute("OFFER", offer_);
    region_.Reset(keyex_->secret_size);
    accept_.Reset(keyex_->accept_size);
    client_.Reset(keyex_->output_size);
    server_.Reset(keyex_->output_size);
  }

  // keyex_ defines the algorithm under test.
  const KEYEX *keyex_;
  ScopedBuf region_;
  // secret_ is Alice's generated secret.
  ScopedBuf secret_;
  // offer_ is Alice's offer message when she is the offering party.
  ScopedBuf offer_;
  // b_accept_ is Bob's acceptance message when he is the accepting party.
  ScopedBuf accept_;
  // client_ and server_ are a shared key that Alice and Bob can both compute.
  ScopedBuf client_;
  ScopedBuf server_;
};

using KeyxDeathTest = KeyxTest;

TEST_P(KeyxTest, CheckDefinition) {
  EXPECT_NE(keyex_, nullptr);
  EXPECT_NE(keyex_get_accept_size(keyex_), 0U);
  EXPECT_NE(keyex_get_output_size(keyex_), 0U);
}

TEST_P(KeyxDeathTest, AcceptWithBadParameters) {
  ASSERT_TRUE(ReadNext());
  // Check nulls.
  EXPECT_ASSERT(keyex_accept(nullptr, region_.Get(), offer_.Get(),
                             accept_.Get(), client_.Get()));
  EXPECT_ASSERT(keyex_accept(keyex_, nullptr, offer_.Get(), accept_.Get(),
                             client_.Get()));
  EXPECT_ASSERT(keyex_accept(keyex_, region_.Get(), nullptr, accept_.Get(),
                             client_.Get()));
  EXPECT_ASSERT(keyex_accept(keyex_, region_.Get(), offer_.Get(), nullptr,
                             client_.Get()));
  EXPECT_ASSERT(keyex_accept(keyex_, region_.Get(), offer_.Get(), accept_.Get(),
                             nullptr));
  // Check short lengths.
  ScopedBuf empty(0);
  EXPECT_FALSE(keyex_accept(keyex_, empty.Get(), offer_.Get(), accept_.Get(),
                            client_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);

  EXPECT_FALSE(keyex_accept(keyex_, region_.Get(), empty.Get(), accept_.Get(),
                            client_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrIllegalParameter);
  EXPECT_ASSERT(keyex_accept(keyex_, region_.Get(), offer_.Get(), empty.Get(),
                             client_.Get()));
  EXPECT_ASSERT(keyex_accept(keyex_, region_.Get(), offer_.Get(), accept_.Get(),
                             empty.Get()));
}

TEST_P(KeyxTest, ComputeSharedKey) {
  while (ReadNext()) {
    EXPECT_TRUE(keyex_accept(keyex_, region_.Get(), offer_.Get(), accept_.Get(),
                             client_.Get()));
    KeyexFinish(secret_, accept_, server_);
    EXPECT_PRED2(buf_equal, client_.Get(), server_.Get());
  }
}

INSTANTIATE_TEST_CASE_P(Crypto, KeyxTest,
                        ::testing::ValuesIn(KeyxTest::GetData()));
INSTANTIATE_TEST_CASE_P(Crypto, KeyxDeathTest,
                        ::testing::Values(KeyxDeathTest::GetData()[0]));

}  // namespace vapidssl
