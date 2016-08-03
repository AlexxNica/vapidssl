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

#include "crypto/sign.h"
#include "crypto/sign_internal.h"

#include "base/buf.h"
#include "base/error.h"
#include "base/platform/test/platform_helper.h"
#include "base/test/scoped_buf.h"
#include "crypto/hash.h"
#include "crypto/test/crypto_test.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// SignTest is the test fixture for the unit tests in this file.
class SignTest : public CryptoTest {
 public:
  ~SignTest() override = default;
  SignTest &operator=(const SignTest &) = delete;
  SignTest(const SignTest &) = delete;

  // GetData defines the signature verification algorithms that can be
  // tested and their associated test data files.
  static const std::vector<TEST_DATA> &GetData() {
    static const std::vector<TEST_DATA> kTestData = {
        {
            .algorithm = kSignRSA,
            .parameter = kTlsHashSHA256,
            .path = "test/rsa_with_sha256_tests.txt",
        },
        {
            .algorithm = kSignRSA,
            .parameter = kTlsHashSHA384,
            .path = "test/rsa_with_sha384_tests.txt",
        },
    };
    return kTestData;
  }

 protected:
  SignTest() : sign_(nullptr), hash_(nullptr) {}

  // SetUp is called at the start of each test to set up the test fixture.  It
  // calls |CryptoHelper::SetUp| to open its associated gold file, and registers
  // the attributes it expects to use.  It also allocates working buffers that
  // will be needed during testing.
  void SetUp() override {
    CryptoTest::SetUp();
    const struct test_data_st &test_data = GetParam();
    sign_ = sign_find(test_data.algorithm, test_data.parameter);
    ASSERT_NE(sign_, nullptr);
    hash_ = hash_find(test_data.parameter);
    ASSERT_NE(hash_, nullptr);
    AddHexAttribute("DN", dn_);
    AddHexAttribute("DATA", signed_data_);
    AddHexAttribute("KEY", public_key_);
    AddHexAttribute("SIG", signature_);
  }

  // ReadNext extends the |CryptoHelper::ReadNext| to prepare the |digest_| of
  // |signed_data_|.
  bool ReadNext() override {
    if (!CryptoTest::ReadNext()) {
      return false;
    }
    state_.Reset(hash_get_state_size(hash_));
    hash_init(hash_, state_.Get());
    hash_update(hash_, state_.Get(), signed_data_.Get());
    digest_.Reset(hash_get_output_size(hash_));
    hash_final(hash_, state_.Get(), digest_.Get());
    return true;
  }

  // sign_ defines the algorithm under test.
  const SIGN *sign_;
  // hash_ defines the associated hash algorithm.
  const HASH *hash_;
  // state_ is used by |hash_| to produce |digest_| from the |signed_data_|.
  ScopedBuf state_;
  // digest_ is the digest of the signed data.
  ScopedBuf digest_;
  // dn_ is the distinguished name on the certificate (ignored).
  ScopedBuf dn_;
  // signed_data_ is the signed data associated with the signature.
  ScopedBuf signed_data_;
  // public_key_ is the public key associated with the signature.
  ScopedBuf public_key_;
  // signature_ is the signature to be verified.
  ScopedBuf signature_;
};

using SignDeathTest = SignTest;

TEST_P(SignDeathTest, CheckDefinitions) {
  EXPECT_NE(sign_, nullptr);
}

TEST_P(SignDeathTest, VerifySignedWithBadState) {
  ASSERT_TRUE(ReadNext());
  // Check sign_ must be non-nullptr with the right id.
  EXPECT_ASSERT(
      sign_verify(nullptr, digest_.Get(), signature_.Get(), public_key_.Get()));
  SIGN dummy;
  memcpy(&dummy, sign_, sizeof(*sign_));
  dummy.algorithm++;
  EXPECT_ASSERT(
      sign_verify(&dummy, digest_.Get(), signature_.Get(), public_key_.Get()));
  memcpy(&dummy, sign_, sizeof(*sign_));
  dummy.hash_algorithm = 0;
  EXPECT_ASSERT(
      sign_verify(&dummy, digest_.Get(), signature_.Get(), public_key_.Get()));
}

TEST_P(SignDeathTest, VerifySignedWithBadSignature) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(sign_verify(sign_, digest_.Get(), public_key_.Get(), nullptr));
  ASSERT_TRUE(buf_consume(signature_.Get(), 1, nullptr));
  EXPECT_FALSE(
      sign_verify(sign_, digest_.Get(), signature_.Get(), public_key_.Get()));
  tls_error_source_t source;
  EXPECT_TRUE(TLS_ERROR_get(&source, nullptr, nullptr, nullptr));
  EXPECT_EQ(source, kTlsErrCrypto);
  error_clear();
}

TEST_P(SignDeathTest, VerifySignedWithBadData) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(
      sign_verify(sign_, nullptr, signature_.Get(), public_key_.Get()));
  uint8_t raw[1] = {0xff};
  BUF tmp = buf_init();
  buf_wrap(raw, 1, 1, &tmp);
  buf_xor(&tmp, signature_.Get());
  EXPECT_FALSE(
      sign_verify(sign_, digest_.Get(), signature_.Get(), public_key_.Get()));
  tls_error_source_t source;
  EXPECT_TRUE(TLS_ERROR_get(&source, nullptr, nullptr, nullptr));
  EXPECT_EQ(source, kTlsErrCrypto);
  error_clear();
}

TEST_P(SignDeathTest, VerifySignedWithBadKey) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(sign_verify(sign_, digest_.Get(), nullptr, signature_.Get()));
  ASSERT_TRUE(buf_consume(public_key_.Get(), 1, nullptr));
  EXPECT_FALSE(
      sign_verify(sign_, digest_.Get(), signature_.Get(), public_key_.Get()));
  tls_error_source_t source;
  EXPECT_TRUE(TLS_ERROR_get(&source, nullptr, nullptr, nullptr));
  EXPECT_EQ(source, kTlsErrCrypto);
  error_clear();
}

TEST_P(SignTest, VerifySigned) {
  while (ReadNext()) {
    EXPECT_TRUE(
        sign_verify(sign_, digest_.Get(), signature_.Get(), public_key_.Get()));
  }
}

INSTANTIATE_TEST_CASE_P(Crypto, SignTest,
                        ::testing::ValuesIn(SignTest::GetData()));
INSTANTIATE_TEST_CASE_P(Crypto, SignDeathTest,
                        ::testing::Values(SignDeathTest::GetData()[0]));

}  // namespace vapidssl
