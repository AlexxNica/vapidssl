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

#include "x509v3/certificate.h"
#include "x509v3/certificate_internal.h"

#include <assert.h>
#include <string.h>
#include <time.h>
#include <memory>

#include "base/buf.h"
#include "base/error.h"
#include "base/list.h"
#include "base/platform/test/io_mock.h"
#include "base/platform/test/platform_helper.h"
#include "base/test/scoped_buf.h"
#include "common/test/state_helper.h"
#include "common/test/stream_helper.h"
#include "crypto/hash.h"
#include "crypto/sign.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"
#include "x509v3/asn1.h"
#include "x509v3/oid.h"
#include "x509v3/test/truststore_helper.h"
#include "x509v3/truststore.h"

namespace vapidssl {

namespace {

const char *kName = "NAME";
const char *kChainLabel = "Chain Length";
const char *kLeafKeyLabel = "Public Key (Leaf)";
const size_t kNameLen = 113;
const size_t kKeyLen = 271;


}  // namespace

class CertificateTest : public CryptoTest {
 public:
  ~CertificateTest() override = default;
  CertificateTest &operator=(const CertificateTest &) = delete;
  CertificateTest(const CertificateTest &) = delete;

  // GetData lists the test data files containing the certificate data.
  static const std::vector<TEST_DATA> &GetData() {
    static const std::vector<TEST_DATA> kTestData = {
        {
            .algorithm = 0, .parameter = 0, .path = "test/x509v3_tests.txt",
        },
    };
    return kTestData;
  }

 protected:
  CertificateTest() = default;

  // SetUp prepares the test by registering the necessary attributes as well as
  // by setting up the data streams and trust store.
  void SetUp() override {
    CryptoTest::SetUp();
    AddStringAttribute(kName, name_, true);
    // stream_helper_.SetMtu(1);
    stream_helper_.SetParent(*this);
    stream_helper_.SetCryptoHelper(GetCryptoHelper());
    stream_helper_.SetPending(12);  // ~ 3 kb
    stream_helper_.SetNesting(kRecv, 9);
    stream_helper_.AddCallback(kChainLabel, ChainCallback);
    stream_helper_.AddCallback(kLeafKeyLabel, LeafKeyCallback);
    stream_helper_.Reset();
    truststore_buf_.Reset(truststore_size(1));
    EXPECT_TRUE(truststore_init(truststore_buf_.Get(), 1, &truststore_));
    EXPECT_TRUE(truststore_add(&truststore_, TruststoreHelper::dn,
                               TruststoreHelper::dn_len, TruststoreHelper::key,
                               TruststoreHelper::key_len));
  }

  // stream_helper_ manages the data streams.
  StreamHelper stream_helper_;
  // region_ is the memory used during testing.
  ScopedBuf region_;
  // chain_ represents the certificate chain being parsed.
  CERTIFICATE chain_;
  // name_ is a data attribute used to set the server's name.
  std::string name_;
  // sni_ holds the server name  throughout the certificate parsing.
  ScopedBuf sni_;
  // truststore_buf_ holds the memory needed for the trust store.
  ScopedBuf truststore_buf_;
  // truststore_ represents the list of DN/key pairs we trust.
  LIST truststore_;
  // key_ holds the chain's parsed leaf public key.
  ScopedBuf key_;
  // expected_key_ holds the key as read from the data file.
  ScopedBuf expected_key_;

 private:
  static bool ChainCallback(StreamHelper &helper, ScopedBuf &buf) {
    CertificateTest *test = static_cast<CertificateTest *>(helper.GetParent());
    return test && helper.HasAttribute(kName) && test->CopySNI();
  }

  static bool LeafKeyCallback(StreamHelper &helper, ScopedBuf &buf) {
    CertificateTest *test = static_cast<CertificateTest *>(helper.GetParent());
    if (!test) {
      return false;
    }
    test->expected_key_.Reset(buf);
    return true;
  }

  bool CopySNI() {
    if (name_.length() == 0) {
      return false;
    }
    sni_.Reset(name_.length());
    memcpy(sni_.Raw(), name_.c_str(), sni_.Len());
    return true;
  }
};

using CertificateDeathTest = CertificateTest;

TEST_P(CertificateDeathTest, BadParameters) {
  ScopedBuf key(kKeyLen);
  STREAM *client_recv = stream_helper_.GetStream(kIoClient, kRecv);
  // Check nulls on init
  EXPECT_ASSERT(certificate_init(nullptr, 0xFFFF, key.Get(), &chain_));
  EXPECT_ASSERT(certificate_init(region_.Get(), 0xFFFF, nullptr, &chain_));
  EXPECT_ASSERT(certificate_init(region_.Get(), 0xFFFF, key.Get(), nullptr));
  // Check OOM on init
  region_.Reset(0);
  EXPECT_FALSE(certificate_init(region_.Get(), 0xFFFF, key.Get(), &chain_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  // Check nulls on set_stream
  EXPECT_ASSERT(certificate_set_stream(nullptr, &chain_));
  EXPECT_ASSERT(certificate_set_stream(client_recv, nullptr));
  // Check nulls on set_name
  EXPECT_ASSERT(certificate_set_name(nullptr, &chain_));
  EXPECT_ASSERT(certificate_set_name(sni_.Get(), nullptr));
  // Check nulls on set_trust
  EXPECT_ASSERT(certificate_set_trust(nullptr, &chain_));
  EXPECT_ASSERT(certificate_set_trust(&truststore_, nullptr));
  // Check nulls on recv
  EXPECT_ASSERT(certificate_recv(nullptr));
  // Check nulls on leaf_key
  EXPECT_ASSERT(certificate_is_trusted(nullptr));
}

TEST_P(CertificateTest, ParseCertificateChain) {
  region_.Reset(certificate_size(kNameLen, kKeyLen));
  key_.Reset(kKeyLen);
  STREAM *client_recv = stream_helper_.GetStream(kIoClient, kRecv);
  stream_set_hashing(client_recv, kTrue);
  ASSERT_TRUE(certificate_init(region_.Get(), kNameLen, key_.Get(), &chain_));
  certificate_set_stream(client_recv, &chain_);
  certificate_set_trust(&truststore_, &chain_);
  uint24_t length = 0;
  do {
    // Initial ReadNext() should grab chain length and server name.
    while (!stream_recv_u24(client_recv, &length)) {
      ASSERT_TRUE(stream_helper_.ReadNext());
    }
    certificate_set_name(sni_.Get(), &chain_);
    // Matches [1] below
    stream_nested_begin(client_recv, length);
    do {
      while (!stream_recv_u24(client_recv, &length)) {
        ASSERT_TRUE(stream_helper_.ReadNext());
      }
      // Matches [1] below
      stream_nested_begin(client_recv, length);
      while (!certificate_recv(&chain_)) {
        ASSERT_TRUE(stream_helper_.ReadNext());
      }
      // Matches [1] above
      EXPECT_TRUE(stream_nested_finish(client_recv));
      // Matches [0] above
    } while (!stream_nested_finish(client_recv));
    // Chain is completely parsed; check if it's trusted.
    EXPECT_TRUE(certificate_is_trusted(&chain_));
    EXPECT_PRED2(buf_equal, expected_key_.Get(), key_.Get());
  } while (stream_helper_.ReadNext());
}

INSTANTIATE_TEST_CASE_P(X509v3, CertificateTest,
                        ::testing::ValuesIn(CertificateTest::GetData()));
INSTANTIATE_TEST_CASE_P(X509v3, CertificateDeathTest,
                        ::testing::Values(CertificateDeathTest::GetData()[0]));

}  // namespace vapidssl
