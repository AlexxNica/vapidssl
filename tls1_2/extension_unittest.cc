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

#include "tls1_2/extension.h"
#include "crypto/test/crypto_test.h"
#include "tls1_2/extension_internal.h"

#include <string>
#include <vector>

#include "base/platform/test/io_mock.h"
#include "base/types.h"
#include "common/stream.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"
#include "tls1_2/message.h"
#include "tls1_2/test/tls_helper.h"

namespace vapidssl {

namespace {

// kSNI is a server name indication used for testing.
const char *kSNI = "www.google.com";

}  // namespace

class ExtensionTest : public CryptoTest {
 public:
  virtual ~ExtensionTest() = default;
  ExtensionTest &operator=(const ExtensionTest &) = delete;
  ExtensionTest(const ExtensionTest &) = delete;

  // GetData lists the test data files containing the extension data.
  static const std::vector<TEST_DATA> &GetData() {
    static const std::vector<TEST_DATA> kTestData = {
        {
            .algorithm = 0,
            .parameter = 0,
            .path = "test/tls1_2_extension_tests.txt",
        },
    };
    return kTestData;
  }

 protected:
  ExtensionTest() = default;

  // SetUp prepares the test by configuring the TLS helper with parameters and
  // callbacks, as well as by configuring the data streams.
  void SetUp() override {
    CryptoTest::SetUp();
    tls_helper_.SetCryptoHelper(GetCryptoHelper());
    tls_helper_.SetState(&extension_, sizeof(extension_));
    tls_helper_.SetSNI(kSNI);
    tls_helper_.Reset();
    region_.Reset(0x1000);
    // Strip the nesting since the extensions are within a single message.
    EXPECT_TRUE(stream_nested_finish(tls_helper_.GetStream(kIoClient, kSend)));
    EXPECT_TRUE(stream_nested_finish(tls_helper_.GetStream(kIoClient, kRecv)));
  }

  // region_ is the memory used during testing.
  ScopedBuf region_;
  // tls_helper_ manages the TLS connection object.
  TlsHelper tls_helper_;
  // extension_ represents the TLS 1.2 extensions.
  EXTENSION extension_;
};

using ExtensionDeathTest = ExtensionTest;

TEST_P(ExtensionDeathTest, NullParameters) {
  EXPECT_ASSERT(extension_init(nullptr, tls_helper_.GetTLS(), &extension_));
  EXPECT_ASSERT(extension_init(region_.Get(), nullptr, &extension_));
  EXPECT_ASSERT(extension_init(region_.Get(), tls_helper_.GetTLS(), nullptr));
  EXPECT_ASSERT(extension_length(nullptr));
  EXPECT_ASSERT(extension_send(nullptr));
  EXPECT_ASSERT(extension_recv(nullptr));
  EXPECT_ASSERT(extension_echoed(nullptr, kExtSignatureAndHash));
}

TEST_P(ExtensionTest, SendAndRecvExtensions) {
  do {
    region_.Reset();
    extension_init(region_.Get(), tls_helper_.GetTLS(), &extension_);
    EXPECT_TRUE(extension_send(&extension_));
    while (!extension_recv(&extension_)) {
      ASSERT_TRUE(tls_helper_.ReadNext());
    }
    EXPECT_TRUE(extension_echoed(&extension_, kExtSignatureAndHash));
    EXPECT_FALSE(extension_echoed(&extension_, kExtMaxFragmentLength));
  } while (tls_helper_.ReadNext());
}

INSTANTIATE_TEST_CASE_P(Tls1_2, ExtensionTest,
                        ::testing::ValuesIn(ExtensionTest::GetData()));
INSTANTIATE_TEST_CASE_P(Tls1_2, ExtensionDeathTest,
                        ::testing::Values(ExtensionTest::GetData()[0]));

}  // namespace vapidssl
