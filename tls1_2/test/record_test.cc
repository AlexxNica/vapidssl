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

#include "tls1_2/test/record_test.h"

#include <stddef.h>

#include "base/test/scoped_buf.h"
#include "base/types.h"
#include "common/chunk.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"
#include "tls1_2/ciphersuite.h"
#include "tls1_2/record.h"
#include "tls1_2/test/config_helper.h"
#include "x509v3/test/truststore_helper.h"

namespace vapidssl {

const size_t RecordTest::kNumFragments = 6;

// We "hide" the ciphersuite in the |parameter| field.
const std::vector<TEST_DATA> &RecordTest::GetData() {
  static const std::vector<TEST_DATA> kTestData = {
      {
          .algorithm = kAeadAes128Gcm,
          .parameter = kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
          .path =
              "third_party/boringssl/crypto/cipher/test/aes_128_gcm_tests.txt",
      },
      {
          .algorithm = kAeadAes256Gcm,
          .parameter = kTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
          .path =
              "third_party/boringssl/crypto/cipher/test/aes_256_gcm_tests.txt",
      },
      {
          .algorithm = kAeadChaCha20Poly1305,
          .parameter = kTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
          .path = "third_party/boringssl/crypto/cipher/test/"
                  "chacha20_poly1305_tests.txt",
      },
  };
  return kTestData;
}

RecordTest::RecordTest()
    : ciphersuite_(kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) {}

void RecordTest::SetUp() {
  ChunkTest::SetUp();
  const struct test_data_st &test_data = GetParam();
  ciphersuite_ = (tls_ciphersuite_t)test_data.parameter;
  EXPECT_TRUE(ciphersuite_is_supported(ciphersuite_));
}

const TLS_CONFIG *RecordTest::GetConfig() {
  return config_helper_.GetConfig();
}

tls_ciphersuite_t RecordTest::GetCiphersuite() {
  return ciphersuite_;
}

void RecordTest::ResetRecords() {
  region_.Reset(2 * (record_size(GetConfig()) + chunk_size(kNumFragments)));
  EXPECT_TRUE(
      chunk_init(region_.Get(), kIoLoopback, kSend, kNumFragments, &tx_));
  EXPECT_TRUE(record_init(GetConfig(), region_.Get(), kSend, &tx_));
  EXPECT_TRUE(
      chunk_init(region_.Get(), kIoLoopback, kRecv, kNumFragments, &rx_));
  EXPECT_TRUE(record_init(GetConfig(), region_.Get(), kRecv, &rx_));
}

bool RecordTest::ReadNext() {
  // Skip nonces that don't match the ciphersuite's specified length.
  if (!ChunkTest::ReadNext()) {
    return false;
  }
  // Adjust the fixed nonce (by truncation or padding) to be the right size.
  size_t nonce_len = ciphersuite_fix_nonce_length(ciphersuite_);
  ScopedBuf fixed_nonce(nonce_len);
  buf_copy(nonce_.Get(), fixed_nonce.Get());
  // Still have |nonce_| have the complete nonce length.
  if (!ciphersuite_xor_nonce(ciphersuite_)) {
    nonce_len += ciphersuite_var_nonce_length(ciphersuite_);
  }
  nonce_.Reset(nonce_len);
  // Only the fixed nonce should be ready.
  buf_copy(fixed_nonce.Get(), nonce_.Get());
  return true;
}

}  // namespace vapidssl
