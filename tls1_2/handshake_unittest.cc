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

#include "tls1_2/handshake.h"
#include "crypto/test/crypto_test.h"
#include "tls1_2/handshake_internal.h"

#include <string>
#include <vector>

#include "base/platform/test/io_mock.h"
#include "base/platform/test/random_fake.h"
#include "base/test/scoped_buf.h"
#include "base/types.h"
#include "crypto/test/crypto_helper.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"
#include "tls1_2/ciphersuite.h"
#include "tls1_2/config.h"
#include "tls1_2/prf.h"
#include "tls1_2/test/tls_helper.h"
#include "tls1_2/tls.h"

namespace vapidssl {

namespace {

// Needs to be kept in sync with test/tls1_2_handshake_tests.txt
const tls_ciphersuite_t kCiphersuite = kTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;

const char *kSNI = "Leaf";
const char *kClientRandom = "Random (ClientHello)";
const char *kServerRandom = "Random (ServerHello)";
const char *kKeyExpansion = "key expansion";
const char *kClientCrypto = "Verify (Finished: Client)";
const char *kClientFinished = "client finished";
const char *kServerCrypto = "Verify (Finished: Server)";
const char *kServerFinished = "server finished";

}  // namespace

class HandshakeTest : public CryptoTest {
 public:
  ~HandshakeTest() override = default;
  HandshakeTest &operator=(const HandshakeTest &) = delete;
  HandshakeTest(const HandshakeTest &) = delete;

  // GetData lists the test data files containing the handshake data.
  static const std::vector<TEST_DATA> &GetData() {
    static const std::vector<TEST_DATA> kTestData = {
        {
            .algorithm = 0,
            .parameter = 0,
            .path = "test/tls1_2_handshake_tests.txt",
        },
    };
    return kTestData;
  }

 protected:
  HandshakeTest() = default;

  // SetUp prepares the test by configuring the TLS helper with parameters and
  // callbacks.
  void SetUp() override {
    CryptoTest::SetUp();
    tls_helper_.SetParent(*this);
    tls_helper_.SetCryptoHelper(GetCryptoHelper());
    tls_helper_.SetState(&handshake_, sizeof(handshake_));
    tls_helper_.SetSNI(kSNI);
    tls_helper_.SetHash(hash_find(kTlsHashSHA384));
    tls_helper_.AddCallback(kClientRandom, RandomCallback);
    tls_helper_.AddCallback(kServerRandom, RandomCallback);
    tls_helper_.AddCallback(kClientCrypto, CryptoCallback);
    tls_helper_.AddCallback(kServerCrypto, CryptoCallback);
    tls_helper_.Reset();
  }

  // region_ is the memory used during testing.
  ScopedBuf region_;
  // tls_helper_ manages the TLS connection object.
  TlsHelper tls_helper_;
  // handshake_ represents the TLS 1.2 connection handshake.
  HANDSHAKE handshake_;
  // client_random_ is the random number picked by the client.
  ScopedBuf client_random_;
  // server_random_ is the random number picked by the server.
  ScopedBuf server_random_;

 private:
  // RandomCallback is invoked when either the client or server sends a random
  // value.  It saves the random value in the TlsHelper object for later use.
  static bool RandomCallback(StreamHelper &helper, ScopedBuf &buf) {
    HandshakeTest *test = static_cast<HandshakeTest *>(helper.GetParent());
    if (!test) {
      return false;
    }
    if (helper.GetLabel().compare(kClientRandom) == 0) {
      test->client_random_.Reset(buf);
    } else {
      test->server_random_.Reset(buf);
    }
    return true;
  }

  static bool CryptoCallback(StreamHelper &helper, ScopedBuf &buf) {
    ScopedBuf tmp(0x1000);
    // Allocate a keyblock.
    const AEAD *aead = ciphersuite_get_aead(kCiphersuite);
    size_t key_len = aead_get_key_size(aead);
    size_t iv_len = ciphersuite_fix_nonce_length(kCiphersuite);
    ScopedBuf keyblock((key_len + iv_len) * 2);
    // Allocate a stream digest.
    const HASH *hash = ciphersuite_get_hash(kCiphersuite);
    ScopedBuf digest(hash_get_output_size(hash));
    // Generate the keyblock.
    TlsHelper &tls_helper = static_cast<TlsHelper &>(helper);
    TLS *tls = tls_helper.GetTLS();
    BUF *master = tls_get_master_secret(tls);
    HandshakeTest *test = static_cast<HandshakeTest *>(tls_helper.GetParent());
    if (!test) {
      return false;
    }
    if (!prf(tmp.Get(), hash, master, kKeyExpansion, test->server_random_.Get(),
             test->client_random_.Get(), keyblock.Get())) {
      return false;
    }
    BUF client_write_key = buf_init();
    buf_malloc(keyblock.Get(), key_len, &client_write_key);
    buf_produce(&client_write_key, key_len, NULL);
    BUF server_write_key = buf_init();
    buf_malloc(keyblock.Get(), key_len, &server_write_key);
    buf_produce(&server_write_key, key_len, NULL);
    BUF client_write_iv = buf_init();
    buf_malloc(keyblock.Get(), iv_len, &client_write_iv);
    buf_produce(&client_write_iv, iv_len, NULL);
    BUF server_write_iv = buf_init();
    buf_malloc(keyblock.Get(), iv_len, &server_write_iv);
    buf_produce(&server_write_iv, iv_len, NULL);
    // Do client/server specific bits.
    CHUNK *record = nullptr;
    BUF *key = nullptr;
    BUF *iv = nullptr;
    const char *label = nullptr;
    if (tls_helper.GetLabel().compare(kClientCrypto) == 0) {
      record = tls_helper.GetRecord(kRecv);
      key = &client_write_key;
      iv = &client_write_iv;
      label = kClientFinished;
      STREAM *server_recv = tls_helper.GetStream(kIoServer, kRecv);
      if (!stream_clone_digest(server_recv, tmp.Get(), digest.Get())) {
        return false;
      }
    } else {
      record = tls_helper.GetRecord(kSend);
      key = &server_write_key;
      iv = &server_write_iv;
      label = kServerFinished;
      STREAM *server_send = tls_helper.GetStream(kIoServer, kSend);
      stream_final_digest(server_send, digest.Get());
    }
    // Enable the cipher and generate the verify message.
    buf_reset(buf.Get(), 0);
    buf_produce(buf.Get(), 4, nullptr);
    BUF *region = tls_get_region(tls);
    return record_set_ciphersuite(record, region, kCiphersuite, key, iv) &&
           prf(tmp.Get(), hash, master, label, digest.Get(), nullptr,
               buf.Get());
  }
};

using HandshakeDeathTest = HandshakeTest;

TEST_P(HandshakeDeathTest, NullParameters) {
  EXPECT_ASSERT(handshake_size(nullptr));
  EXPECT_ASSERT(handshake_init(nullptr, tls_helper_.GetTLS(), &handshake_));
  EXPECT_ASSERT(handshake_init(region_.Get(), nullptr, &handshake_));
  EXPECT_ASSERT(handshake_init(region_.Get(), tls_helper_.GetTLS(), nullptr));
  EXPECT_ASSERT(handshake_connect(nullptr));
}

TEST_P(HandshakeDeathTest, OutOfMemory) {
  ScopedBuf empty;
  EXPECT_FALSE(handshake_init(empty.Get(), tls_helper_.GetTLS(), &handshake_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
}

TEST_P(HandshakeTest, PerformHandshake) {
  TLS *tls = tls_helper_.GetTLS();
  const TLS_CONFIG *config = tls_get_config(tls);
  size_t size = config_get_max_aead_size(config);
  size += handshake_size(config);
  do {
    random_fake_seed(0xdeadbeef);
    region_.Reset(size);
    EXPECT_TRUE(handshake_init(region_.Get(), tls, &handshake_));
    while (!handshake_connect(&handshake_)) {
      ASSERT_TRUE(tls_helper_.ReadNext());
    }
  } while (tls_helper_.ReadNext());
}

INSTANTIATE_TEST_CASE_P(Tls1_2, HandshakeTest,
                        ::testing::ValuesIn(HandshakeTest::GetData()));
INSTANTIATE_TEST_CASE_P(Tls1_2, HandshakeDeathTest,
                        ::testing::Values(HandshakeTest::GetData()[0]));

}  // namespace vapidssl
