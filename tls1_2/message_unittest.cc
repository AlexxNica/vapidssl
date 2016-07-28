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

#include "tls1_2/message.h"
#include "tls1_2/message_internal.h"

#include "base/buf.h"
#include "base/error.h"
#include "base/platform/random.h"
#include "base/platform/test/io_mock.h"
#include "base/test/scoped_buf.h"
#include "common/chunk.h"
#include "common/test/stream_helper.h"
#include "crypto/hash.h"
#include "crypto/test/crypto_test.h"
#include "crypto/test/hash_test.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"
#include "tls1_2/test/record_test.h"

namespace vapidssl {

class MessageTest : public RecordTest {
 public:
  ~MessageTest() override = default;
  MessageTest &operator=(const MessageTest &) = delete;
  MessageTest(const MessageTest &) = delete;

 protected:
  MessageTest() : recv_(), send_(), received_() {}

  void ResetMessage() {
    region_.Reset(LIST_SIZE(STREAM_HASH, VAPIDSSL_HASHES + 1) +
                  message_size(GetConfig(), kRecv) +
                  message_size(GetConfig(), kSend));
    EXPECT_TRUE(
        LIST_NEW(STREAM_HASH, region_.Get(), VAPIDSSL_HASHES + 1, &hashes_));
    EXPECT_TRUE(
        message_init(GetConfig(), region_.Get(), kIoLoopback, kSend, &send_));
    EXPECT_TRUE(
        message_init(GetConfig(), region_.Get(), kIoLoopback, kRecv, &recv_));
    STREAM *tx = message_get_stream(&send_);
    STREAM *rx = message_get_stream(&recv_);
    stream_set_hashes(tx, &hashes_);
    stream_set_hashes(rx, &hashes_);
    received_.Reset(buf_size(GetPlaintext(0)));
  }

  MESSAGE recv_;
  MESSAGE send_;
  ScopedBuf received_;
  LIST hashes_;
};

using MessageTestOnce = MessageTest;
using MessageDeathTest = MessageTest;

TEST_P(MessageDeathTest, InitWithBadParameters) {
  ASSERT_TRUE(ReadNext());
  EXPECT_ASSERT(message_size(nullptr, kRecv));

  EXPECT_ASSERT(
      message_init(nullptr, region_.Get(), kIoLoopback, kSend, &send_));
  EXPECT_ASSERT(message_init(GetConfig(), nullptr, kIoLoopback, kSend, &send_));
  EXPECT_ASSERT(
      message_init(GetConfig(), region_.Get(), kIoLoopback, kSend, nullptr));

  region_.Reset(1);
  EXPECT_FALSE(
      message_init(GetConfig(), region_.Get(), kIoLoopback, kSend, &send_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
}

TEST_P(MessageDeathTest, SendAndRecvBadAlert) {
  ASSERT_TRUE(ReadNext());
  // Check null parameters
  EXPECT_ASSERT(message_send_alert(nullptr, kFalse, kTlsErrCloseNotify));
  EXPECT_ASSERT(message_recv_alert(nullptr, kTlsErrCloseNotify));
  // Check incorrect message
  EXPECT_ASSERT(message_send_alert(&recv_, kFalse, kTlsErrCloseNotify));
  EXPECT_ASSERT(message_recv_alert(&send_, kTlsErrCloseNotify));
}

TEST_P(MessageTestOnce, SendAndRecvAlert) {
  ASSERT_TRUE(ReadNext());
  // Send and receive an alert normally
  ResetMessage();
  EXPECT_TRUE(message_send_alert(&send_, kFalse, kTlsErrCloseNotify));
  EXPECT_TRUE(message_recv_alert(&recv_, kTlsErrCloseNotify));
  // Discard other data when looking for an alert
  ResetMessage();
  EXPECT_TRUE(message_send_appdata(&send_, GetPlaintext(0)));
  EXPECT_TRUE(message_send_alert(&send_, kFalse, kTlsErrCloseNotify));
  EXPECT_TRUE(message_send_alert(&send_, kFalse, kTlsErrNoRenegotiation));
  EXPECT_TRUE(message_recv_alert(&recv_, kTlsErrCloseNotify));
}

TEST_P(MessageDeathTest, SendAndRecvBadHandshake) {
  ASSERT_TRUE(ReadNext());
  message_handshake_t type;
  // Check null parameters
  EXPECT_ASSERT(message_send_handshake(nullptr, kClientHello, 2));
  EXPECT_ASSERT(message_recv_handshake(nullptr, &type));
  EXPECT_ASSERT(message_recv_handshake(&recv_, nullptr));
  // Check incorrect message
  EXPECT_ASSERT(message_send_handshake(&recv_, kClientHello, 2));
  EXPECT_ASSERT(message_recv_handshake(&send_, &type));
  // Send and receive a handshake message after application data
  ResetMessage();
  EXPECT_TRUE(message_send_appdata(&send_, GetPlaintext(0)));
  EXPECT_TRUE(message_recv_appdata(&recv_, received_.Get()));
  EXPECT_PRED2(buf_equal, GetPlaintext(0), received_.Get());
  EXPECT_ASSERT(message_send_handshake(&send_, kClientHello, 2));
  EXPECT_FALSE(message_recv_handshake(&recv_, &type));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
}

TEST_P(MessageTestOnce, SendAndRecvHandshake) {
  ASSERT_TRUE(ReadNext());
  STREAM *tx = nullptr;
  STREAM *rx = nullptr;
  message_handshake_t type;
  uint16_t value;
  // Send and receive a handshake message normally
  ResetMessage();
  EXPECT_TRUE(message_send_handshake(&send_, kClientHello, 2));
  tx = message_get_stream(&send_);
  EXPECT_TRUE(stream_send_u16(tx, 0xABCD));
  EXPECT_TRUE(stream_flush(tx));
  EXPECT_TRUE(message_recv_handshake(&recv_, &type));
  EXPECT_EQ(type, kClientHello);
  rx = message_get_stream(&recv_);
  EXPECT_TRUE(stream_recv_u16(rx, &value));
  EXPECT_EQ(value, 0xABCDU);
}

TEST_P(MessageDeathTest, SendAndRecvCcsWithNullParameters) {
  ASSERT_TRUE(ReadNext());
  // Check null parameters
  EXPECT_ASSERT(message_send_ccs(nullptr, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nonce_.Get()));
  EXPECT_ASSERT(message_send_ccs(&send_, nullptr, GetCiphersuite(), key_.Get(),
                                 nonce_.Get()));
  EXPECT_ASSERT(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                                 nullptr, nonce_.Get()));
  EXPECT_ASSERT(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nullptr));
  EXPECT_ASSERT(message_recv_ccs(nullptr, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nonce_.Get()));
  EXPECT_ASSERT(message_recv_ccs(&recv_, nullptr, GetCiphersuite(), key_.Get(),
                                 nonce_.Get()));
  EXPECT_ASSERT(message_recv_ccs(&recv_, region_.Get(), GetCiphersuite(),
                                 nullptr, nonce_.Get()));
  EXPECT_ASSERT(message_recv_ccs(&recv_, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nullptr));
}

TEST_P(MessageDeathTest, SendAndRecvCcsWithIncorrectMessage) {
  ASSERT_TRUE(ReadNext());
  // Check incorrect message
  EXPECT_ASSERT(message_send_ccs(&recv_, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nonce_.Get()));
  EXPECT_ASSERT(message_recv_ccs(&send_, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nonce_.Get()));
}

TEST_P(MessageDeathTest, SendAndRecvCcsAfterAnotherCcs) {
  ASSERT_TRUE(ReadNext());
  // Send and receive a CCS message after another CCS message
  ResetMessage();
  EXPECT_TRUE(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                               key_.Get(), nonce_.Get()));
  EXPECT_TRUE(message_recv_ccs(&recv_, region_.Get(), GetCiphersuite(),
                               key_.Get(), nonce_.Get()));
  EXPECT_ASSERT(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nonce_.Get()));
  EXPECT_FALSE(message_recv_ccs(&recv_, region_.Get(), GetCiphersuite(),
                                key_.Get(), nonce_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
}

TEST_P(MessageDeathTest, SendAndRecvCcsAfterApplicationData) {
  ASSERT_TRUE(ReadNext());
  // Send and receive a CCS message after application data
  ResetMessage();
  EXPECT_TRUE(message_send_appdata(&send_, GetPlaintext(0)));
  EXPECT_TRUE(message_recv_appdata(&recv_, received_.Get()));
  EXPECT_PRED2(buf_equal, GetPlaintext(0), received_.Get());
  EXPECT_ASSERT(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nonce_.Get()));
  EXPECT_FALSE(message_recv_ccs(&recv_, region_.Get(), GetCiphersuite(),
                                key_.Get(), nonce_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
}

TEST_P(MessageDeathTest, SendAndRecvCcsWithInsufficientMemory) {
  ASSERT_TRUE(ReadNext());
  // Send and receive a CCS message with insufficient memory
  ResetMessage();
  BUF tmp = buf_init();
  EXPECT_TRUE(buf_malloc(region_.Get(),
                         region_.Len() - buf_allocated(region_.Get()), &tmp));
  EXPECT_FALSE(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                                key_.Get(), nonce_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  buf_free(&tmp);
  EXPECT_TRUE(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                               key_.Get(), nonce_.Get()));
  EXPECT_TRUE(buf_malloc(region_.Get(),
                         region_.Len() - buf_allocated(region_.Get()), &tmp));
  EXPECT_FALSE(message_recv_ccs(&recv_, region_.Get(), GetCiphersuite(),
                                key_.Get(), nonce_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  buf_free(&tmp);
}

TEST_P(MessageTestOnce, SendAndRecvCcs) {
  ASSERT_TRUE(ReadNext());
  // Send and receive a CCS message normally
  ResetMessage();
  EXPECT_TRUE(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                               key_.Get(), nonce_.Get()));
  EXPECT_TRUE(message_recv_ccs(&recv_, region_.Get(), GetCiphersuite(),
                               key_.Get(), nonce_.Get()));
}

TEST_P(MessageDeathTest, SendAndRecvBadApplicationData) {
  ASSERT_TRUE(ReadNext());
  // Check null parameters
  EXPECT_ASSERT(message_send_appdata(nullptr, GetPlaintext(0)));
  EXPECT_ASSERT(message_send_appdata(&send_, nullptr));
  EXPECT_ASSERT(message_recv_appdata(nullptr, received_.Get()));
  EXPECT_ASSERT(message_recv_appdata(&recv_, nullptr));
  // Check incorrect message
  EXPECT_ASSERT(message_send_appdata(&recv_, GetPlaintext(0)));
  EXPECT_ASSERT(message_recv_appdata(&send_, received_.Get()));
  // Send and receive application data after a CCS message
  ResetMessage();
  EXPECT_TRUE(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                               key_.Get(), nonce_.Get()));
  EXPECT_TRUE(message_recv_ccs(&recv_, region_.Get(), GetCiphersuite(),
                               key_.Get(), nonce_.Get()));
  EXPECT_ASSERT(message_send_appdata(&send_, GetPlaintext(0)));
  EXPECT_FALSE(message_recv_appdata(&recv_, received_.Get()));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
}

TEST_P(MessageTestOnce, SendAndRecvApplicationData) {
  ASSERT_TRUE(ReadNext());
  // Send and receive application data normally
  ResetMessage();
  EXPECT_TRUE(message_send_appdata(&send_, GetPlaintext(0)));
  EXPECT_TRUE(message_recv_appdata(&recv_, received_.Get()));
  EXPECT_PRED2(buf_equal, GetPlaintext(0), received_.Get());
}

TEST_P(MessageTest, SendAndRecv) {
  STREAM *tx = nullptr;
  STREAM *rx = nullptr;
  uint16_t u16 = 0;
  uint32_t u32 = 0;
  message_handshake_t type;
  while (ReadNext()) {
    ResetMessage();
    // Send hello, CCS, and finished messages
    EXPECT_TRUE(message_send_handshake(&send_, kClientHello, 2));
    tx = message_get_stream(&send_);
    EXPECT_TRUE(stream_send_u16(tx, 0xAABB));
    EXPECT_TRUE(stream_flush(tx));
    EXPECT_TRUE(message_send_ccs(&send_, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nonce_.Get()));
    EXPECT_TRUE(message_send_handshake(&send_, kFinished, 4));
    EXPECT_TRUE(stream_send_u32(tx, 0xCCDDEEFF));
    EXPECT_TRUE(stream_flush(tx));
    // Receive hello, CCS, and finished messages
    EXPECT_TRUE(message_recv_handshake(&recv_, &type));
    EXPECT_EQ(type, kClientHello);
    rx = message_get_stream(&recv_);
    EXPECT_TRUE(stream_recv_u16(rx, &u16));
    EXPECT_EQ(u16, 0xAABBU);
    EXPECT_TRUE(message_recv_ccs(&recv_, region_.Get(), GetCiphersuite(),
                                 key_.Get(), nonce_.Get()));
    EXPECT_TRUE(message_recv_handshake(&recv_, &type));
    EXPECT_EQ(type, kFinished);
    EXPECT_TRUE(stream_recv_u32(rx, &u32));
    EXPECT_EQ(u32, 0xCCDDEEFFU);
    // Send some application data
    EXPECT_TRUE(message_send_appdata(&send_, GetPlaintext(0)));
    EXPECT_TRUE(message_recv_appdata(&recv_, received_.Get()));
    EXPECT_PRED2(buf_equal, GetPlaintext(0), received_.Get());
    // Send and receive a close message
    EXPECT_TRUE(message_send_alert(&send_, kTrue, kTlsErrCloseNotify));
    EXPECT_TRUE(message_recv_alert(&recv_, kTlsErrCloseNotify));
  }
}

INSTANTIATE_TEST_CASE_P(Tls1_2, MessageTest,
                        ::testing::ValuesIn(RecordTest::GetData()));
INSTANTIATE_TEST_CASE_P(Tls1_2, MessageTestOnce,
                        ::testing::Values(RecordTest::GetData()[0]));
INSTANTIATE_TEST_CASE_P(Tls1_2, MessageDeathTest,
                        ::testing::Values(RecordTest::GetData()[0]));

}  // namespace vapidssl
