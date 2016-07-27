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

#include "x509v3/asn1.h"
#include "x509v3/asn1_internal.h"

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/platform/test/io_mock.h"
#include "common/test/stream_helper.h"
#include "public/error.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

class Asn1Test : public ::testing::Test {
 public:
  ~Asn1Test() override = default;
  Asn1Test &operator=(const Asn1Test &) = delete;
  Asn1Test(const Asn1Test &) = delete;

 protected:
  Asn1Test() = default;

  // SetUp configures the data streams and the ASN.1 decoder.
  void SetUp() override {
    region_.Reset(0x1000);
    stream_helper_.SetNesting(kRecv, 4);
    stream_helper_.Reset();
    STREAM *rx = stream_helper_.GetStream(kIoLoopback, kRecv);
    asn1_init(region_.Get(), rx, &asn1_);
  }

  // Send puts |bytes| into the loopback stream to be received by the calls
  // below.
  bool Send(std::vector<uint8_t> bytes) {
    stream_helper_.Reset();
    STREAM *tx = stream_helper_.GetStream(kIoLoopback, kSend);
    for (auto byte : bytes) {
      if (!stream_send_u8(tx, byte)) {
        return false;
      }
    }
    return true;
  }

  // ReceiveType wraps a call to |asn1_recv_type| with checks for I/O retries.
  bool ReceiveType() {
    stream_helper_.Flush();
    while (!asn1_recv_type(&asn1_)) {
      if (!TLS_ERROR_test(kTlsErrPlatform, io_mock_retry())) {
        return false;
      }
    }
    return true;
  }

  // ReceiveEncoding wraps a call to |asn1_recv_encoding| with checks for I/O
  // retries.
  bool ReceiveEncoding() {
    stream_helper_.Flush();
    while (!asn1_recv_encoding(&asn1_)) {
      if (!TLS_ERROR_test(kTlsErrPlatform, io_mock_retry())) {
        return false;
      }
    }
    return true;
  }

  // ReceiveData wraps a call to |asn1_recv_data| with checks for I/O retries.
  bool ReceiveData(asn1_tag_number_t tag) {
    stream_helper_.Flush();
    while (!asn1_recv_data(&asn1_, tag)) {
      if (!TLS_ERROR_test(kTlsErrPlatform, io_mock_retry())) {
        return false;
      }
    }
    return true;
  }

  // ReceiveNested wraps a call to |asn1_nested_begin| with checks for I/O
  // retries.
  bool ReceiveNested(asn1_tag_number_t tag) {
    stream_helper_.Flush();
    while (!asn1_nested_begin(&asn1_, tag)) {
      if (!TLS_ERROR_test(kTlsErrPlatform, io_mock_retry())) {
        return false;
      }
    }
    return true;
  }

  // SetTypeAndLen overrides the |type| and |len| fields of |asn1_|.
  void SetTypeAndLen(uint8_t type, uint16_t len) {
    asn1_.type = type;
    asn1_.len_len = (len < 0x100 ? 1 : 2);
    asn1_.len = len;
    asn1_.state = kAsn1LengthRead;
  }

  // region_ is the memory used during testing.
  ScopedBuf region_;
  // stream_helper_ manages the data streams used to send and receive data.
  StreamHelper stream_helper_;
  // asn1_ pares and decodes ASN.1/DER data.
  ASN1 asn1_;
};

using Asn1DeathTest = Asn1Test;

TEST_F(Asn1DeathTest, InitAsn1) {
  STREAM *rx = stream_helper_.GetStream(kIoLoopback, kRecv);
  EXPECT_ASSERT(asn1_init(nullptr, rx, &asn1_));
  EXPECT_ASSERT(asn1_init(region_.Get(), nullptr, &asn1_));
  EXPECT_ASSERT(asn1_init(region_.Get(), rx, nullptr));
  EXPECT_ASSERT(asn1_get_type(nullptr));
  EXPECT_ASSERT(asn1_get_type(&asn1_));
  EXPECT_ASSERT(asn1_get_len(nullptr));
  EXPECT_ASSERT(asn1_get_len(&asn1_));
  EXPECT_ASSERT(asn1_get_data(nullptr));
  EXPECT_ASSERT(asn1_get_data(&asn1_));
}

TEST_F(Asn1DeathTest, ReceiveTypeAndLength) {
  EXPECT_ASSERT(asn1_recv_type(nullptr));
  // Short form with zero length (and blocking I/O).
  stream_helper_.SetMtu(1);
  stream_helper_.Reset();
  EXPECT_TRUE(Send({kAsn1Null, 0x00}));
  EXPECT_TRUE(ReceiveType());
  EXPECT_EQ(asn1_get_type(&asn1_), kAsn1Null);
  EXPECT_EQ(asn1_get_len(&asn1_), 0U);
  // Long form with zero length (and blocking I/O).
  EXPECT_TRUE(Send({kAsn1Constructed | kAsn1Sequence, 0x80, 0x00}));
  EXPECT_FALSE(ReceiveType());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Long form length less than 128.
  stream_helper_.SetMtu(0);
  stream_helper_.Reset();
  EXPECT_TRUE(Send({kAsn1Constructed | kAsn1Sequence, 0x81, 0x7f}));
  EXPECT_FALSE(ReceiveType());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Long form length equal to 128.
  EXPECT_TRUE(Send({kAsn1Constructed | kAsn1Sequence, 0x81, 0x80}));
  EXPECT_TRUE(ReceiveType());
  EXPECT_EQ(asn1_get_len(&asn1_), 0x80U);
  stream_helper_.Reset();
  asn1_reset(&asn1_);
  // Long form length with leading zero byte.
  EXPECT_TRUE(Send({kAsn1Constructed | kAsn1Sequence, 0x82, 0x00, 0xff}));
  EXPECT_FALSE(ReceiveType());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Wrong construction
  EXPECT_TRUE(Send({kAsn1Constructed | kAsn1Boolean, 0x01}));
  EXPECT_FALSE(ReceiveType());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Short length for boolean
  EXPECT_TRUE(Send({kAsn1Boolean, 0x00}));
  EXPECT_FALSE(ReceiveType());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Long length for boolean
  EXPECT_TRUE(Send({kAsn1Boolean, 0x02}));
  EXPECT_FALSE(ReceiveType());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Zero length for integer
  EXPECT_TRUE(Send({kAsn1Integer, 0x00}));
  EXPECT_FALSE(ReceiveType());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Too short for bit string.
  EXPECT_TRUE(Send({kAsn1BitString, 0x00}));
  EXPECT_FALSE(ReceiveType());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Wrong length for NULL
  EXPECT_TRUE(Send({kAsn1Null, 0x01}));
  EXPECT_FALSE(ReceiveType());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
}

TEST_F(Asn1DeathTest, ReceiveEncoding) {
  // Invalid boolean.
  SetTypeAndLen(kAsn1Boolean, 1);
  EXPECT_TRUE(Send({0xfe}));
  EXPECT_FALSE(ReceiveEncoding());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Invalid bit string
  SetTypeAndLen(kAsn1BitString, 2);
  EXPECT_TRUE(Send({0x08, 0x00}));
  EXPECT_FALSE(ReceiveEncoding());
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
}

TEST_F(Asn1DeathTest, ReceiveData) {
  uint32_t value = 0;
  EXPECT_ASSERT(asn1_recv_data(nullptr, kAsn1Any));
  // Send boolean when we're expecting an integer.
  EXPECT_TRUE(Send({kAsn1Boolean, 0x01, 0x00}));
  EXPECT_FALSE(ReceiveData(kAsn1Integer));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Send boolean when we're expecting anything.
  EXPECT_TRUE(Send({kAsn1Boolean, 0x01, 0xff}));
  EXPECT_TRUE(ReceiveData(kAsn1Any));
  EXPECT_TRUE(buf_get_val(asn1_get_data(&asn1_), 1, &value));
  EXPECT_EQ(value, 0xffU);
}

TEST_F(Asn1DeathTest, ReceiveNested) {
  STREAM *rx = stream_helper_.GetStream(kIoLoopback, kRecv);
  uint32_t value = 0;
  EXPECT_ASSERT(asn1_nested_begin(nullptr, kAsn1Sequence));
  // Send integer when we're expecting a nested structure.
  EXPECT_TRUE(Send({kAsn1Integer, 0x01, 0x00}));
  EXPECT_FALSE(ReceiveNested(kAsn1Any));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
  // Check misalignment at end. ASN.1 notation is given inline.
  EXPECT_TRUE(Send({
      // seq0 ::= SEQUENCE {
      kAsn1Constructed | kAsn1Sequence, 0x0f,
      //     a INTEGER,
      0x02, 0x02, 0xde, 0xad,
      //     b INTEGER,
      0x02, 0x02, 0xbe, 0xef,
      //     c INTEGER,
      0x02, 0x02, 0xfe, 0xed,
      //     d INTEGER,
      0x02, 0x02, 0xfa, 0xce,
  }));
  EXPECT_TRUE(ReceiveNested(kAsn1Sequence));
  EXPECT_TRUE(ReceiveData(kAsn1Integer));
  EXPECT_TRUE(ReceiveData(kAsn1Integer));
  EXPECT_TRUE(ReceiveData(kAsn1Integer));
  EXPECT_FALSE(ReceiveData(kAsn1Integer));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrLengthMismatch);
  asn1_reset(&asn1_);
  // Send doubly-nested structure.  ASN.1 notation is given inline.
  EXPECT_TRUE(Send({
      // top ::= SEQUENCE {
      kAsn1Constructed | kAsn1Sequence, 0x12,
      //   seq1 ::= SEQUENCE {
      kAsn1Constructed | kAsn1Sequence, 0x08,
      //     x INTEGER,
      0x02, 0x02, 0xde, 0xad,
      //     y INTEGER
      0x02, 0x02, 0xbe, 0xef,
      //   },
      //   seq2 ::= SEQUENCE {
      kAsn1Constructed | kAsn1Sequence, 0x06,
      //     z INTEGER
      0x02, 0x04, 0xfe, 0xed, 0xfa, 0xce,
      //   }
      // }
  }));
  // Start 'top'.
  EXPECT_TRUE(ReceiveNested(kAsn1Sequence));
  EXPECT_FALSE(stream_nested_finish(rx));
  // Start 'seq1'.
  EXPECT_TRUE(ReceiveNested(kAsn1Sequence));
  EXPECT_FALSE(stream_nested_finish(rx));
  // Receive 'x'.
  EXPECT_TRUE(ReceiveData(kAsn1Integer));
  EXPECT_TRUE(buf_get_val(asn1_get_data(&asn1_), 2, &value));
  EXPECT_EQ(value, 0xdeadU);
  EXPECT_FALSE(stream_nested_finish(rx));
  // Receive 'y'.
  EXPECT_TRUE(ReceiveData(kAsn1Integer));
  EXPECT_TRUE(buf_get_val(asn1_get_data(&asn1_), 2, &value));
  EXPECT_EQ(value, 0xbeefU);
  // Finish 'seq1'.
  EXPECT_TRUE(stream_nested_finish(rx));
  // Start 'seq2'.
  EXPECT_TRUE(ReceiveNested(kAsn1Sequence));
  EXPECT_FALSE(stream_nested_finish(rx));
  // Receive 'z'.
  EXPECT_TRUE(ReceiveData(kAsn1Integer));
  EXPECT_TRUE(buf_get_val(asn1_get_data(&asn1_), 4, &value));
  EXPECT_EQ(value, 0xfeedfaceU);
  // Finish 'seq2'.
  EXPECT_TRUE(stream_nested_finish(rx));
  // Finish 'top'.
  EXPECT_TRUE(stream_nested_finish(rx));
}

}  // namespace vapidssl
