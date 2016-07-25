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

#include "x509v3/oid.h"

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/test/scoped_buf.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

TEST(OidTest, NullParams) {
  ScopedBuf buf;
  EXPECT_ASSERT(oid_match(nullptr));
}

TEST(OidTest, ShortBuf) {
  std::vector<uint8_t> v = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01};
  ScopedBuf buf(v);
  EXPECT_EQ(oid_match(buf.Get()), kOidUnknown);
}

TEST(OidTest, LongBuf) {
  std::vector<uint8_t> v = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                            0x0d, 0x01, 0x01, 0x0b, 0xff};
  ScopedBuf buf(v);
  EXPECT_EQ(oid_match(buf.Get()), kOidUnknown);
}

TEST(OidTest, MismatchedBuf) {
  std::vector<uint8_t> v = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                            0x0d, 0x01, 0x01, 0xb0};
  ScopedBuf buf(v);
  EXPECT_EQ(oid_match(buf.Get()), kOidUnknown);
}

TEST(OidTest, MatchingBuf) {
  std::vector<uint8_t> v = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                            0x0d, 0x01, 0x01, 0x0b};
  ScopedBuf buf(v);
  EXPECT_EQ(oid_match(buf.Get()), kOidSha256WithRsaEncryption);
}

}  // namespace vapidssl
