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

#include "crypto/test/crypto_test.h"

#include <stdint.h>
#include <stdlib.h>

#include "base/error.h"
#include "base/platform/test/time_fake.h"
#include "crypto/boringssl/test/boringssl_helper.h"
#include "public/error.h"

namespace vapidssl {

namespace {

// Fri, 01 Jul 2016 00:00:00 GMT
const uint64_t kFixedDateTime = 1467331200;

}  // namespace

void CryptoTest::SetUp() {
  const struct test_data_st &test_data = GetParam();
  ASSERT_TRUE(crypto_helper_->SetDataFile(test_data.path));
  time_fake_set(kFixedDateTime);
}

CryptoHelper &CryptoTest::GetCryptoHelper() {
  return *crypto_helper_;
}

bool CryptoTest::HasAttribute(const std::string &tag) {
  return crypto_helper_->HasAttribute(tag);
}

void CryptoTest::AddHexAttribute(const std::string &tag, ScopedBuf &buf,
                                 bool optional) {
  crypto_helper_->AddHexAttribute(tag, buf, optional);
}

void CryptoTest::AddStringAttribute(const std::string &tag, std::string &str,
                                    bool optional) {
  crypto_helper_->AddStringAttribute(tag, str, optional);
}

bool CryptoTest::ReadNext() {
  return crypto_helper_->ReadNext();
}

void CryptoTest::KeyexFinish(ScopedBuf &secret, ScopedBuf &accept,
                             ScopedBuf &shared) {
  return crypto_helper_->KeyexFinish(secret, accept, shared);
}


}  // namespace vapidssl
