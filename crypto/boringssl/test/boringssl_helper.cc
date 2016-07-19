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

#include "crypto/boringssl/test/boringssl_helper.h"

#include <stdint.h>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "base/buf.h"
#include "third_party/boringssl/crypto/test/file_test.h"
#include "third_party/boringssl/include/openssl/curve25519.h"
#include "third_party/boringssl/include/openssl/err.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

static const ::testing::TestEventListener *kErrorListener =
    BoringSslHelper::RegisterListener();

::testing::TestEventListener *BoringSslHelper::RegisterListener() {
  return ErrorHelper::AddListener(new BoringSslHelper::CryptoListener());
}

bool BoringSslHelper::SetDataFile(const std::string &path) {
  if (!PlatformHelper::SetDataFile(path)) {
    return false;
  }
  file_test_.reset(new ::FileTest(path_.c_str()));
  return file_test_.get() != nullptr && file_test_->is_open();
}

bool BoringSslHelper::HasAttribute(const std::string &tag) {
  return file_test_.get() != nullptr && file_test_->HasAttribute(tag);
}

bool BoringSslHelper::ReadNext() {
  CryptoHelper::ReadNext();
  // Read the data into |file_test_|.
  if (file_test_.get() == nullptr || !file_test_->is_open()) {
    ADD_FAILURE() << "Test data file was not found.";
    return false;
  }
  if (file_test_->ReadNext() == ::FileTest::kReadEOF) {
    return false;
  }
  // Copy the hex data from |file_test_| to our |hex_attributes_|.
  std::vector<uint8_t> bytes;
  for (auto &i : optional_hex_) {
    if (!file_test_->HasAttribute(i.first)) {
      continue;
    }
    file_test_->GetBytes(&bytes, i.first);
    i.second->Reset(bytes);
  }
  for (auto &i : required_hex_) {
    if (!file_test_->GetBytes(&bytes, i.first)) {
      std::cerr << "Error reading from '" << path_ << "'." << std::endl;
      abort();
    }
    i.second->Reset(bytes);
  }
  // Copy the string data from |file_test_| to our |string_attributes_|.
  for (auto &i : optional_str_) {
    if (!file_test_->HasAttribute(i.first)) {
      continue;
    }
    file_test_->GetAttribute(i.second, i.first);
  }
  for (auto &i : required_str_) {
    if (!file_test_->GetAttribute(i.second, i.first)) {
      std::cerr << "Error reading from '" << path_ << "'." << std::endl;
      abort();
    }
  }
  return true;
}

void BoringSslHelper::KeyexFinish(ScopedBuf &secret, ScopedBuf &accept,
                                  ScopedBuf &shared) {
  EXPECT_TRUE(X25519(buf_as(shared.Get(), shared.Len()),
                     buf_as(secret.Get(), secret.Len()),
                     buf_as(accept.Get(), accept.Len())));
}

// CryptoListener methods

BoringSslHelper::CryptoListener::CryptoListener()
    : ErrorListener(kTlsErrCrypto, "BoringSSL libcrypto") {}

const std::string &BoringSslHelper::CryptoListener::GetReasonAsString(
    int reason) {
  if (!HasReason(reason)) {
    char error_string[1024] = {0};
    ERR_error_string_n((uint32_t)reason, error_string, sizeof(error_string));
    if (strlen(error_string) != 0) {
      AddReason(reason, error_string);
    }
  }
  return ErrorListener::GetReasonAsString(reason);
}

}  // namespace vapidssl
