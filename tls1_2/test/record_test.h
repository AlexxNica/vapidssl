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

#ifndef VAPIDSSL_TLS1_2_TEST_RECORD_TEST_H
#define VAPIDSSL_TLS1_2_TEST_RECORD_TEST_H

#include "common/test/chunk_test.h"

#include <stddef.h>

#include "public/config.h"
#include "public/error.h"
#include "tls1_2/test/config_helper.h"

namespace vapidssl {

class RecordTest : public ChunkTest {
 public:
  ~RecordTest() override = default;
  RecordTest &operator=(const RecordTest &) = delete;
  RecordTest(const RecordTest &) = delete;

  // GetData defines the cipher suites for each record that can be tested and
  // their associated test data files.
  static const std::vector<TEST_DATA> &GetData();

 protected:
  // kNumFragments is the number of fragments in the record, needed by
  // record_unittest.cc.
  static const size_t kNumFragments;

  RecordTest();

  // SetUp configures the test by reading the cipher suite from the test data
  // file.
  void SetUp() override;

  // GetConfig delegates to |config_helper_| to get its TLS_CONFIG.
  virtual const TLS_CONFIG *GetConfig();

  // GetCiphersuite returns this test's cipher suite.
  virtual tls_ciphersuite_t GetCiphersuite();

  // ResetRecords reinitializes the TLS connections data chunks.
  virtual void ResetRecords();

  // ReadNext invokes |ChunkTest::ReadNext|, then manipulates the buffer to
  // manage the nonce according to the selected |ciphersuite_|.
  bool ReadNext() override;

 private:
  // ciphersuite_ is the TLS 1.2 cipher suite to use when sending or receiving
  // records with this test.
  tls_ciphersuite_t ciphersuite_;
  // config_helper_ manages the TLS configuration.
  ConfigHelper config_helper_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_TLS1_2_TEST_RECORD_TEST_H
