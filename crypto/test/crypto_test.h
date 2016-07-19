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

#ifndef VAPIDSSL_CRYPTO_TEST_CRYPTO_TEST_H
#define VAPIDSSL_CRYPTO_TEST_CRYPTO_TEST_H

#include "third_party/gtest/googletest/include/gtest/gtest.h"

#include <stdint.h>
#include <memory>
#include <string>

#include "crypto/test/crypto_helper.h"
#include "public/error.h"

namespace vapidssl {

// The TEST_DATA struct associates an algorithm ID (and optional parameter) with
// a test data file.
typedef struct test_data_st {
  // algorithm is an algorithm ID, such as an |aead_t|, |hash_t|, |keyex_t|, or
  // |sign_t|.
  uint16_t algorithm;
  // parameter is optional, and used to further identify the algorithm, such as
  // an EC curve ID for a key exchange algorithm.
  uint16_t parameter;
  // path is the path to the test data file, relative to the project root.
  std::string path;
} TEST_DATA;

// CryptoTest is the base class for the unit tests that use cryptographic test
// vectors from test data files.
class CryptoTest : public ::testing::TestWithParam<TEST_DATA> {
 public:
  ~CryptoTest() override = default;
  CryptoTest &operator=(const CryptoTest &) = delete;
  CryptoTest(const CryptoTest &) = delete;

 protected:
  // Somewhat unusually, the implementation of this class in
  // crypto/test/crypto_test.cc is missing the constructor.  That can be found
  // in crypto/<provider>/crypto_test_<provider>.cc, where '<provider>' is a
  // specific crypto library implementation, such as 'boringssl'.
  CryptoTest();

  // SetUp is called at the start of each test.  In the case of |CryptoTest|, it
  // determines the test data file.
  void SetUp() override;

  // GetCryptoHelper returns the |CryptoHelper| for this object.
  virtual CryptoHelper &GetCryptoHelper();

  // HasAttribute returns whether an optional attribute named by |tag| was
  // provided in the last set of attributes read by |ReadNext|.
  virtual bool HasAttribute(const std::string &tag);

  // AddHexAttribute registers a |tag| to scan for in the test data file and an
  // unwrapped |buf| to use to wrap the data associated with that tag. It is an
  // error to call |AddHexAttribute| with a |buf| that already wraps memory, or
  // to call |AddHexAttribute| or |AddStringAttribute| twice with the same
  // |tag|.
  virtual void AddHexAttribute(const std::string &tag, ScopedBuf &buf,
                               bool optional = false);

  // AddStringAttribute registers a |tag| to scan for in the test data file and
  // an unwrapped |buf| to use to wrap the string associated with that tag. It
  // is an error to call |AddHexAttribute| with a |buf| that already wraps
  // memory, or to call |AddHexAttribute| or |AddStringAttribute| twice with the
  // same |tag|.
  virtual void AddStringAttribute(const std::string &tag, std::string &str,
                                  bool optional = false);

  // ReadNext invokes |crypto_helper_|'s |ReadNext| method to read the set of
  // attributes from the test data file.
  virtual bool ReadNext();

  // KeyexFinish performs the server side computation of the key exchange
  // algorithm.  It produces a |shared| key from two values derived from the
  // test data file: the server's |secret|, and the offer that the client
  // |accept|ed.
  virtual void KeyexFinish(ScopedBuf &secret, ScopedBuf &accept,
                           ScopedBuf &shared);

 private:
  // crypto_helper_ manages reading data from the test's data file and
  // performing server-specific crypto routines.  It must be set by the
  // constructor provided by the specific crypto implementation.
  std::unique_ptr<CryptoHelper> crypto_helper_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_CRYPTO_TEST_CRYPTO_TEST_H
