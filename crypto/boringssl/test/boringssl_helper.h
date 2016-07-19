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

#ifndef VAPIDSSL_CRYPTO_BORINGSSL_HELPER_H
#define VAPIDSSL_CRYPTO_BORINGSSL_HELPER_H

#include "crypto/test/crypto_helper.h"

#include <stdint.h>
#include <map>
#include <memory>
#include <string>

#include "base/buf.h"
#include "base/test/error_helper.h"
#include "base/test/error_listener.h"
#include "public/error.h"
#include "third_party/boringssl/crypto/test/file_test.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// BoringSslHelper is a CryptoHelper (which in turn is a PlatformHelper) which
// uses BoringSSL as its crypto implementation.
class BoringSslHelper : public CryptoHelper {
 public:
  BoringSslHelper() = default;
  ~BoringSslHelper() override = default;
  BoringSslHelper &operator=(const BoringSslHelper &) = delete;
  BoringSslHelper(const BoringSslHelper &) = delete;

  // RegisterListener adds a test event listener to |ErrorHelper|'s list and
  // returns for assignment in a static initializer.
  static ::testing::TestEventListener *RegisterListener();

  // SetDataFile takes a path, |path|, that gives the location of this test's
  // test data file relative to the project root. If |path_| is already set or
  // |path| does not reference a valid file, it returns false without
  // modification; otherwise it returns true.
  bool SetDataFile(const std::string &path) override;

  // HasAttribute returns whether an optional attribute named by |tag| was
  // provided in the last set of attributes read by |ReadNext|.
  bool HasAttribute(const std::string &tag) override;

  // ReadNext updates |attributes_| with values of the next |iteration_|'s data
  // in the test's associated test data file described by |path_|. If |path_| is
  // unset or an error occurs during reading, it returns false; otherwise it
  // returns true.
  bool ReadNext() override;

  // KeyexFinish performs the server side computation of the key exchange
  // algorithm.  It produces a |shared| key from two values derived from the
  // test data file: the server's |secret|, and the offer that the client
  // |accept|ed.
  void KeyexFinish(ScopedBuf &secret, ScopedBuf &accept,
                   ScopedBuf &shared) override;

 private:
  // file_test_ reuses BoringSSL's own test code to provide lists of sets of
  // named test data attributes that can be easily specified in text files.
  std::unique_ptr<FileTest> file_test_;

  // BoringSslHelper::CryptoListener responds to BoringSSL errors.
  class CryptoListener : public ::vapidssl::ErrorListener {
   public:
    CryptoListener();

   protected:
    // GetReasonAsString retrieves the BoringSSL error messages.
    const std::string &GetReasonAsString(int reason) override;
  };
};

}  // namespace vapidssl

#endif  // VAPIDSSL_CRYPTO_BORINGSSL_HELPER_H
