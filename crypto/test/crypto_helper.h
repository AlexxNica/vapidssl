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

#ifndef VAPIDSSL_CRYPTO_TEST_CRYPTO_HELPER_H
#define VAPIDSSL_CRYPTO_TEST_CRYPTO_HELPER_H

#include "base/platform/test/platform_helper.h"

#include <stdint.h>
#include <memory>
#include <string>

#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// CryptoHelper is the abstract base class for the unit tests that use
// cryptographic test vectors from test data files.
class CryptoHelper : public PlatformHelper {
 public:
  CryptoHelper() = default;
  ~CryptoHelper() override = default;
  CryptoHelper &operator=(const CryptoHelper &) = delete;
  CryptoHelper(const CryptoHelper &) = delete;

  // KeyexFinish performs the server side computation of the key exchange
  // algorithm.  It produces a |shared| key from two values derived from the
  // test data file: the server's |secret|, and the offer that the client
  // |accept|ed.
  virtual void KeyexFinish(ScopedBuf &secret, ScopedBuf &accept,
                           ScopedBuf &shared) = 0;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_CRYPTO_TEST_CRYPTO_HELPER_H
