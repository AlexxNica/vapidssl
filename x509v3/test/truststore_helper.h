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

#ifndef VAPIDSSL_X509V3_TEST_TRUSTSTORE_HELPER_H
#define VAPIDSSL_X509V3_TEST_TRUSTSTORE_HELPER_H

#include <stddef.h>
#include <stdint.h>

namespace vapidssl {

class TruststoreHelper {
 public:
  static const size_t dn_len;
  static const uint8_t dn[];

  static const size_t key_len;
  static const uint8_t key[];
};

}  // namespace vapidssl

#endif  // VAPIDSSL_X509V3_TEST_TRUSTSTORE_HELPER_H
