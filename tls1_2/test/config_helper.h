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

#ifndef VAPIDSSL_TLS1_2_TEST_CONFIG_HELPER_H
#define VAPIDSSL_TLS1_2_TEST_CONFIG_HELPER_H

#include <stddef.h>

#include "base/test/scoped_buf.h"
#include "public/config.h"

namespace vapidssl {

// ConfigHelper is a simple wrapper calls that creates and manages a TLS_CONFIG
// for use in testing.
class ConfigHelper {
 public:
  ConfigHelper();
  virtual ~ConfigHelper() = default;
  ConfigHelper &operator=(const ConfigHelper &) = delete;
  ConfigHelper(const ConfigHelper &) = delete;

  // GetConfig returns a pointer to TLS configuration object.
  virtual TLS_CONFIG *GetConfig();

 private:
  // config_ represents the TLS library's configuration.
  TLS_CONFIG *config_;
  // region_ is the memory that backs the TLS_CONFIG object.
  ScopedBuf region_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_TLS1_2_TEST_CONFIG_HELPER_H
