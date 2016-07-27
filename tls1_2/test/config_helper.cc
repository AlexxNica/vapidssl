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

#include "tls1_2/test/config_helper.h"

#include <stddef.h>

#include "base/buf.h"
#include "base/test/scoped_buf.h"
#include "public/config.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"
#include "x509v3/test/truststore_helper.h"

namespace vapidssl {

ConfigHelper::ConfigHelper() : config_(nullptr) {
  region_.Reset(TLS_CONFIG_size(1));
  if (!TLS_CONFIG_init(region_.Raw(), region_.Len(), 1, &config_) ||
      !TLS_CONFIG_trust_signer(config_, TruststoreHelper::dn,
                               TruststoreHelper::dn_len, TruststoreHelper::key,
                               TruststoreHelper::key_len)) {
    abort();
  }
}

TLS_CONFIG *ConfigHelper::GetConfig() {
  return config_;
}

}  // namespace vapidssl
