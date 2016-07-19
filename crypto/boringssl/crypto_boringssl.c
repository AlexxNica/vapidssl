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

#include "crypto/crypto.h"

#include <assert.h>
#include <stdlib.h>

#include "base/error.h"
#include "public/error.h"
#include "third_party/boringssl/include/openssl/err.h"

// Library routines

tls_result_t crypto_error(void *ignored) {
  const char *file = NULL;
  int line = -1;
  int reason = (int)ERR_get_error_line(&file, &line);
  ERR_clear_error();
  return error_set(file, line, kTlsErrCrypto, reason);
}
