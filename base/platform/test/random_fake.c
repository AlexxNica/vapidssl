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

#include "base/platform/random.h"

#include <stdint.h>

// Library routines.

uint32_t g_rand = 0xdeadbeef;

void random_buf(BUF *out) {
  size_t len = buf_available(out);
  uint8_t *raw = NULL;
  buf_produce(out, len, &raw);
  for (size_t i = 0; i < len; ++i) {
    g_rand *= 1103515245;
    g_rand += 12345;
    raw[i] = (uint8_t)(g_rand >> 16);
  }
}
