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

#include "base/platform/test/time_fake.h"
#include "base/platform/time.h"

#include <assert.h>
#include <stdint.h>
#include <time.h>

// g_start is the time from which we start counting seconds, in epoch time.  It
// is initially 0, meaning |time_now| will return epoch time.
int64_t g_start = 0;

static_assert(sizeof(time_t) >= sizeof(uint64_t), "64 bit time");
int64_t time_now(void) {
  return (int64_t)time(NULL) - g_start;
}

void time_fake_set(uint64_t seconds) {
  g_start = seconds - (int64_t)time(NULL);
}
