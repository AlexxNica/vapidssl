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

#include "base/platform/thread.h"

#include <assert.h>
#include <stdlib.h>

// NOTE: This file consciously avoids calling any of the error.h functions, as
// it is the only file that errors.c has a dependency on.

// g_local is the "thread local storage" for the non-threaded implementation.
// Since there's no threads, a single global variable suffices.
static void *g_local = NULL;

// Library routines.

void *thread_get_local(void) {
  return g_local;
}

void thread_set_local(void *mem) {
  assert(!g_local || !mem);
  g_local = mem;
}
