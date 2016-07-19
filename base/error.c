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

#include "base/error.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "base/platform/thread.h"
#include "public/error.h"

// error_st represents an error, combining both an informational code as well as
// information about where the error occurred.
struct error_st {
  // The __FILE__ where this error was generated.
  const char *file;
  // The __LINE__ where this error was generated.
  int line;
  // The code where this error was generated.
  tls_error_source_t source;
  // The specific error code for this error.
  int reason;
};

// Public functions

size_t TLS_ERROR_size() {
  return sizeof(struct error_st);
}

tls_result_t TLS_ERROR_init(void *mem, size_t len) {
  if (len < TLS_ERROR_size() || !mem) {
    return kTlsFailure;
  }
  memset(mem, 0, len);
  thread_set_local(mem);
  return kTlsSuccess;
}

tls_result_t TLS_ERROR_get(tls_error_source_t *out_source, int *out_reason,
                           const char **out_file, int *out_line) {
  struct error_st *local = thread_get_local();
  assert(local);  // Fail hard in debug mode if errors uninitialized.
  if (!local) {
    return kTlsFailure;
  }
  if (out_file) {
    *out_file = local->file;
  }
  if (out_line) {
    *out_line = local->line;
  }
  if (out_source) {
    *out_source = local->source;
  }
  if (out_reason) {
    *out_reason = local->reason;
  }
  return kTlsSuccess;
}

tls_result_t TLS_ERROR_test(tls_error_source_t source, int reason) {
  struct error_st *local = thread_get_local();
  assert(local);  // Fail hard in debug mode if errors uninitialized.
  if (!local || local->source != source || local->reason != reason) {
    return kTlsFailure;
  }
  return kTlsSuccess;
}

void *TLS_ERROR_cleanup(void) {
  void *mem = NULL;
  if (error_clear()) {
    mem = thread_get_local();
    thread_set_local(NULL);
  }
  return mem;
}

// Library routines

tls_result_t error_set(const char *file, int line, tls_error_source_t source,
                       int reason) {
  struct error_st *local = thread_get_local();
  // This function MUST NOT be called before |TLS_ERROR_init|.  This constraint
  // is satisfied by having every |TLS_CONFIG_*| and |TLS_*| API check that
  // |error_clear| succeeds before proceeding.  If somehow we get here and the
  // constraint is not met, we assume there's been a memory corruption and
  // choose to die an ugly death. */
  assert(local);
  if (!local) {
    abort();
  }
  local->file = file;
  local->line = line;
  local->source = source;
  local->reason = reason;
  return kTlsFailure;
}

tls_result_t error_clear() {
  void *local = thread_get_local();
  if (!local) {
    return kTlsFailure;
  }
  memset(local, 0, TLS_ERROR_size());
  return kTlsSuccess;
}
