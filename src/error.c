/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "vapidssl/internal/error.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "vapidssl/arch/thread.h"

/* error_st represents an error, combining both an informational code as well as
 * information about where the error occurred. */
struct error_st {
  /* The __FILE__ where this error was generated. */
  const char* file;
  /* The __LINE__ where this error was generated. */
  int line;
  /* The code where this error was generated. */
  tls_error_source_t source;
  /* The specific error code for this error. */
  int reason;
};

/* Public functions */

tls_result_t TLS_ERROR_size(size_t* out) {
  if (!out) {
    return kTlsFailure;
  }
  *out = sizeof(struct error_st);
  return kTlsSuccess;
}

tls_result_t TLS_ERROR_init(void* mem, size_t len) {
  size_t needed;
  if (!TLS_ERROR_size(&needed) || !mem || len < needed) {
    return kTlsFailure;
  }
  memset(mem, 0, len);
  thread_set_local(mem);
  return kTlsSuccess;
}

tls_result_t TLS_ERROR_get(tls_error_source_t* out_source, int* out_reason,
                           const char** out_file, int* out_line) {
  struct error_st* local = thread_get_local();
  assert(local); /* Fail hard in debug mode if errors uninitialized. */
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
  struct error_st* local = thread_get_local();
  assert(local); /* Fail hard in debug mode if errors uninitialized. */
  if (!local || local->source != source || local->reason != reason) {
    return kTlsFailure;
  }
  return kTlsSuccess;
}

void* TLS_ERROR_cleanup(void) {
  void* mem = NULL;
  if (error_clear()) {
    mem = thread_get_local();
    thread_set_local(NULL);
  }
  return mem;
}

/* Library routines */

tls_result_t error_set(const char* file, int line, tls_error_source_t source,
                       int reason) {
  struct error_st* local = thread_get_local();
  /* This function MUST NOT be called before |TLS_ERROR_init|.  This constraint
   * is satisfied by having every |TLS_CONFIG_*| and |TLS_*| API check that
   * |error_clear| succeeds before proceeding.  If somehow we get here and the
   * constraint is not met, we assume there's been a memory corruption and
   * choose to die an ugly death. */
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
  void* local = thread_get_local();
  if (!local) {
    return kTlsFailure;
  }
  size_t len;
  TLS_ERROR_size(&len);
  memset(local, 0, len);
  return kTlsSuccess;
}
