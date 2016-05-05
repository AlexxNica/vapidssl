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

extern "C" {
#include "vapidssl/internal/error.h"
}
#include <errno.h>
#include "gtest/gtest.h"

namespace {


TEST(ErrorDeathTest, PutAndGetErrorUninitialized) {
  /* Check each function's behavior when errors haven't been initialized. */
  ASSERT_EQ(error_clear(), kTlsFailure);
  ASSERT_DEATH(ERROR_SET(kTlsErrVapid, EAGAIN), "");
  ASSERT_DEATH(TLS_ERROR_get(NULL, NULL, NULL, NULL), "");
  ASSERT_DEATH(TLS_ERROR_test(kTlsErrVapid, EAGAIN), "");
  ASSERT_EQ(TLS_ERROR_cleanup(), (void *)NULL);
}

TEST(ErrorTest, InsufficientMemory) {
  size_t len;
  ASSERT_EQ(TLS_ERROR_size(NULL), kTlsFailure);
  ASSERT_EQ(TLS_ERROR_size(&len), kTlsSuccess);
  void *mem = NULL;
  ASSERT_EQ(TLS_ERROR_init(mem, len), kTlsFailure);
  mem = malloc(len);
  ASSERT_EQ(TLS_ERROR_init(mem, 0), kTlsFailure);
  ASSERT_EQ(TLS_ERROR_init(mem, len - 1), kTlsFailure);
  ASSERT_EQ(TLS_ERROR_init(mem, len), kTlsSuccess);
  free(TLS_ERROR_cleanup());
}

TEST(ErrorTest, GetSuccess) {
  size_t len;
  ASSERT_EQ(TLS_ERROR_size(&len), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_init(malloc(len), len), kTlsSuccess);
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check all fields are zero/null when no error. */
  ASSERT_EQ(TLS_ERROR_get(&source, &reason, &file, &line), kTlsSuccess);
  ASSERT_EQ(source, 0);
  ASSERT_EQ(reason, 0);
  ASSERT_EQ(file, (void *)NULL);
  ASSERT_EQ(line, 0);
  free(TLS_ERROR_cleanup());
}

TEST(ErrorTest, PutAndGetError) {
  size_t len;
  ASSERT_EQ(TLS_ERROR_size(&len), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_init(malloc(len), len), kTlsSuccess);
  /* Check we can set an error. */
  int anchor = __LINE__;
  ASSERT_EQ(ERROR_SET(kTlsErrVapid, kTlsErrOutOfMemory), kTlsFailure);
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check the error we get matches the one we set. */
  ASSERT_EQ(TLS_ERROR_get(&source, &reason, &file, &line), kTlsSuccess);
  ASSERT_EQ(source, kTlsErrVapid);
  ASSERT_EQ(reason, kTlsErrOutOfMemory);
  ASSERT_EQ(file, __FILE__);
  ASSERT_EQ(line, anchor + 1);
  free(TLS_ERROR_cleanup());
}

TEST(ErrorTest, TestError) {
  size_t len;
  ASSERT_EQ(TLS_ERROR_size(&len), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_init(malloc(len), len), kTlsSuccess);
  ASSERT_EQ(ERROR_SET(kTlsErrArch, EAGAIN), kTlsFailure);
  /* Check the error matches both source and reason. */
  ASSERT_EQ(TLS_ERROR_test(kTlsErrVapid, EAGAIN), kTlsFailure);
  ASSERT_EQ(TLS_ERROR_test(kTlsErrArch, kTlsErrNotImplemented), kTlsFailure);
  ASSERT_EQ(TLS_ERROR_test(kTlsErrArch, EAGAIN), kTlsSuccess);
  free(TLS_ERROR_cleanup());
}

TEST(ErrorTest, ClearError) {
  size_t len;
  ASSERT_EQ(TLS_ERROR_size(&len), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_init(malloc(len), len), kTlsSuccess);
  /* Check we can clear when no error. */
  ASSERT_EQ(error_clear(), kTlsSuccess);
  /* Check we can clear when there is an error. */
  ASSERT_EQ(ERROR_SET(kTlsErrArch, EAGAIN), kTlsFailure);
  ASSERT_EQ(TLS_ERROR_test(kTlsErrArch, EAGAIN), kTlsSuccess);
  ASSERT_EQ(error_clear(), kTlsSuccess);
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check that the error was cleared. */
  ASSERT_EQ(TLS_ERROR_get(&source, &reason, &file, &line), kTlsSuccess);
  ASSERT_EQ(source, 0);
  ASSERT_EQ(reason, 0);
  ASSERT_EQ(file, (void *)NULL);
  ASSERT_EQ(line, 0);
  free(TLS_ERROR_cleanup());
}

TEST(ErrorTest, DoublePutAndGetError) {
  size_t len;
  ASSERT_EQ(TLS_ERROR_size(&len), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_init(malloc(len), len), kTlsSuccess);
  /* Check we can put multiple errors. */
  int anchor = __LINE__;
  ASSERT_EQ(ERROR_SET(kTlsErrArch, EAGAIN), kTlsFailure);
  ASSERT_EQ(ERROR_SET(kTlsErrVapid, kTlsErrNotImplemented), kTlsFailure);
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check we get the most recent error. */
  ASSERT_EQ(TLS_ERROR_get(&source, &reason, &file, &line), kTlsSuccess);
  ASSERT_EQ(source, kTlsErrVapid);
  ASSERT_EQ(reason, kTlsErrNotImplemented);
  ASSERT_EQ(file, __FILE__);
  ASSERT_EQ(line, anchor + 2);
  /* Check we STILL get the most recent error even after it has been gotten.
   */
  ASSERT_EQ(TLS_ERROR_get(&source, &reason, &file, &line), kTlsSuccess);
  ASSERT_EQ(source, kTlsErrVapid);
  ASSERT_EQ(reason, kTlsErrNotImplemented);
  ASSERT_EQ(file, __FILE__);
  ASSERT_EQ(line, anchor + 2);
  free(TLS_ERROR_cleanup());
}

TEST(ErrorTest, GetIndividualErrorDetails) {
  size_t len;
  ASSERT_EQ(TLS_ERROR_size(&len), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_init(malloc(len), len), kTlsSuccess);
  int anchor = __LINE__;
  ASSERT_EQ(ERROR_SET(kTlsErrArch, EAGAIN), kTlsFailure);
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check we can get just the source. */
  ASSERT_EQ(TLS_ERROR_get(NULL, NULL, NULL, NULL), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_get(&source, NULL, NULL, NULL), kTlsSuccess);
  ASSERT_EQ(source, kTlsErrArch);
  /* Check we can get just the reason. */
  ASSERT_EQ(TLS_ERROR_get(NULL, NULL, NULL, NULL), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_get(NULL, &reason, NULL, NULL), kTlsSuccess);
  ASSERT_EQ(reason, EAGAIN);
  /* Check we can get just the file. */
  ASSERT_EQ(TLS_ERROR_get(NULL, NULL, NULL, NULL), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_get(NULL, NULL, &file, NULL), kTlsSuccess);
  ASSERT_EQ(file, __FILE__);
  /* Check we can get just the line. */
  ASSERT_EQ(TLS_ERROR_get(NULL, NULL, NULL, NULL), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_get(NULL, NULL, NULL, &line), kTlsSuccess);
  ASSERT_EQ(line, anchor + 1);
  free(TLS_ERROR_cleanup());
}

TEST(ErrorDeathTest, CleanupErrors) {
  size_t len;
  ASSERT_EQ(TLS_ERROR_size(&len), kTlsSuccess);
  ASSERT_EQ(TLS_ERROR_init(malloc(len), len), kTlsSuccess);
  /* Check we can cleanup with an error present. */
  ASSERT_EQ(ERROR_SET(kTlsErrArch, EAGAIN), kTlsFailure);
  ASSERT_EQ(TLS_ERROR_test(kTlsErrArch, EAGAIN), kTlsSuccess);
  uint8_t *mem = (uint8_t *)TLS_ERROR_cleanup();
  ASSERT_NE(mem, (void *)NULL);
  size_t i;
  for (i = 0; i < len; i++) {
    ASSERT_EQ(mem[i], 0);
  }
  /* Check that errors are now uninitialized. */
  ASSERT_EQ(TLS_ERROR_cleanup(), (void *)NULL);
  ASSERT_DEATH(TLS_ERROR_get(NULL, NULL, NULL, NULL), "");
  ASSERT_DEATH(ERROR_SET(kTlsErrVapid, EAGAIN), "");
  /* Check we can reinitialize. */
  TLS_ERROR_init(mem, len);
  int anchor = __LINE__;
  ASSERT_EQ(ERROR_SET(kTlsErrArch, EAGAIN), kTlsFailure);
  tls_error_source_t source;
  int reason, line;
  const char *file;
  ASSERT_EQ(TLS_ERROR_get(&source, &reason, &file, &line), kTlsSuccess);
  ASSERT_EQ(source, kTlsErrArch);
  ASSERT_EQ(reason, EAGAIN);
  ASSERT_EQ(file, __FILE__);
  ASSERT_EQ(line, anchor + 1);
  free(TLS_ERROR_cleanup());
}

}  // namespace
