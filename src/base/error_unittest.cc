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

#include "base/error.h"

#include <errno.h>
#include <memory>

#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"
#include "vapidssl/error.h"

namespace vapidssl {

TEST(ErrorTest, GetSuccess) {
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check all fields are zero/null when no error. */
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, 0);
  EXPECT_EQ(reason, 0);
  EXPECT_EQ(file, nullptr);
  EXPECT_EQ(line, 0);
}

TEST(ErrorTest, PutAndGetError) {
  /* Check we can set an error. */
  int anchor = __LINE__;
  EXPECT_FALSE(ERROR_SET(kTlsErrArch, EAGAIN));
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check the error we get matches the one we set. */
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, kTlsErrArch);
  EXPECT_EQ(reason, EAGAIN);
  EXPECT_EQ(file, __FILE__);
  EXPECT_EQ(line, anchor + 1);
}

TEST(ErrorTest, TestError) {
  EXPECT_FALSE(ERROR_SET(kTlsErrArch, EAGAIN));
  /* Check the error matches both source and reason. */
  EXPECT_FALSE(TLS_ERROR_test(kTlsErrVapid, EAGAIN));
  EXPECT_FALSE(TLS_ERROR_test(kTlsErrArch, kTlsErrNotImplemented));
  EXPECT_TRUE(TLS_ERROR_test(kTlsErrArch, EAGAIN));
}

TEST(ErrorTest, ClearError) {
  /* Check we can clear when no error. */
  EXPECT_TRUE(error_clear());
  /* Check we can clear when there is an error. */
  EXPECT_FALSE(ERROR_SET(kTlsErrArch, EAGAIN));
  EXPECT_TRUE(TLS_ERROR_test(kTlsErrArch, EAGAIN));
  EXPECT_TRUE(error_clear());
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check that the error was cleared. */
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, 0);
  EXPECT_EQ(reason, 0);
  EXPECT_EQ(file, nullptr);
  EXPECT_EQ(line, 0);
}

TEST(ErrorTest, DoublePutAndGetError) {
  /* Check we can put multiple errors. */
  int anchor = __LINE__;
  EXPECT_FALSE(ERROR_SET(kTlsErrArch, EAGAIN));
  EXPECT_FALSE(ERROR_SET(kTlsErrVapid, kTlsErrNotImplemented));
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check we get the most recent error. */
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, kTlsErrVapid);
  EXPECT_EQ(reason, kTlsErrNotImplemented);
  EXPECT_EQ(file, __FILE__);
  EXPECT_EQ(line, anchor + 2);
  /* Check we STILL get the most recent error even after it has been gotten.
   */
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, kTlsErrVapid);
  EXPECT_EQ(reason, kTlsErrNotImplemented);
  EXPECT_EQ(file, __FILE__);
  EXPECT_EQ(line, anchor + 2);
}

TEST(ErrorTest, GetIndividualErrorDetails) {
  int anchor = __LINE__;
  EXPECT_FALSE(ERROR_SET(kTlsErrArch, EAGAIN));
  tls_error_source_t source;
  int reason, line;
  const char *file;
  /* Check we can get just the source. */
  EXPECT_TRUE(TLS_ERROR_get(NULL, NULL, NULL, NULL));
  EXPECT_TRUE(TLS_ERROR_get(&source, NULL, NULL, NULL));
  EXPECT_EQ(source, kTlsErrArch);
  /* Check we can get just the reason. */
  EXPECT_TRUE(TLS_ERROR_get(NULL, NULL, NULL, NULL));
  EXPECT_TRUE(TLS_ERROR_get(NULL, &reason, NULL, NULL));
  EXPECT_EQ(reason, EAGAIN);
  /* Check we can get just the file. */
  EXPECT_TRUE(TLS_ERROR_get(NULL, NULL, NULL, NULL));
  EXPECT_TRUE(TLS_ERROR_get(NULL, NULL, &file, NULL));
  EXPECT_EQ(file, __FILE__);
  /* Check we can get just the line. */
  EXPECT_TRUE(TLS_ERROR_get(NULL, NULL, NULL, NULL));
  EXPECT_TRUE(TLS_ERROR_get(NULL, NULL, NULL, &line));
  EXPECT_EQ(line, anchor + 1);
}

TEST(ErrorDeathTest, CleanupErrors) {
  size_t len = 0;
  EXPECT_TRUE(TLS_ERROR_size(&len));
  /* Check we can cleanup with an error present. */
  EXPECT_FALSE(ERROR_SET(kTlsErrArch, EAGAIN));
  EXPECT_TRUE(TLS_ERROR_test(kTlsErrArch, EAGAIN));
  uint8_t *mem = (uint8_t *)TLS_ERROR_cleanup();
  EXPECT_NE(mem, nullptr);
  for (size_t i = 0; i < len; ++i) {
    EXPECT_EQ(mem[i], 0);
  }
  /* Check that errors are now uninitialized. */
  EXPECT_EQ(TLS_ERROR_cleanup(), nullptr);
  EXPECT_ASSERT(TLS_ERROR_get(NULL, NULL, NULL, NULL));
  EXPECT_ASSERT(ERROR_SET(kTlsErrVapid, EAGAIN));
  /* Check we can reinitialize. */
  TLS_ERROR_init(mem, len);
  int anchor = __LINE__;
  EXPECT_FALSE(ERROR_SET(kTlsErrArch, EAGAIN));
  tls_error_source_t source;
  int reason, line;
  const char *file;
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, kTlsErrArch);
  EXPECT_EQ(reason, EAGAIN);
  EXPECT_EQ(file, __FILE__);
  EXPECT_EQ(line, anchor + 1);
}

TEST(ErrorDeathTest, PutAndGetErrorUninitialized) {
  /* Uninitialize. */
  size_t len;
  EXPECT_TRUE(TLS_ERROR_size(&len));
  void *mem = TLS_ERROR_cleanup();
  EXPECT_NE(mem, nullptr);
  /* Check each function's behavior when errors have been uninitialized. */
  EXPECT_FALSE(error_clear());
  EXPECT_ASSERT(ERROR_SET(kTlsErrVapid, EAGAIN));
  EXPECT_ASSERT(TLS_ERROR_get(NULL, NULL, NULL, NULL));
  EXPECT_ASSERT(TLS_ERROR_test(kTlsErrVapid, EAGAIN));
  EXPECT_EQ(TLS_ERROR_cleanup(), nullptr);
  /* Reinitialize. */
  EXPECT_TRUE(TLS_ERROR_init(mem, len));
}

TEST(ErrorTest, InsufficientMemory) {
  /* Uninitialize. */
  size_t len;
  EXPECT_TRUE(TLS_ERROR_size(&len));
  void *mem = TLS_ERROR_cleanup();
  EXPECT_NE(mem, nullptr);
  /* Check that initialization fails without sufficient memory. */
  EXPECT_FALSE(TLS_ERROR_size(NULL));
  EXPECT_TRUE(TLS_ERROR_size(&len));
  EXPECT_FALSE(TLS_ERROR_init(NULL, len));
  EXPECT_FALSE(TLS_ERROR_init(mem, 0));
  EXPECT_FALSE(TLS_ERROR_init(mem, len - 1));
  /* Reinitialize. */
  EXPECT_TRUE(TLS_ERROR_init(mem, len));
}

} /* namespace vapidssl */
