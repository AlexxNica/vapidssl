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

#include <errno.h>
#include <memory>

#include "public/error.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

TEST(ErrorTest, GetSuccess) {
  tls_error_source_t source;
  int reason, line;
  const char *file;
  // Check all fields are zero/null when no error.
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, 0);
  EXPECT_EQ(reason, 0);
  EXPECT_EQ(file, nullptr);
  EXPECT_EQ(line, 0);
}

TEST(ErrorTest, PutAndGetError) {
  // Check we can set an error.
  int anchor = __LINE__;
  EXPECT_FALSE(ERROR_SET(kTlsErrPlatform, EAGAIN));
  tls_error_source_t source;
  int reason, line;
  const char *file;
  // Check the error we get matches the one we set.
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, kTlsErrPlatform);
  EXPECT_EQ(reason, EAGAIN);
  EXPECT_EQ(file, __FILE__);
  EXPECT_EQ(line, anchor + 1);
}

TEST(ErrorTest, TestError) {
  EXPECT_FALSE(ERROR_SET(kTlsErrPlatform, EAGAIN));
  // Check the error matches both source and reason.
  EXPECT_FALSE(TLS_ERROR_test(kTlsErrVapid, EAGAIN));
  EXPECT_FALSE(TLS_ERROR_test(kTlsErrPlatform, kTlsErrNotImplemented));
  EXPECT_TRUE(TLS_ERROR_test(kTlsErrPlatform, EAGAIN));
}

TEST(ErrorTest, ClearError) {
  // Check we can clear when no error.
  EXPECT_TRUE(error_clear());
  // Check we can clear when there is an error.
  EXPECT_FALSE(ERROR_SET(kTlsErrPlatform, EAGAIN));
  EXPECT_TRUE(TLS_ERROR_test(kTlsErrPlatform, EAGAIN));
  EXPECT_TRUE(error_clear());
  tls_error_source_t source;
  int reason, line;
  const char *file;
  // Check that the error was cleared.
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, 0);
  EXPECT_EQ(reason, 0);
  EXPECT_EQ(file, nullptr);
  EXPECT_EQ(line, 0);
}

TEST(ErrorTest, DoublePutAndGetError) {
  // Check we can put multiple errors.
  int anchor = __LINE__;
  EXPECT_FALSE(ERROR_SET(kTlsErrPlatform, EAGAIN));
  EXPECT_FALSE(ERROR_SET(kTlsErrVapid, kTlsErrNotImplemented));
  tls_error_source_t source;
  int reason, line;
  const char *file;
  // Check we get the most recent error.
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, kTlsErrVapid);
  EXPECT_EQ(reason, kTlsErrNotImplemented);
  EXPECT_EQ(file, __FILE__);
  EXPECT_EQ(line, anchor + 2);
  // Check we STILL get the most recent error even after it has been gotten./
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, kTlsErrVapid);
  EXPECT_EQ(reason, kTlsErrNotImplemented);
  EXPECT_EQ(file, __FILE__);
  EXPECT_EQ(line, anchor + 2);
}

TEST(ErrorTest, GetIndividualErrorDetails) {
  int anchor = __LINE__;
  EXPECT_FALSE(ERROR_SET(kTlsErrPlatform, EAGAIN));
  tls_error_source_t source;
  int reason, line;
  const char *file;
  // Check we can get just the source.
  EXPECT_TRUE(TLS_ERROR_get(nullptr, nullptr, nullptr, nullptr));
  EXPECT_TRUE(TLS_ERROR_get(&source, nullptr, nullptr, nullptr));
  EXPECT_EQ(source, kTlsErrPlatform);
  // Check we can get just the reason.
  EXPECT_TRUE(TLS_ERROR_get(nullptr, nullptr, nullptr, nullptr));
  EXPECT_TRUE(TLS_ERROR_get(nullptr, &reason, nullptr, nullptr));
  EXPECT_EQ(reason, EAGAIN);
  // Check we can get just the file.
  EXPECT_TRUE(TLS_ERROR_get(nullptr, nullptr, nullptr, nullptr));
  EXPECT_TRUE(TLS_ERROR_get(nullptr, nullptr, &file, nullptr));
  EXPECT_EQ(file, __FILE__);
  // Check we can get just the line.
  EXPECT_TRUE(TLS_ERROR_get(nullptr, nullptr, nullptr, nullptr));
  EXPECT_TRUE(TLS_ERROR_get(nullptr, nullptr, nullptr, &line));
  EXPECT_EQ(line, anchor + 1);
}

TEST(ErrorDeathTest, CleanupErrors) {
  size_t len = 0;
  EXPECT_TRUE(TLS_ERROR_size(&len));
  // Check we can cleanup with an error present.
  EXPECT_FALSE(ERROR_SET(kTlsErrPlatform, EAGAIN));
  EXPECT_TRUE(TLS_ERROR_test(kTlsErrPlatform, EAGAIN));
  uint8_t *mem = (uint8_t *)TLS_ERROR_cleanup();
  EXPECT_NE(mem, nullptr);
  for (size_t i = 0; i < len; ++i) {
    EXPECT_EQ(mem[i], 0);
  }
  // Check that errors are now uninitialized.
  EXPECT_EQ(TLS_ERROR_cleanup(), nullptr);
  EXPECT_ASSERT(TLS_ERROR_get(nullptr, nullptr, nullptr, nullptr));
  EXPECT_ASSERT(ERROR_SET(kTlsErrVapid, EAGAIN));
  // Check we can reinitialize.
  TLS_ERROR_init(mem, len);
  int anchor = __LINE__;
  EXPECT_FALSE(ERROR_SET(kTlsErrPlatform, EAGAIN));
  tls_error_source_t source;
  int reason, line;
  const char *file;
  EXPECT_TRUE(TLS_ERROR_get(&source, &reason, &file, &line));
  EXPECT_EQ(source, kTlsErrPlatform);
  EXPECT_EQ(reason, EAGAIN);
  EXPECT_EQ(file, __FILE__);
  EXPECT_EQ(line, anchor + 1);
}

TEST(ErrorDeathTest, PutAndGetErrorUninitialized) {
  // Uninitialize.
  size_t len;
  EXPECT_TRUE(TLS_ERROR_size(&len));
  void *mem = TLS_ERROR_cleanup();
  EXPECT_NE(mem, nullptr);
  // Check each function's behavior when errors have been uninitialized.
  EXPECT_FALSE(error_clear());
  EXPECT_ASSERT(ERROR_SET(kTlsErrVapid, EAGAIN));
  EXPECT_ASSERT(TLS_ERROR_get(nullptr, nullptr, nullptr, nullptr));
  EXPECT_ASSERT(TLS_ERROR_test(kTlsErrVapid, EAGAIN));
  EXPECT_EQ(TLS_ERROR_cleanup(), nullptr);
  // Reinitialize.
  EXPECT_TRUE(TLS_ERROR_init(mem, len));
}

TEST(ErrorTest, InsufficientMemory) {
  // Uninitialize.
  size_t len;
  EXPECT_TRUE(TLS_ERROR_size(&len));
  void *mem = TLS_ERROR_cleanup();
  EXPECT_NE(mem, nullptr);
  // Check that initialization fails without sufficient memory.
  EXPECT_FALSE(TLS_ERROR_size(nullptr));
  EXPECT_TRUE(TLS_ERROR_size(&len));
  EXPECT_FALSE(TLS_ERROR_init(nullptr, len));
  EXPECT_FALSE(TLS_ERROR_init(mem, 0));
  EXPECT_FALSE(TLS_ERROR_init(mem, len - 1));
  // Reinitialize.
  EXPECT_TRUE(TLS_ERROR_init(mem, len));
}

}  // namespace vapidssl
