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

#ifndef VAPIDSSL_TEST_MACROS_H
#define VAPIDSSL_TEST_MACROS_H

#include <stdio.h>

#include "base/error.h"
#include "base/platform/test/platform_helper.h"
#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

// EXPECT_ASSERT checks that a given call aborts the program because of an
// assertion.  Assertions should only be caused by programmer error, and not by
// incorrect API usage or network I/O.
#define EXPECT_ASSERT(expr) EXPECT_DEATH(expr, PlatformHelper::AssertionRegex)

// ASSERT_ASSERT is identical to |EXPECT_ASSERT| except that on failure, it
// immediately returns from the current function.
#define ASSERT_ASSERT(expr) ASSERT_DEATH(expr, PlatformHelper::AssertionRegex)

// EXPECT_ERROR checks to see if VapidSSL's most recent error has a given
// |source| and |reason|.  Errors should be the result of bad API parameters and
// network I/O; programmer errors should result in assertions instead. If there
// is no error or if the error is different than expected, the test assertion
// fails. This macro also has the side-effect of clearing the expected error.
// Failure to use this macro or equivalent calls may cause the UncheckedListener
// to incorrectly fail tests with expected errors.
#define EXPECT_ERROR(source, reason)           \
  EXPECT_TRUE(TLS_ERROR_test(source, reason)); \
  error_clear()

// ASSERT_ERROR is identical to |EXPECT_ERROR| except that on failure, it
// immediately returns from the current function.
#define ASSERT_ERROR(source, reason)           \
  ASSERT_TRUE(TLS_ERROR_test(source, reason)); \
  error_clear()

// HEXDUMP is a simple loop that can be used to print a byte array as a hex
// stream when debugging.  It should not be needed during normal unit testing;
// it is included here for the developer's convenience.
#define HEXDUMP(buf, len)                                                  \
  printf("HEXDUMP: %s (%s:%d): ", #buf, __FILE__, __LINE__);               \
  if (!(buf)) {                                                              \
    printf("(null)");                                                      \
  } else {                                                                 \
    for (size_t i##__LINE__ = 0; (i##__LINE__) < (len); ++(i##__LINE__)) { \
      printf("%02x", (buf)[i##__LINE__]);                                  \
    }                                                                      \
  }                                                                        \
  printf("\n");

// BUFDUMP wraps a call to |HEXDUMP| with a |BUF| argument.  It violates the
// abstraction of |BUF|.  It should not be needed during normal unit testing;
// it is included here for the developer's convenience.
#define BUFDUMP(buf) \
  HEXDUMP(&((buf)->raw[(buf)->offset]), (buf)->length - (buf)->offset)

// LENDUMP wraps a call to |HEXDUMP| assuming a pattern of '<name>' and
// '<name>_len', as is typically the case in BoringSSL's code.
#define LENDUMP(buf) HEXDUMP(buf, buf##_len)

#endif  // VAPIDSSL_TEST_MACROS_H
