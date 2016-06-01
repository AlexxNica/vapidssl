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

#ifndef VAPIDSSL_TEST_MACROS_H
#define VAPIDSSL_TEST_MACROS_H

#include "base/error.h"
#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

/* EXPECT_ASSERT checks that a given call aborts the program because of an
 * assertion.  Assertions should only be caused by programmer
 * error, and not by incorrect API usage or network I/O. */
#define EXPECT_ASSERT(expr) EXPECT_DEATH(expr, ".*: Assertion `.*' failed\\.")

/* ASSERT_ASSERT is identical to |EXPECT_ASSERT| except that on failure, it
 * immediately returns from the current function. */
#define ASSERT_ASSERT(expr) ASSERT_DEATH(expr, ".*: Assertion `.*' failed\\.")

/* EXPECT_ERROR checks to see if VapidSSL's most recent error has a given
 * |source| and |reason|.  Errors should be the result of bad API parameters and
 * network I/O; programmer errors should result in assertions instead. If there
 * is no error or if the error is different than expected, the test assertion
 * fails. This macro also has the side-effect of clearing the expected error.
 * Failure to use this macro or equivalent calls may cause the UncheckedListener
 * to incorrectly fail tests with expected errors. */
#define EXPECT_ERROR(source, reason)           \
  EXPECT_TRUE(TLS_ERROR_test(source, reason)); \
  error_clear()

/* ASSERT_ERROR is identical to |EXPECT_ERROR| except that on failure, it
 * immediately returns from the current function. */
#define ASSERT_ERROR(source, reason)           \
  ASSERT_TRUE(TLS_ERROR_test(source, reason)); \
  error_clear()

#endif /* VAPIDSSL_TEST_MACROS_H */
