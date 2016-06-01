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

#ifndef VAPIDSSL_BASE_TEST_ERROR_TEST_HELPER_H
#define VAPIDSSL_BASE_TEST_ERROR_TEST_HELPER_H

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <set>

#include "base/buf.h"
#include "base/test/error_listener.h"
#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

/* ErrorTestHelper provides several methods to manage VapidSSL's errors during
 * uint testing.  It is not directly used by unit test cases. */
class ErrorTestHelper {
 public:
  /* GetListeners returns a reference to the list of |TestEventListener|s that
   * have been added via |AddListener|. |TestEventListener|s are described in
   * AdvancedGuide.md#extending-google-test-by-handling-test-events. */
  static std::vector<::testing::TestEventListener *> &GetListeners();

  /* AddListener adds a |TestEventListener| to the static list then returns its
   * argument.  Listeners need to be added before |main| is called; thus the
   * proper way to use this method is as a static initializer:
   *    const ::testing::TestEventListener *kSomeListener =
   *      ErrorTestHelper::AddListener(new SomeTestEventListener); */
  static ::testing::TestEventListener *AddListener(
      ::testing::TestEventListener *listener);

  /* Init registers the listeners and configures an |EnvironmentWithErrors|.  If
   * |verbose| is true, it will register all listeners added with |AddListener|,
   * otherwise it will only register |kUncheckedListener|.  This method must be
   * called after |InitGoogleTest| but before |RUN_ALL_TESTS|. */
  static void Init(bool verbose);

  /* ErrorTestHelper itself should not be instantiated! */
  ErrorTestHelper() = delete;
  ~ErrorTestHelper() = default;
  ErrorTestHelper &operator=(const ErrorTestHelper &) = delete;
  ErrorTestHelper(const ErrorTestHelper &) = delete;

 private:
  /* ErrorTestHelper::Environment sets up and tears down the thread-local
   * error storage as needed. See Google Test's
   * AdvancedGuide.md#global-set-up-and-tear-down*/
  class EnvironmentWithErrors : public ::testing::Environment {
   protected:
    void SetUp() override;
    void TearDown() override;

   private:
    /* err_ wraps the memory allocated by |SetUp|. */
    std::unique_ptr<uint8_t[]> err_;
  };

  class VapidListener : public ErrorListener {
   protected:
    /* HandleError implements |ErrorListener::HandleError|, and handles
     * VapidSSL errors. */
    bool HandleError(tls_error_source_t source, int reason) override;
  };

  class UncheckedListener : public ::testing::EmptyTestEventListener {
   protected:
    /* OnTestCaseEnd is called after each test case completes and fails if
     * VapidSSL indicates an error.  Expected errors should be automatically
     * checked and cleared using |EXPECT_ERROR| and |ASSERT_ERROR| from
     * test/macros.h. */
    void OnTestCaseEnd(const ::testing::TestCase &test_case) override;
  };
};

} /* namespace vapidssl */

#endif /* VAPIDSSL_BASE_TEST_ERROR_TEST_HELPER_H */
