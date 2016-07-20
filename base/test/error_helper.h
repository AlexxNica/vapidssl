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

#ifndef VAPIDSSL_BASE_TEST_ERROR_HELPER_H
#define VAPIDSSL_BASE_TEST_ERROR_HELPER_H

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <set>

#include "base/buf.h"
#include "base/test/error_listener.h"
#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// ErrorHelper provides several methods to manage VapidSSL's errors during uint
// testing.  It is not directly used by unit test cases.
class ErrorHelper {
 public:
  // ErrorHelper itself should not be instantiated!
  ErrorHelper() = delete;
  ~ErrorHelper() = default;
  ErrorHelper &operator=(const ErrorHelper &) = delete;
  ErrorHelper(const ErrorHelper &) = delete;

  // GetListeners returns a reference to the list of |TestEventListener|s that
  // have been added via |AddListener|. |TestEventListener|s are described in
  // AdvancedGuide.md#extending-google-test-by-handling-test-events.
  static std::vector<ErrorListener *> &GetListeners();

  // AddListener adds a |TestEventListener| to the static list then returns its
  // argument.  Listeners need to be added before |main| is called; thus the
  // proper way to use this method is as a static initializer:    const
  // ::testing::TestEventListener *kSomeListener =
  // ErrorHelper::AddListener(new SomeTestEventListener); */
  static ErrorListener *AddListener(ErrorListener *listener);

  // Init registers the listeners and configures an |EnvironmentWithErrors|.  If
  // |verbose| is true, it will register all listeners added with |AddListener|,
  // otherwise it will only register |kUncheckedListener|.  This method must be
  // called after |InitGoogleTest| but before |RUN_ALL_TESTS|.
  static void Init(bool verbose);

  static const std::string &GetSourceAsString(tls_error_source_t source);
  static const std::string &GetReasonAsString(tls_error_source_t source,
                                              int reason);

 private:
  // ErrorHelper::Environment sets up and tears down the thread-local error
  // storage as needed. See Google Test's
  // AdvancedGuide.md#global-set-up-and-tear-down
  class EnvironmentWithErrors : public ::testing::Environment {
   protected:
    // SetUp prepares the testing environment by calling |TLS_ERROR_init|.
    void SetUp() override;

    // TearDown cleans up the testing environment by calling
    // |TLS_ERROR_cleanup|.
    void TearDown() override;

   private:
    // err_ wraps the memory allocated by |SetUp|.
    std::unique_ptr<uint8_t[]> err_;
  };

  class VapidListener : public ErrorListener {
   public:
    VapidListener();
  };

  class UncheckedListener : public ::testing::EmptyTestEventListener {
   public:
    explicit UncheckedListener(bool verbose);

   protected:
    // OnTestCaseEnd is called after each test case completes and fails if
    // VapidSSL indicates an error.  Expected errors should be automatically
    // checked and cleared using |EXPECT_ERROR| and |ASSERT_ERROR| from
    // test/macros.h.
    void OnTestCaseEnd(const ::testing::TestCase &test_case) override;

   private:
    // verbose_ indicates whether to print error details when a test case ends
    // with an error present.
    bool verbose_;
  };
};

}  // namespace vapidssl

#endif  // VAPIDSSL_BASE_TEST_ERROR_HELPER_H
