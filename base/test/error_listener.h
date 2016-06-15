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

#ifndef VAPIDSSL_BASE_TEST_ERROR_LISTENER_H
#define VAPIDSSL_BASE_TEST_ERROR_LISTENER_H

#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// ErrorListener is a TestEventListener that responds to test results.  See
// AdvancedGuide.md#extending-google-test-by-handling-test-events in
// third_party/gtest/googletest/docs/ for more detail.
class ErrorListener : public ::testing::EmptyTestEventListener {
 protected:
  // OnTestPartResult is called after each test result and on failure prints the
  // details of an error, if present.  It clears the error.
  void OnTestPartResult(const ::testing::TestPartResult &result) override;

  // HandleError prints error details for errors that this listener recognizes
  // based on |source|.  It returns true if it can handle the error and false
  // otherwise.
  virtual bool HandleError(tls_error_source_t source, int reason) = 0;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_BASE_TEST_ERROR_LISTENER_H
