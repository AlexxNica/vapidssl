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
 public:
  virtual ~ErrorListener() = default;
  ErrorListener &operator=(const ErrorListener &) = delete;
  ErrorListener(const ErrorListener &) = delete;

  // GetSource returns the source of the error being handled.
  tls_error_source_t GetSource();

  // GetSource returns the source of the error being handled as a human readable
  // string.
  const std::string &GetSourceAsString();

  // GetSource interprets the reason of the error being handled as a human
  // readable string.  Subclasses should override this method.
  virtual const std::string &GetReasonAsString(int reason);

 protected:
  ErrorListener(tls_error_source_t source_e, const std::string &source_s);

  // AddReason maps an integer |reason_i| to a human readable |reason_s|.
  void AddReason(int reason_i, const std::string &reason_s);

  // HasReason returns whether a |reason| is recognized by this listener.
  // Subclasses should override this method.
  virtual bool HasReason(int reason);

  // OnTestPartResult is called after each test result and on failure prints the
  // details of an error, if present.  It clears the error.
  void OnTestPartResult(const ::testing::TestPartResult &result) override;

  std::pair<tls_error_source_t, std::string> source_;
  std::map<int, std::string> reasons_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_BASE_TEST_ERROR_LISTENER_H
