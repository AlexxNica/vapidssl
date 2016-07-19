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

#include "base/test/error_listener.h"

#include <iostream>

#include "base/error.h"
#include "base/platform/thread.h"
#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// Public methods

tls_error_source_t ErrorListener::GetSource() {
  return source_.first;
}

const std::string &ErrorListener::GetSourceAsString() {
  return source_.second;
}

const std::string &ErrorListener::GetReasonAsString(int reason) {
  auto i = reasons_.find(reason);
  if (i != reasons_.end()) {
    return i->second;
  }
  static const std::string kUnknownReason = "Unknown reason";
  return kUnknownReason;
}

// Protected methods

ErrorListener::ErrorListener(tls_error_source_t e, const std::string &s)
    : source_(e, s) {}

bool ErrorListener::HasReason(int reason) {
  return reasons_.find(reason) != reasons_.end();
}

void ErrorListener::AddReason(int i, const std::string &s) {
  reasons_[i] = s;
}

void ErrorListener::OnTestPartResult(const ::testing::TestPartResult &result) {
  if (!result.failed()) {
    return;
  }
  // This event listener may be called when TLS_ERROR_init has not been called,
  // so we're forced to break the abstraction and check.
  if (!thread_get_local()) {
    return;
  }
  // Get the error.
  tls_error_source_t source;
  int reason = -1;
  const char *file = nullptr;
  int line = -1;
  if (!TLS_ERROR_get(&source, &reason, &file, &line) || !file) {
    return;
  }
  // Handle it if it's an error we know about.
  if (source == GetSource()) {
    std::cout << "  Origin: " << file << ":" << line << std::endl;
    std::cout << "  Source: " << GetSourceAsString() << std::endl;
    std::cout << "  Reason: " << GetReasonAsString(reason);
    std::cout << " (" << reason << ")" << std::endl;
    error_clear();
  }
}

}  // namespace vapidssl
