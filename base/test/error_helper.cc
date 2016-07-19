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

#include "base/test/error_helper.h"

#include <stddef.h>
#include <stdint.h>
#include <iostream>
#include <vector>

#include "base/error.h"
#include "base/platform/thread.h"
#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

std::vector<::testing::TestEventListener *> &ErrorHelper::GetListeners() {
  static std::vector<::testing::TestEventListener *> *listeners_ =
      new std::vector<::testing::TestEventListener *>();
  return *listeners_;
}

::testing::TestEventListener *ErrorHelper::AddListener(
    ::testing::TestEventListener *listener) {
  GetListeners().push_back(listener);
  return listener;
}

void ErrorHelper::Init(bool verbose) {
  auto &listeners = ::testing::UnitTest::GetInstance()->listeners();
  if (verbose) {
    auto &extra = GetListeners();
    for (auto i : extra) {
      listeners.Append(i);
    }
    listeners.Append(new ErrorHelper::VapidListener);
  }
  listeners.Append(new ErrorHelper::UncheckedListener);
  ::testing::AddGlobalTestEnvironment(new EnvironmentWithErrors);
}

bool ErrorHelper::VapidListener::HandleError(tls_error_source_t source,
                                             int reason) {
// kErrorStrings is a simple mapping of each tls_error_t value to its symbolic
// name.
#define STRINGIFY_ENUM_VALUE(reason) \
  { reason, #reason }
  static const std::map<int, std::string> kErrorStrings = {
      // VapidSSL errors.
      STRINGIFY_ENUM_VALUE(kTlsErrBadAlert),
      STRINGIFY_ENUM_VALUE(kTlsErrTooManyEmptyChunks),
      STRINGIFY_ENUM_VALUE(kTlsErrDisconnected),
      STRINGIFY_ENUM_VALUE(kTlsErrOutOfMemory),
      STRINGIFY_ENUM_VALUE(kTlsErrIntegerOverflow),
      STRINGIFY_ENUM_VALUE(kTlsErrOutOfBounds),
      STRINGIFY_ENUM_VALUE(kTlsErrInvalidArgument),
      STRINGIFY_ENUM_VALUE(kTlsErrInvalidState),
      STRINGIFY_ENUM_VALUE(kTlsErrUnsupportedAlgorithm),
      STRINGIFY_ENUM_VALUE(kTlsErrNoAvailableOptions),
      STRINGIFY_ENUM_VALUE(kTlsErrBufferChanged),
      STRINGIFY_ENUM_VALUE(kTlsErrNotImplemented),
  };
#undef STRINGIFY_ENUM_VALUE
  if (source != kTlsErrVapid) {
    return false;
  }
  std::cout << "  Source: VapidSSL library" << std::endl;
  const auto &i = kErrorStrings.find(reason);
  if (i != kErrorStrings.end()) {
    std::cout << "  Reason: " << i->second << std::endl;
  }
  return true;
}

void ErrorHelper::UncheckedListener::OnTestCaseEnd(
    const ::testing::TestCase &test_case) {
  // This event listener may be called when TLS_ERROR_init has not been called,
  // so we're forced to break the abstraction and check.
  if (!thread_get_local()) {
    return;
  }
  const char *file = NULL;
  EXPECT_TRUE(TLS_ERROR_get(NULL, NULL, &file, NULL));
  EXPECT_EQ(file, nullptr);
}

void ErrorHelper::EnvironmentWithErrors::SetUp() {
  size_t len = 0;
  if (!TLS_ERROR_size(&len)) {
    std::cerr << "Failed to initialize thread local storage!" << std::endl;
    abort();
  }
  err_.reset(new (std::nothrow) uint8_t[len]);
  assert(err_.get() != NULL);
  if (!TLS_ERROR_init(err_.get(), len)) {
    std::cerr << "Failed to initialize thread local storage!" << std::endl;
    abort();
  }
}

void ErrorHelper::EnvironmentWithErrors::TearDown() {
  TLS_ERROR_cleanup();
}

}  // namespace vapidssl
