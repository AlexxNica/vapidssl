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

#include "base/test/error_test_helper.h"

#include <stddef.h>
#include <stdint.h>
#include <iostream>
#include <vector>

#include "base/arch/thread.h"
#include "base/error.h"
#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

std::vector<::testing::TestEventListener *> &ErrorTestHelper::GetListeners() {
  static std::vector<::testing::TestEventListener *> *listeners_ =
      new std::vector<::testing::TestEventListener *>();
  return *listeners_;
}

::testing::TestEventListener *ErrorTestHelper::AddListener(
    ::testing::TestEventListener *listener) {
  GetListeners().push_back(listener);
  return listener;
}

void ErrorTestHelper::Init(bool verbose) {
  auto &listeners = ::testing::UnitTest::GetInstance()->listeners();
  if (verbose) {
    auto &extra = GetListeners();
    for (auto i : extra) {
      listeners.Append(i);
    }
    listeners.Append(new ErrorTestHelper::VapidListener);
  }
  listeners.Append(new ErrorTestHelper::UncheckedListener);
  ::testing::AddGlobalTestEnvironment(new EnvironmentWithErrors);
}

bool ErrorTestHelper::VapidListener::HandleError(tls_error_source_t source,
                                                 int reason) {
/* kErrorStrings is a simple mapping of each tls_error_t value to its symbolic
 * name. */
#define STRINGIFY_ENUM_VALUE(reason) \
  { reason, #reason }
  static const std::map<int, std::string> kErrorStrings = {
      /* VapidSSL errors. */
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

void ErrorTestHelper::UncheckedListener::OnTestCaseEnd(
    const ::testing::TestCase &test_case) {
  /* This event listener may be called when TLS_ERROR_init has not been called,
   * so we're forced to break the abstraction and check. */
  if (!thread_get_local()) {
    return;
  }
  const char *file = NULL;
  EXPECT_TRUE(TLS_ERROR_get(NULL, NULL, &file, NULL));
  EXPECT_EQ(file, nullptr);
}

void ErrorTestHelper::EnvironmentWithErrors::SetUp() {
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

void ErrorTestHelper::EnvironmentWithErrors::TearDown() {
  TLS_ERROR_cleanup();
}

} /* namespace vapidssl */
