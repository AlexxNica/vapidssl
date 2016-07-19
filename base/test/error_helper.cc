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

std::vector<ErrorListener *> &ErrorHelper::GetListeners() {
  static std::vector<ErrorListener *> *listeners_ =
      new std::vector<ErrorListener *>();
  return *listeners_;
}

ErrorListener *ErrorHelper::AddListener(ErrorListener *listener) {
  GetListeners().push_back(listener);
  return listener;
}

void ErrorHelper::Init(bool verbose) {
  auto &listeners = ::testing::UnitTest::GetInstance()->listeners();
  if (verbose) {
    AddListener(new ErrorHelper::VapidListener);
    auto &extra = GetListeners();
    for (auto i : extra) {
      listeners.Append(i);
    }
  }
  listeners.Append(new ErrorHelper::UncheckedListener);
  ::testing::AddGlobalTestEnvironment(new EnvironmentWithErrors);
}

const std::string &ErrorHelper::GetSourceAsString(tls_error_source_t source) {
  for (auto i : GetListeners()) {
    if (source == i->GetSource()) {
      return i->GetSourceAsString();
    }
  }
  static const std::string kUnknownSource = "Unknown source";
  return kUnknownSource;
}

const std::string &ErrorHelper::GetReasonAsString(tls_error_source_t source,
                                                  int reason) {
  for (auto i : GetListeners()) {
    if (source == i->GetSource()) {
      return i->GetReasonAsString(reason);
    }
  }
  static const std::string kUnknownReason = "Unknown reason";
  return kUnknownReason;
}

// VapidListener methods

ErrorHelper::VapidListener::VapidListener()
    : ErrorListener(kTlsErrVapid, "VapidSSL library") {
#define ADD_ERROR_REASON(reason) AddReason(reason, #reason);
  ADD_ERROR_REASON(kTlsErrBadAlert);
  ADD_ERROR_REASON(kTlsErrTooManyEmptyChunks);
  ADD_ERROR_REASON(kTlsErrTooManyWarnings);
  ADD_ERROR_REASON(kTlsErrLengthMismatch);
  ADD_ERROR_REASON(kTlsErrDisconnected);
  ADD_ERROR_REASON(kTlsErrOutOfMemory);
  ADD_ERROR_REASON(kTlsErrIntegerOverflow);
  ADD_ERROR_REASON(kTlsErrOutOfBounds);
  ADD_ERROR_REASON(kTlsErrInvalidArgument);
  ADD_ERROR_REASON(kTlsErrInvalidState);
  ADD_ERROR_REASON(kTlsErrUnsupportedAlgorithm);
  ADD_ERROR_REASON(kTlsErrNoAvailableOptions);
  ADD_ERROR_REASON(kTlsErrBufferChanged);
  ADD_ERROR_REASON(kTlsErrNotImplemented);

  ADD_ERROR_REASON(kTlsErrCloseNotify);
  ADD_ERROR_REASON(kTlsErrUnexpectedMessage);
  ADD_ERROR_REASON(kTlsErrBadRecordMac);
  ADD_ERROR_REASON(kTlsErrRecordOverflow);
  ADD_ERROR_REASON(kTlsErrHandshakeFailure);
  ADD_ERROR_REASON(kTlsErrBadCertificate);
  ADD_ERROR_REASON(kTlsErrUnsupportedCertificate);
  ADD_ERROR_REASON(kTlsErrRevokedCertificate);
  ADD_ERROR_REASON(kTlsErrExpiredCertificate);
  ADD_ERROR_REASON(kTlsErrCertificateUnknown);
  ADD_ERROR_REASON(kTlsErrIllegalParameter);
  ADD_ERROR_REASON(kTlsErrUnknownCA);
  ADD_ERROR_REASON(kTlsErrDecodeError);
  ADD_ERROR_REASON(kTlsErrDecryptError);
  ADD_ERROR_REASON(kTlsErrProtocolVersion);
  ADD_ERROR_REASON(kTlsErrInsufficientSecurity);
  ADD_ERROR_REASON(kTlsErrInternalError);
  ADD_ERROR_REASON(kTlsErrNoRenegotiation);
  ADD_ERROR_REASON(kTlsErrUnsupportedExtension);
#undef ADD_ERROR_REASON
}

// UncheckedListener methods

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

// EnvironmentWithErrors methods

void ErrorHelper::EnvironmentWithErrors::SetUp() {
  size_t len = TLS_ERROR_size();
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
