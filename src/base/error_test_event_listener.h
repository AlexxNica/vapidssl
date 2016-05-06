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

#ifndef VAPIDSSL_BASE_ERROR_TEST_EVENT_LISTENER_H
#define VAPIDSSL_BASE_ERROR_TEST_EVENT_LISTENER_H

#include "third_party/gtest/googletest/include/gtest/gtest.h"
#include "vapidssl/error.h"

namespace vapidssl {

/* ErrorTestEventListener is a TestEventListener that responds to test results.
 * See AdvancedGuide.md#extending-google-test-by-handling-test-events in
 * third_party/gtest/googletest/docs/ for more detail. */
class ErrorTestEventListener : public ::testing::EmptyTestEventListener {
 protected:
  /* OnTestPartResult is called after each test result and on failure prints
   * the details of an error, if present.  It clears the error. */
  void OnTestPartResult(const ::testing::TestPartResult &result) override;

  /* HandleError prints error details for errors that this listener recognizes
   * based on |source|.  It returns true if it can handle the error and false
   * otherwise. */
  virtual bool HandleError(tls_error_source_t source, int reason) = 0;
};

} /* namespace vapidssl */

#endif /* VAPIDSSL_BASE_ERROR_TEST_EVENT_LISTENER_H */
