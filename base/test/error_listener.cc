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

#include "base/test/error_listener.h"

#include <iostream>

#include "base/arch/thread.h"
#include "base/error.h"
#include "public/error.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

void ErrorListener::OnTestPartResult(const ::testing::TestPartResult &result) {
  if (!result.failed()) {
    return;
  }
  /* This event listener may be called when TLS_ERROR_init has not been called,
   * so we're forced to break the abstraction and check. */
  if (!thread_get_local()) {
    return;
  }
  /* Get the error. */
  tls_error_source_t source;
  int reason = -1;
  const char *file = nullptr;
  int line = -1;
  if (!TLS_ERROR_get(&source, &reason, &file, &line) || !file) {
    return;
  }
  /* Handle it if it's an error we know about. */
  if (HandleError(source, reason)) {
    std::cout << "  Origin: " << file << ":" << line << std::endl;
    error_clear();
  }
}

} /* namespace vapidssl */
