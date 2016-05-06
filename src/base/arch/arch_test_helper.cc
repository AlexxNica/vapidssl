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

#include "base/arch/arch_test_helper.h"

#include <stdint.h>
#include <iostream>
#include <string>
#include <vector>

#include "base/buf.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

static const ::testing::TestEventListener *kErrorListener =
    ArchTestHelper::RegisterListener();

::testing::TestEventListener *ArchTestHelper::RegisterListener() {
  return ErrorTestHelper::AddListener(new ArchTestHelper::ErrorListener());
}

ArchTestHelper::ArchTestHelper() : attributes_(), path_("") {}

ArchTestHelper::~ArchTestHelper() {}

bool ArchTestHelper::AddAttribute(const std::string &tag, ScopedBuf &buf) {
  if (attributes_[tag]) {
    return false;
  }
  attributes_[tag] = &buf;
  return true;
}

bool ArchTestHelper::ReadNext() {
  return false;
}

} /* namespace vapidssl */
