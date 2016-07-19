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

#include "base/platform/test/platform_helper.h"

#include <iostream>
#include <map>
#include <string>

#include "base/buf.h"
#include "base/test/scoped_buf.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// Static initializer to add listener before running |main|.
static const ::testing::TestEventListener *kErrorListener =
    PlatformHelper::RegisterListener();

::testing::TestEventListener *PlatformHelper::RegisterListener() {
  return ErrorHelper::AddListener(new PlatformHelper::PlatformListener());
}

PlatformHelper::PlatformHelper()
    : optional_hex_(),
      required_hex_(),
      optional_str_(),
      required_str_(),
      path_("") {}

PlatformHelper::~PlatformHelper() {}

void PlatformHelper::AddHexAttribute(const std::string &tag, ScopedBuf &buf,
                                     bool optional) {
  CheckDuplicateTag(tag);
  if (optional) {
    optional_hex_[tag] = &buf;
  } else {
    required_hex_[tag] = &buf;
  }
}

void PlatformHelper::AddStringAttribute(const std::string &tag,
                                        std::string &str, bool optional) {
  CheckDuplicateTag(tag);
  if (optional) {
    optional_str_[tag] = &str;
  } else {
    required_str_[tag] = &str;
  }
}

void PlatformHelper::CheckDuplicateTag(const std::string &tag) {
  if (optional_hex_.find(tag) != optional_hex_.end() ||
      required_hex_.find(tag) != required_hex_.end() ||
      optional_str_.find(tag) != optional_str_.end() ||
      required_str_.find(tag) != required_str_.end()) {
    std::cerr << "Duplicate attribute added!" << std::endl;
    abort();
  }
}

bool PlatformHelper::ReadNext() {
  // Clear old attributes.
  for (auto &i : optional_hex_) {
    i.second->Reset(0);
  }
  for (auto &i : required_hex_) {
    i.second->Reset(0);
  }
  for (auto &i : optional_str_) {
    i.second->clear();
  }
  for (auto &i : required_str_) {
    i.second->clear();
  }
  return false;
}

}  // namespace vapidssl
