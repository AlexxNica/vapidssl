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

#include "base/arch/test/arch_helper.h"

#include <stdint.h>
#include <iostream>
#include <string>
#include <vector>

#include "base/buf.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

static const ::testing::TestEventListener *kErrorListener =
    ArchHelper::RegisterListener();

::testing::TestEventListener *ArchHelper::RegisterListener() {
  return ErrorHelper::AddListener(new ArchHelper::ArchListener());
}

ArchHelper::ArchHelper() : attributes_(), path_("") {}

ArchHelper::~ArchHelper() {}

void ArchHelper::AddAttribute(const std::string &tag, ScopedBuf &buf) {
  if (attributes_[tag]) {
    std::cerr << "Duplicate attribute added!" << std::endl;
    abort();
  }
  attributes_[tag] = &buf;
}

bool ArchHelper::ReadNext() {
  return false;
}

}  // namespace vapidssl
