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

#include <string>

namespace vapidssl {

static const std::string kCheckFile = "LICENSE";

std::string ArchHelper::base_dir_("");

bool ArchHelper::SetBaseDir(const std::string &base_dir) {
  if (!ArchHelper::base_dir_.empty()) {
    return false;
  }
  std::string new_base(base_dir);
  if (new_base.back() != '/') {
    new_base.push_back('/');
  }
  struct stat buf;
  std::string license = new_base + kCheckFile;
  if (stat(license.c_str(), &buf) != 0) {
    return false;
  }
  base_dir_ = new_base;
  return true;
}

bool ArchHelper::SetDataFile(const std::string &path) {
  std::string new_path = base_dir_ + path;
  struct stat buf;
  if (stat(new_path.c_str(), &buf) != 0) {
    ADD_FAILURE() << "Test data file '" << path << "' was not found.";
    return false;
  }
  path_ = new_path;
  return true;
}

bool ArchHelper::ArchListener::HandleError(tls_error_source_t source,
                                           int reason) {
  if (source != kTlsErrArch || reason == 0) {
    return false;
  }
  std::cout << "  Source: Linux OS" << std::endl;
  std::cout << "  Reason: " << strerror(reason) << " (" << reason << ")";
  std::cout << std::endl;
  return true;
}

}  // namespace vapidssl
