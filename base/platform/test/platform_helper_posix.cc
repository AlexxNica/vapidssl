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

#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <string>

#include "public/error.h"

namespace vapidssl {

static const char *kCheckFile = "LICENSE";

std::string PlatformHelper::base_dir_("");

bool PlatformHelper::SetBaseDir(const std::string &base_dir) {
  if (!PlatformHelper::base_dir_.empty()) {
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

bool PlatformHelper::SetDataFile(const std::string &path) {
  std::string new_path = base_dir_ + path;
  struct stat buf;
  if (stat(new_path.c_str(), &buf) != 0) {
    ADD_FAILURE() << "Test data file '" << path << "' was not found.";
    return false;
  }
  path_ = new_path;
  return true;
}

// PlatformListener methods

PlatformHelper::PlatformListener::PlatformListener()
    : ErrorListener(kTlsErrPlatform, OsName) {}

const std::string &PlatformHelper::PlatformListener::GetReasonAsString(
    int reason) {
  if (!HasReason(reason)) {
    AddReason(reason, strerror(reason));
  }
  return ErrorListener::GetReasonAsString(reason);
}

}  // namespace vapidssl
