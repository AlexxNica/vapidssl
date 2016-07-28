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

#include <stdlib.h>
#include <iostream>
#include <string>

#include "base/platform/test/io_mock.h"
#include "base/platform/test/platform_helper.h"
#include "base/test/error_helper.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace {

static const char *kVerboseOpt = "-v";
static const char *kIoDebugOpt = "-d";
static const char *kBaseDirArg = "--base_dir=";
// This is base_dir_ if building according to BUILDING.md.
static const char *kDefaultBaseDir = "..";

// print_usage displays the correct way to invoke the unit tests and exits.
void print_usage(std::string exec_name) {
  std::cerr << "usage: " << exec_name;
  std::cerr << " [" << kVerboseOpt << "]";
  std::cerr << " [<gtest-options>] ";
  std::cerr << "" << kBaseDirArg << "<project-root>";
  std::cerr << std::endl;
  exit(1);
}

}  // namespace

// main is the entry point for unit testing.  It initializes the Google Test
// library, parses VapidSSL-specific arguments, initializes the VapidSSL
// library, and runs the unit tests. As we only have a couple of arguments to
// parse, this doesn't require sophisticated argument parsing (yet).
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  bool verbose = false;
  bool has_dir = false;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    size_t base_dir_len = strlen(kBaseDirArg);
    if (arg.compare(kVerboseOpt) == 0) {
      verbose = true;
    } else if (arg.compare(kIoDebugOpt) == 0) {
      io_mock_set_verbose(kTrue);
    } else if (arg.compare(0, base_dir_len, kBaseDirArg) == 0) {
      std::string base_dir = arg.substr(base_dir_len);
      has_dir = ::vapidssl::PlatformHelper::SetBaseDir(base_dir);
    } else {
      std::cerr << "error: Unknown argument: '" << arg << "'." << std::endl;
      print_usage(argv[0]);
    }
  }
  if (!has_dir && !::vapidssl::PlatformHelper::SetBaseDir(kDefaultBaseDir)) {
    std::cerr << "error: Missing or invalid project root." << std::endl;
    print_usage(argv[0]);
  }
  ::vapidssl::ErrorHelper::Init(verbose);
  return RUN_ALL_TESTS();
}
