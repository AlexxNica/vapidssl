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

#include "base/arch/test/arch_test_helper.h"
#include "base/test/error_test_helper.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace {

static const char *kVerboseOpt = "-v";
static const char *kBaseDirArg = "--base_dir=";
/* This is base_dir_ if building according to BUILDING.md. */
static const char *kDefaultBaseDir = "..";

/* print_usage displays the correct way to invoke the unit tests and exits.*/
void print_usage(std::string exec_name) {
  std::cerr << "usage: " << exec_name;
  std::cerr << " [" << kVerboseOpt << "]";
  std::cerr << " [<gtest-options>] ";
  std::cerr << "" << kBaseDirArg << "<project-root>";
  std::cerr << std::endl;
  exit(1);
}

} /* namespace */

/* main is the entry point for unit testing.  It initializes the Google Test
 * library, parses VapidSSL-specific arguments, initializes the VapidSSL
 * library, and runs the unit tests. As we only have a couple of arguments
 * to parse, this doesn't require sophisticated argument parsing (yet). */
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  bool verbose = false;
  bool has_dir = false;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    size_t base_dir_len = strlen(kBaseDirArg);
    if (arg.compare(kVerboseOpt) == 0) {
      verbose = true;
    } else if (arg.compare(0, base_dir_len, kBaseDirArg) == 0) {
      std::string base_dir = arg.substr(base_dir_len);
      has_dir = ::vapidssl::ArchTestHelper::SetBaseDir(base_dir);
    } else {
      std::cerr << "error: Unknown argument: '" << arg << "'." << std::endl;
      print_usage(argv[0]);
    }
  }
  if (!has_dir && !::vapidssl::ArchTestHelper::SetBaseDir(kDefaultBaseDir)) {
    std::cerr << "error: Missing or invalid project root." << std::endl;
    print_usage(argv[0]);
  }
  ::vapidssl::ErrorTestHelper::Init(verbose);
  return RUN_ALL_TESTS();
}
