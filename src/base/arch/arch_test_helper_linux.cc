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

#include <string>

namespace vapidssl {

static const std::string kCheckFile = "LICENSE";

std::string ArchTestHelper::base_dir_("");

bool ArchTestHelper::SetBaseDir(const std::string &base_dir) {
  if (!ArchTestHelper::base_dir_.empty()) {
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

bool ArchTestHelper::SetDataFile(const std::string &path) {
  std::string new_path = base_dir_ + path;
  struct stat buf;
  if (stat(new_path.c_str(), &buf) != 0) {
    return false;
  }
  path_ = new_path;
  return true;
}

bool ArchTestHelper::ErrorListener::HandleError(tls_error_source_t source,
                                                int reason) {
  if (source != kTlsErrArch) {
    return false;
  }
  std::cout << "  Source: Linux OS" << std::endl;
  char error_string[1024];
  if (strerror_r(reason, error_string, sizeof(error_string)) == 0) {
    std::cout << "  Reason: " << error_string << std::endl;
  }
  return true;
}

} /* namespace vapidssl */
