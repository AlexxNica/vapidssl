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

#ifndef VAPIDSSL_BASE_PLATFORM_TEST_PLATFORM_HELPER_H
#define VAPIDSSL_BASE_PLATFORM_TEST_PLATFORM_HELPER_H

#include <stdint.h>
#include <map>
#include <memory>
#include <string>

#include "base/buf.h"
#include "base/test/error_helper.h"
#include "base/test/error_listener.h"
#include "base/test/scoped_buf.h"
#include "public/error.h"
#include "third_party/boringssl/crypto/test/file_test.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

// PlatformHelper provides a platform-specific way to get test data from test
// data files.  Once |main| has set the project root using |SetBaseDir|,
// individual unit tests can specify test data files using |SetDataFile| and
// register named buffers as "attributes" using |AddHexAttribute|.  Each
// subsequent
// call to |ReadNext| will then populate the buffer with a corresponding value
// from the file.
class PlatformHelper {
 public:
  // AssertionRegex is a regular expression that matches the output for a failed
  // assertion on this platform.
  static const char *AssertionRegex;

  // OsName is the short name of the operating system, e.g. "Linux", "Windows",
  // or "Mac OSX".
  static const char *OsName;

  // RegisterListener adds a test event listener to |ErrorHelper|'s list and
  // returns for assignment in a static initailizer.
  static ::testing::TestEventListener *RegisterListener();

  // SetBaseDir sets the project root for the unit tests.  If |base_dir_| is
  // already set or |base_dir| is not a valid directory, it returns false
  // without modification; otherwise, it returns true.
  static bool SetBaseDir(const std::string &base_dir);

  PlatformHelper();
  virtual ~PlatformHelper();
  PlatformHelper &operator=(const PlatformHelper &) = delete;
  PlatformHelper(const PlatformHelper &) = delete;

  // SetDataFile takes a path, |path|, that gives the location of this test's
  // test data file relative to the project root. If |path_| is already set or
  // |path| does not reference a valid file, it returns false without
  // modification; otherwise it returns true.
  virtual bool SetDataFile(const std::string &path);

  // HasAttribute returns whether an optional attribute named by |tag| was
  // provided in the last set of attributes read by |ReadNext|.
  virtual bool HasAttribute(const std::string &tag) = 0;

  // AddHexAttribute registers a |tag| to scan for in the test data file and an
  // unwrapped |buf| to use to wrap the data associated with that tag. It is an
  // error to call |AddHexAttribute| with a |buf| that already wraps memory, or
  // to call |AddHexAttribute| or |AddStringAttribute| twice with the same
  // |tag|.
  virtual void AddHexAttribute(const std::string &tag, ScopedBuf &buf,
                               bool optional = false);

  // AddStringAttribute registers a |tag| to scan for in the test data file and
  // an unwrapped |buf| to use to wrap the string associated with that tag. It
  // is an error to call |AddHexAttribute| with a |buf| that already wraps
  // memory, or to call |AddHexAttribute| or |AddStringAttribute| twice with the
  // same |tag|.
  virtual void AddStringAttribute(const std::string &tag, std::string &str,
                                  bool optional = false);

  // ReadNext updates |attributes_| with values of the next |iteration_|'s data
  // in the test's associated test data file described by |path_|. If |path_| is
  // unset or an error occurs during reading, it returns false; otherwise it
  // returns true.
  virtual bool ReadNext();

 protected:
  // optional_hex_ and required_hex_ are the optional and required sets,
  // respectively, of named test data attributes represented by hex strings.
  // The attributes should be "registered" by adding a BUF struct for each name
  // in the derived class's |SetUp| method.
  std::map<std::string, ScopedBuf *> optional_hex_;
  std::map<std::string, ScopedBuf *> required_hex_;
  // optional_str_ and required_str_ are the optional and required sets,
  // respectively, of named test data attributes represented by strings. The
  // attributes should be "registered" by adding a BUF struct for each name
  // in the derived class's |SetUp| method.
  std::map<std::string, std::string *> optional_str_;
  std::map<std::string, std::string *> required_str_;
  // path_ is the absolute path to the test's gold file.
  std::string path_;

 private:
  // CheckDuplicateTag aborts if a |tag| is added twice.
  void CheckDuplicateTag(const std::string &tag);

  // base_dir_ is the project root directory.
  static std::string base_dir_;

  class PlatformListener : public ErrorListener {
   public:
    PlatformListener();

   protected:
    // GetReasonAsString returns a human readable error message corresponding to
    // |reason| for platform-specific errors.
    const std::string &GetReasonAsString(int reason) override;
  };
};

}  // namespace vapidssl

#endif  // VAPIDSSL_BASE_PLATFORM_TEST_PLATFORM_HELPER_H
