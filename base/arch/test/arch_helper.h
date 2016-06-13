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

#ifndef VAPIDSSL_BASE_ARCH_TEST_ARCH_HELPER_H
#define VAPIDSSL_BASE_ARCH_TEST_ARCH_HELPER_H

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

/* ArchHelper provides a platform-specific way to get test data from test
 * data files.  Once |main| has set the project root using |SetBaseDir|,
 * individual unit tests can specify test data files using |SetDataFile| and
 * register named buffers as "attributes" using |AddAttribute|.  Each subsequent
 * call to |ReadNext| will then populate the buffer with a corresponding value
 * from the file. */
class ArchHelper {
 public:
  /* RegisterListener adds a test event listener to |ErrorHelper|'s list and
   * returns for assignment in a static initailizer. */
  static ::testing::TestEventListener *RegisterListener();

  /* SetBaseDir sets the project root for the unit tests.  If |base_dir_| is
   * already set or |base_dir| is not a valid directory, it returns false
   * without modification; otherwise, it returns true. */
  static bool SetBaseDir(const std::string &base_dir);

  ArchHelper();
  virtual ~ArchHelper();
  ArchHelper &operator=(const ArchHelper &) = delete;
  ArchHelper(const ArchHelper &) = delete;

  /* SetDataFile takes a path, |path|, that gives the location of this test's
   * test data file relative to the project root. If |path_| is already set or
   * |path| does not reference a valid file, it returns false without
   * modification; otherwise it returns true.*/
  virtual bool SetDataFile(const std::string &path);

  /* AddAttribute registers a |tag| to scan for in the test data file and an
   * unwrapped |buf| to use to wrap the data associated with that tag. It is an
   * error to call |AddAttribute| with a |buf| that already wraps memory, or
   * twice with the same |tag|. */
  virtual void AddAttribute(const std::string &tag, ScopedBuf &buf);

  /* ReadNext updates |attributes_| with values of the next |iteration_|'s data
   * in the test's associated test data file described by |path_|. If |path_| is
   * unset or an error occurs during reading, it returns false; otherwise it
   * returns true.*/
  virtual bool ReadNext();

 protected:
  /* attributes_ is the set of named test data attributes.  The attributes
   * should be "registered" by adding a BUF struct for each name in the derived
   * class's |SetUp| method. */
  std::map<std::string, ScopedBuf *> attributes_;
  /* path_ is the absolute path to the test's gold file. */
  std::string path_;

 private:
  /* base_dir_ is the project root directory. */
  static std::string base_dir_;

  class ArchListener : public ErrorListener {
   protected:
    /* HandleError implements |ErrorListener::HandleError|, and handles
     * platform errors. */
    bool HandleError(tls_error_source_t source, int reason) override;
  };
};

} /* namespace vapidssl */

#endif /* VAPIDSSL_BASE_ARCH_TEST_ARCH_HELPER_H */
