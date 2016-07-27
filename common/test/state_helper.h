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

#ifndef VAPIDSSL_COMMON_TEST_STATE_HELPER_H
#define VAPIDSSL_COMMON_TEST_STATE_HELPER_H

#include <stddef.h>
#include <map>
#include <string>

#include "base/test/scoped_buf.h"

namespace vapidssl {

// StateHelper allows extremely simple snapshotting during unit tests.  It
// stores and can subsequently a region of memory.
class StateHelper {
 public:
  StateHelper() = default;
  virtual ~StateHelper() = default;
  StateHelper &operator=(const StateHelper &) = delete;
  StateHelper(const StateHelper &) = delete;

  // Snapshot saves |state_len| bytes starting at |state| into |snapshot_|.
  // Calling |Snapshot| multiple times will overwrite existing snapshots with
  // whatever is most recent.
  virtual void Snapshot(void *state, size_t state_len);

  // Revert copies the contents of |snapshot_| to |state|.  It is a fatal error
  // if |snapshot_| does not contain |state_len| bytes.
  virtual void Revert(void *state, size_t state_len);

 private:
  // snapshot_ is the buffer holding the saved state.
  ScopedBuf snapshot_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_COMMON_TEST_STATE_HELPER_H
