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

#ifndef VAPIDSSL_COMMON_TEST_STREAM_HELPER_H
#define VAPIDSSL_COMMON_TEST_STREAM_HELPER_H

#include <stddef.h>

#include "base/test/scoped_buf.h"
#include "base/types.h"
#include "common/chunk.h"
#include "common/stream.h"
#include "common/stream_internal.h"
#include "crypto/test/hash_test.h"

namespace vapidssl {

class StreamHelper {
 public:
  // GetSize is a |text_size_f| that can be used with the two segment chunk
  // created by |StreamHelper::Reset| to read the size of text segment from the
  // length segment.
  static tls_result_t GetSize(CHUNK *chunk, size_t *out);

  // SetSize is a |chunk_f| that can be used as a |process_chunk| parameter in
  // |chunk_set_process| It can be used with the two segment sending chunk
  // created by |StreamHelper::Reset| to set the length segment with the size of
  // the text segment.
  static tls_result_t SetSize(CHUNK *chunk);

  StreamHelper();
  virtual ~StreamHelper() = default;
  StreamHelper &operator=(const StreamHelper &) = delete;
  StreamHelper(const StreamHelper &) = delete;

  // Get returns either |rx_| or |tx_|, depending on the requested |direction|.
  virtual STREAM *Get(direction_t direction);

  // Setters
  virtual void SetMaxNesting(size_t max_nesting);
  virtual void SetDataLen(size_t data_len);
  virtual void SetMtu(size_t mtu);
  virtual void SetMaxPending(size_t max_pending);

  // Reset obliterates the current state by resetting |region_| and |loopback_|.
  // It then rebuilds the |rx_| and |tx_| streams and configures their chunks to
  // have two segments: a length segment and and text segment.  It registers
  // |AlwaysContinue|, |GetSize|, and |SetSize| as appropriate.
  virtual void Reset(void);

  // Flush will call |stream_flush| on |tx_| repeatedly until it returns
  // successfully or an error occurs that precludes retrying the I/O.
  virtual void Flush(void);

 private:
  size_t mtu_;
  size_t max_nesting_;
  size_t max_pending_;
  size_t data_len_;
  ScopedBuf region_;
  ScopedBuf loopback_;
  STREAM rx_;
  STREAM tx_;
  LIST hashes_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_COMMON_TEST_STREAM_HELPER_H
