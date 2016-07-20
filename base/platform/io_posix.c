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

#include "base/platform/io.h"

#include <assert.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

//#include <linux/if.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/types.h"

// Library routines.

// TODO(aarongreen): This results in a lot of small writes.  We need
// scatter-gather.
tls_result_t io_data(tls_connection_id_t cid, direction_t direction, BUF *buf) {
  assert(buf);
  size_t max = (direction == kRecv ? buf_available(buf) : buf_ready(buf));
  // Exit early if no work to do.
  if (max == 0) {
    return kTlsSuccess;
  }
  int fd = (int)cid;
  uint8_t *raw = NULL;
  if (direction == kRecv) {
    buf_may_produce(buf, max, &raw);
  } else {
    buf_may_consume(buf, max, &raw);
  }
  size_t count = max;
  ssize_t n = 0;
  while (count != 0) {
    if (direction == kRecv) {
      n = read(fd, raw, count);
      if (n == 0) {
        ERROR_SET(kTlsErrVapid, kTlsErrDisconnected);
        break;
      }
    } else {
      n = write(fd, raw, count);
    }
    if (n < 0) {
      ERROR_SET(kTlsErrPlatform, errno);
      break;
    }
    raw += n;
    count -= n;
  }
  if (direction == kRecv) {
    buf_did_produce(buf, max - count);
  } else {
    buf_did_consume(buf, max - count);
  }
  // Did we exit because of an error?
  return count == 0;
}
