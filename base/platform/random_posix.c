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

#include "base/platform/random.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <base/platform/macros_posix.h>

static const char *kDevURandom = "/dev/urandom";

void random_buf(BUF *out) {
  size_t len = buf_available(out);
  uint8_t *raw = NULL;
  buf_produce(out, len, &raw);
  // TODO(aarongreen): Should we fail more gracefully than this?
  int rand_fd = HANDLE_EINTR(open(kDevURandom, O_RDONLY));
  if (rand_fd == -1) {
    abort();
  }
  ssize_t num = 0;
  while (len > 0) {
    num = HANDLE_EINTR(read(rand_fd, raw, len));
    if (num < 0) {
      abort();
    }
    len -= num;
  }
  close(rand_fd);
}
