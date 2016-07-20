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

#ifndef VAPIDSSL_PLATFORM_IO_MOCK_H
#define VAPIDSSL_PLATFORM_IO_MOCK_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>

#include "base/buf.h"

// This is a mock of a platform specific I/O implementation of io.h.  It adds a
// single function which can be used to configure whether the input and output
// data and read from and written to.

enum io_mock_t {
  kIoLoopback = 0,
  kIoClient = 1,
  kIoServer = 2,
};

// io_mock_init sets up how io_mock will produce and consume I/O for testing.
// Data will be received from |recv| and sent to |send| in chunks of at most
// |mtu| bytes at a time.  |recv| and |send| can be the same BUF structure; this
// causes the data to be looped back.  If |send| is NULL, sent data will be
// discarded.  If |recv| is NULL, attempts to read will cause errors. If |mtu|
// is 0, all ready data is received or available space is sent to.
void io_mock_init(size_t mtu, BUF *recv, BUF *send);

// io_mock_retry returns the error code for incomplete I/O, e.g.
// EAGAIN on Linux.
int io_mock_retry(void);

// io_mock_set_verbose enables printing of all data being sent and received for
// debugging purposes.  This should need to be enabled during unit testing; it
// is included for the developer's convenience.
void io_mock_set_verbose(bool_t enabled);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_PLATFORM_IO_MOCK_H
