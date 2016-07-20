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

#ifndef VAPIDSSL_BASE_PLATFORM_IO_H
#define VAPIDSSL_BASE_PLATFORM_IO_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/types.h"
#include "public/error.h"
#include "public/tls.h"

// This is the platform and/or OS specific interface for I/O.  VapidSSL only
// presumes that the platform has a way to map a |tls_connection_id_t| to a
// specific bi-directional I/O stream.

// io_data either produces data to or consumes data from |buf| depending on
// |direction|. It receives or sends data using the platform-specific connection
// identified by |cid|.  This is analogous to the 'read' and 'write' POSIX
// system calls, respectively, except that the I/O is repeated until either it
// is complete, in which case |kTlsSuccess| is returned, or the platform call
// returns an error, in which case an corresponding error is generated with a
// source of |kTlsErrPlatform| and |kTlsErrFailure| is returned.
tls_result_t io_data(tls_connection_id_t cid, direction_t direction, BUF *buf);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_PLATFORM_IO_H
