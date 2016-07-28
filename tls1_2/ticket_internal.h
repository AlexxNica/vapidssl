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

#ifndef VAPIDSSL_TLS1_2_TICKET_INTERNAL_H
#define VAPIDSSL_TLS1_2_TICKET_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

#include "base/buf.h"

// ticket_st represents the ticket issued by the server and used for stateless
// session resumption as in https://tools.ietf.org/html/rfc5077.
struct ticket_st {
  // expiry is the time (in seconds) at which this ticket is no longer valid.  A
  // value of 0 indicates the ticket does not expire.
  int64_t expiry;
  // data holds the actual session state from the server.  A client should not
  // attempt to interpret this information.
  BUF data;
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_TICKET_INTERNAL_H
