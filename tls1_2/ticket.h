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

#ifndef VAPIDSSL_TLS1_2_TICKET_H
#define VAPIDSSL_TLS1_2_TICKET_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "tls1_2/ticket_internal.h"

#include <stdint.h>

#include "base/buf.h"
#include "public/config.h"
#include "public/error.h"

// The TICKET structure is used to resume TLS sessions.  Server with support for
// RFC 5077 can issue tickets which encapsulate the session state, sans the
// master secret.  Client which store the ticket and master secret can then
// perform an abbreviated handshake to pick up where a previous session left
// off.

// TICKET is the opaque ticket structure, as defined in ticket_internal.h.
typedef struct ticket_st TICKET;

// ticket_erase invalidates |ticket| so that it cannot be used to resume future
// sessions.
void ticket_erase(TICKET *ticket);

// ticket_renew delays the expiration of a |ticket| until |duration| seconds
// from now.
void ticket_renew(TICKET *ticket, uint32_t duration);

// ticket_data returns the buffer holding a |ticket|'s data.
BUF *ticket_data(TICKET *ticket);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_TICKET_H
