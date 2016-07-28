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

#include "tls1_2/ticket.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "base/buf.h"
#include "base/platform/time.h"
#include "tls1_2/config.h"

void ticket_erase(TICKET *ticket) {
  assert(ticket);
  ticket->expiry = 0;
  if (buf_size(&ticket->data) != 0) {
    buf_free(&ticket->data);
  }
}

void ticket_renew(TICKET *ticket, uint32_t duration) {
  assert(ticket);
  int64_t now = time_now();
  if (duration != 0) {
    assert(now < INT64_MAX - UINT32_MAX);
    ticket->expiry = now + duration;
  } else {
    ticket->expiry = 0;
  }
}

BUF *ticket_data(TICKET *ticket) {
  assert(ticket);
  if (ticket->expiry != 0 && ticket->expiry < time_now()) {
    ticket_erase(ticket);
  }
  return &ticket->data;
}
