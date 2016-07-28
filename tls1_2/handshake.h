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

#ifndef VAPIDSSL_TLS1_2_HANDSHAKE_H
#define VAPIDSSL_TLS1_2_HANDSHAKE_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "tls1_2/handshake_internal.h"

#include "base/buf.h"
#include "public/config.h"
#include "public/error.h"
#include "public/tls.h"

// This file contains the routines to perform a TLS 1.2 handshake.

// Opaque handshake state structure, defined in tls1_2/handshake_internal.h.
typedef struct handshake_st HANDSHAKE;

// handshake_size returns the number of bytes needed for a call to
// |handshake_init| and a subsequent call to |handshake_connect| to be
// successful.
size_t handshake_size(const TLS_CONFIG *config);

// handshake_init prepares |out| to be used for a TLS 1.2 handshake using a
// given |region| of memory and a |tls| connection.
tls_result_t handshake_init(BUF *region, TLS *tls, HANDSHAKE *out);

// handshake_connect performs a TLS 1.2 |handshake|.  If it returns
// |kTlsSuccess|, then the |tls| connection passed in |handshake_init| is
// connected and ready for application data.
tls_result_t handshake_connect(HANDSHAKE *handshake);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_HANDSHAKE_H
