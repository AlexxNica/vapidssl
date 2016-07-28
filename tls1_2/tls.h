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

#ifndef VAPIDSSL_TLS1_2_TLS_H
#define VAPIDSSL_TLS1_2_TLS_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "base/buf.h"
#include "common/stream.h"
#include "public/tls.h"
#include "tls1_2/message.h"
#include "tls1_2/ticket.h"

// tls_get_region returns a pointer to the memory region that was given to |tls|
// when |TLS_init| was called.
BUF *tls_get_region(TLS *tls);

// tls_get_config returns a pointer to the configuration that was specified for
// |tls| when |TLS_init| was called.
const TLS_CONFIG *tls_get_config(TLS *tls);

// tls_get_sni returns a pointer to the server name that was specified for |tls|
// when |TLS_init| was called.
BUF *tls_get_sni(TLS *tls);

// tls_get_master_secret returns a pointer to the most recently generated master
// secret for a given |tls| connection.  The buffer may be empty if no master
// secret has been established.
BUF *tls_get_master_secret(TLS *tls);

// tls_get_ticket returns a pointer to the server-issued stateless session
// resumption ticket for the |tls| connection, or NULL if no such ticket exists.
TICKET *tls_get_ticket(TLS *tls);

// tls_get_message returns a pointer |tls|'s MESSAGE object for the given
// |direction|.
MESSAGE *tls_get_message(TLS *tls, direction_t direction);

// tls_get_stream returns a pointer to the underlying STREAM for a |tls|
// connection in particular |direction|.
STREAM *tls_get_stream(TLS *tls, direction_t direction);

// tls_get_ciphersuite gets the cipher suite saved for the given |tls|
// connection.
tls_ciphersuite_t tls_get_ciphersuite(TLS *tls);

// tls_set_ciphersuite saves a |ciphersuite| to be enabled later on the |tls|
// connection's message object when they process a ChangeCipherSpec.
void tls_set_ciphersuite(TLS *tls, tls_ciphersuite_t ciphersuite);

// tls_get_aead_states returns a pointer to buffer holding the memory used to
// perform the bulk AEAD cipher on the |tls| connection.
BUF *tls_get_aead_states(TLS *tls);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_TLS_H
