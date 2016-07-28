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

#ifndef VAPIDSSL_TLS1_2_EXTENSION_H
#define VAPIDSSL_TLS1_2_EXTENSION_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "tls1_2/extension_internal.h"

#include "public/error.h"

// This file includes routines to both encode and decode TLS 1.2 extensions as
// part of the ClientHello/ServerHello exchange.

// Opaque TLS extension encoder/decoder, defined in extension_internal.h.
typedef struct extension_st EXTENSION;

// extension_t lists the supported TLS 1.2 extensions.
// TODO(aarongreen): Add |kExtExtendedMasterSecret|.
typedef enum extension_t {
  kExtServerNameIndication = 0,
  kExtMaxFragmentLength = 1,
  kExtSupportedEllipticCurve = 10,
  kExtSignatureAndHash = 13,
  kExtStatelessSessionTicket = 35,
} extension_t;

// extension_size returns the number of bytes needed for a call to
// |extension_init| to be successful for a given |config|.
size_t extension_size(const TLS_CONFIG *config);

// extension_init prepares |out| for use in encoding and decoding extensions for
// |tls| using memory from |region|.
void extension_init(BUF *region, TLS *tls, EXTENSION *out);

// extension_length returns the total length of |extension| when encoded.
uint16_t extension_length(EXTENSION *extension);

// extension_send encodes the |extension| and sends it to the server using the
// |tls| connection specified in |extension_init|.
tls_result_t extension_send(EXTENSION *extension);

// extension_recv receives an encoded extension list using the |tls| connection
// specified in |extension_init| and decodes it into |extension|.
tls_result_t extension_recv(EXTENSION *extension);

// extension_echoed returns |kTrue| if |extension| indicates the server
// responded to an extension of a given |type| that was sent in
// |extension_send|, and |kFalse| otherwise.
bool_t extension_echoed(EXTENSION *extension, extension_t type);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_EXTENSION_H
