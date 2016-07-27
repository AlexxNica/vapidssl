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

#ifndef VAPIDSSL_X509V3_CERTIFICATE_H
#define VAPIDSSL_X509V3_CERTIFICATE_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "x509v3/certificate_internal.h"

#include <stddef.h>

#include "base/buf.h"
#include "public/tls.h"

// Opaque X.509v3 certificate structure, defined in x509v3/cert.h.
typedef struct certificate_st CERTIFICATE;
typedef struct trusted_issuer_st TRUSTED_ISSUER;

size_t certificate_size(size_t max_name_len, size_t max_key_len);
tls_result_t certificate_init(BUF *region, size_t max_name_len, BUF *leaf_,
                              CERTIFICATE *out);
void certificate_set_stream(STREAM *rx, CERTIFICATE *out);
void certificate_set_name(BUF *sni, CERTIFICATE *out);
void certificate_set_trust(const LIST *truststore, CERTIFICATE *out);
tls_result_t certificate_recv(CERTIFICATE *chain);
bool_t certificate_is_trusted(CERTIFICATE *chain);
void certificate_cleanup(CERTIFICATE *chain);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_X509V3_CERTIFICATE_H
