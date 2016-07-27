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

#ifndef VAPIDSSL_X509V3_TRUSTED_ISSUER_H
#define VAPIDSSL_X509V3_TRUSTED_ISSUER_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/list.h"
#include "base/types.h"
#include "crypto/sign.h"
#include "public/error.h"

// This file contains functions to manages a list of trusted DN/key pairs.  This
// list represents trusted certificate authorities (CAs) when attempting to
// establish a trusted certificate chain.

// truststore_size returns the number of bytes needed for |truststore_init| to
// be successful when creating a truststore for |num_trusted| DN/key pairs.
size_t truststore_size(size_t num_trusted);

// truststore_init allocates the list in |out| from |region| to hole
// |num_trusted| DN/key pairs.
tls_result_t truststore_init(BUF *region, size_t num_trusted, LIST *out);

// truststore_add adds a |dn|/|key| pair, of lengths |dn_len| and |key_len|
// respectively, to the |truststore|.
tls_result_t truststore_add(LIST *truststore, const uint8_t *dn, size_t dn_len,
                            const uint8_t *key, size_t key_len);

// truststore_check iterates over a |truststore|, looking for a DN/key pair that
// matches |dn|.  If it is found, and the key can be used to validate |sign| as
// matching |digest|, it returns |kTrue|.  Otherwise it returns |kFalse|.
bool_t truststore_check(const LIST *truststore, const SIGN *sign, BUF *dn,
                        BUF *digest, BUF *signature);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_X509V3_TRUSTED_ISSUER_H
