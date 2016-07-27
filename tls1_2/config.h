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

#ifndef VAPIDSSL_TLS1_2_CONFIG_H
#define VAPIDSSL_TLS1_2_CONFIG_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/list.h"
#include "base/types.h"
#include "public/config.h"
#include "public/error.h"

// config_fragment_size_t represents the allowable maximum fragment length
// values per https://tools.ietf.org/html/rfc6066#section-4.
typedef enum config_fragment_size_t {
  kFragment512B = 512,
  kFragment1KB = 1024,
  kFragment2KB = 2048,
  kFragment4KB = 4096,
  kFragmentDefault = 16384,
} config_fragment_size_t;

// config_get_fragment_length returns the maximum fragment length in |config|.
config_fragment_size_t config_get_fragment_length(const TLS_CONFIG *config);

// config_get_ticket_length returns the maximum ticket length in |config|.
size_t config_get_ticket_length(const TLS_CONFIG *config);

// config_has_ciphersuite returns whether |ciphersuite| is supported and enabled
// in |config| or not.
bool_t config_has_ciphersuite(const TLS_CONFIG *config,
                              tls_ciphersuite_t ciphersuite);

// config_get_ciphersuites allocates |out| from |region| and fills it with all
// the ciphersuites enabled in |config|, in preference order.  If |resumed| is
// not |kCryptoAny|, it is moved to the front of the list.
tls_result_t config_get_ciphersuites(const TLS_CONFIG *config, BUF *region,
                                     tls_ciphersuite_t resumed, BUF *out);

// config_has_eccurve returns whether |curve| is supported and enabled in
// |config| or not.
bool_t config_has_eccurve(const TLS_CONFIG *config, tls_eccurve_t curve);

// config_get_eccurves allocates |out| from |region| and fills it with all
// the enabled elliptic curves enabled in |config|, in preference order.
tls_result_t config_get_eccurves(const TLS_CONFIG *config, BUF *region,
                                 BUF *out);

// config_has_signature_alg returns whether |signature_alg| is supported and
// enabled in |config| or not.
bool_t config_has_signature_alg(const TLS_CONFIG *config,
                                uint16_t signature_alg);

// config_get_signature_algs allocates |out| from |region| and fills it with all
// the signature algorithms enabled in |config|, in preference order.
tls_result_t config_get_signature_algs(const TLS_CONFIG *config, BUF *region,
                                       BUF *out);

// config_get_max_aead_size returns the maximum value of |aead_get_state_size|
// for all AEADs associated with ciphersuites  enabled in |config|.
size_t config_get_max_aead_size(const TLS_CONFIG *config);

// config_get_max_nonce_len returns the maximum nonce length for all
// ciphersuites enabled in |config|.
size_t config_get_max_nonce_len(const TLS_CONFIG *config);

// config_get_max_hash_size returns the maximum value of |hash_get_state_size|
// for all hash algorithms associated with ciphersuites enabled in |config|.
size_t config_get_max_hash_size(const TLS_CONFIG *config);

// config_get_hashes_size returns the combined size of calling
// |hash_get_state_size| for each hash algorithms associated with ciphersuites
// enabled in |config|.
size_t config_get_hashes_size(const TLS_CONFIG *config);

// config_get_max_name_length returns the maximum length of distinguished names
// as set in |config|.
size_t config_get_max_name_length(const TLS_CONFIG *config);

// config_get_max_name_length returns the maximum length of public signing keys
// as set in |config|.
size_t config_get_max_key_length(const TLS_CONFIG *config);

// config_get_truststore returns the list of issuers that represents the
// truststore for |config|.
const LIST *config_get_truststore(const TLS_CONFIG *config);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_TLS1_2_CONFIG_H
