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

#ifndef VAPIDSSL_PUBLIC_CONFIG_H
#define VAPIDSSL_PUBLIC_CONFIG_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "public/error.h"

// This is the public TLS configuration API for VapidSSL.  It defines symbols
// for the various algorithms and exposes a TLS_CONFIG structure  which can be
// used to configure the client's TLS preferences.  VapidSSL promises not to
// dynamically allocate any memory, so the API has routines to get the size of
// opaque structures, and API calls that need memory take it as a parameter.

// TLS_CONFIG is a TLS configuration, defined in internal/config.h. This
// structure is analogous to BoringSSL's SSL_CTX, defined as |struct ssl_ctx_st|
// in openssl.ssl.h.
typedef struct tls_config_st TLS_CONFIG;

// Supported hash algorithms, numbered per RFC 5246, section 7.4.1.4.1
// (https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1). These should
// correspond to the ciphersuites enumerated by |ciphersuite_t|.
typedef enum tls_hash_t {
  kTlsHashSHA256 = 4,
  kTlsHashSHA384 = 5,
} tls_hash_t;

// Supported TLS cipher IDs, numbered per
// https://tools.ietf.org/html/rfc5246#appendix-A.5,
// https://tools.ietf.org/html/rfc5289#section-3, and
// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-6.
typedef enum tls_ciphersuite_t {
  kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
  kTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
  kTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
} tls_ciphersuite_t;

// Supported TLS named EC curves, per
// https://tools.ietf.org/html/draft-ietf-tls-curve25519-01.
typedef enum tls_eccurve_t {
  kTlsCurve25519 = 0x001D,
} tls_eccurve_t;

// tls_parameter_pref_t is used by the caller to order various security
// parameters to be negotiated with a server. Given a list of parameters,
// setting a parameter to |kTlsPrefer| will add or move it to the beginning of
// the list, setting it to |kTlsAccept| will add or move it to the end of the
// list, and setting it to |kTlsReject| will remove it from the list.
typedef enum tls_parameter_pref_t {
  kTlsPrefer,
  kTlsAccept,
  kTlsReject,
} tls_parameter_pref_t;

// TLS_CONFIG_size returns the amount of memory needed for a call to
// |TLS_CONFIG_init| to be successful, given |num_trusted_issuers| to be
// trusted.
size_t TLS_CONFIG_size(size_t num_trusted_issuers);

// TLS_CONFIG_init takes a region of memory of |len| bytes starting at |mem| and
// configures a TLS config that uses |thumbprint_hash| for trusted certificate
// digests.
tls_result_t TLS_CONFIG_init(void *mem, size_t len, size_t num_trusted_issuers,
                             TLS_CONFIG **out);

// TLS_CONFIG_dup takes a region of memory of |len| bytes starting at |mem| and
// configures a TLS config that is an unfrozen copy of |orig|.  This is useful
// when a config has been frozen but subsequently needs to change (e.g. a cipher
// suite needs to be disabled).  The workflow in this case is to:
// - Call |TLS_shutdown| and |TLS_cleanup| to destroy active connections.
// - Call|TLS_CONFIG_dup| and |TLS_CONFIG_cleanup| to copy and dispose of the
//   old config.
// - Call |TLS_CONFIG_set_*| and |TLS_CONFIG_freeze| to modify and freeze the
//   new config.
// - Call |TLS_init| and |TLS_connect| to reestablish the connections.
//
// This function is thread-safe when compiled with support for threads.
tls_result_t *TLS_CONFIG_dup(const TLS_CONFIG *orig, void *mem, size_t len,
                             TLS_CONFIG *out);

// TLS_CONFIG_trust_signer associates a |key| with a distinguished name |dn| and
// adds them to the |coinfig|'s truststore.  Certificate chains that include a
// certificate whose issuer DN matches |dn| and whose signature can be verified
// using |key| will be considered trusted.
tls_result_t TLS_CONFIG_trust_signer(TLS_CONFIG *config, const uint8_t *dn,
                                     size_t dn_len, const uint8_t *key,
                                     size_t key_len);

// TLS_CONFIG_set_ciphersuite sets the preference |pref| for the cipher suite
// identified by |id| in |config|.  |kTlsPrefer| moves the suite to the head of
// the list, |kTlsAccept| moves it to the end, and |kTlsReject| removes it from
// the list.
//
// This function is thread-safe when compiled with support for threads. It may
// only be called when a |config| has not yet been frozen.
tls_result_t TLS_CONFIG_set_ciphersuite(TLS_CONFIG *config,
                                        tls_ciphersuite_t ciphersuite,
                                        tls_parameter_pref_t pref);

// TLS_CONFIG_set_eccurve sets the preference |pref| for the elliptic curve
// identified by |id| in |config|.  |kTlsPrefer| moves the suite to the head of
// the list, |kTlsAccept| moves it to the end, and |kTlsReject| removes it from
// the list.
//
// This function is thread-safe when compiled with support for threads. It may
// only be called when a |config| has not yet been frozen.
tls_result_t TLS_CONFIG_set_eccurve(TLS_CONFIG *config, tls_eccurve_t group,
                                    tls_parameter_pref_t pref);

// TLS_CONFIG_set_max_name_len sets the maximum |size| for distinguished names
// that can be parsed in X.509v3 certificates without causing an error.  This
// size is only used to calculate the needed memory in |TLS_connect_size|. If a
// certificate with a subject or issuer DN longer than |size| is encountered
// during the handshake, the handshake may still succeed if the caller provided
// sufficient memory.
//
// This function is thread-safe when compiled with support for threads. It may
// only be called when a |config| has not yet been frozen.
tls_result_t TLS_CONFIG_set_max_name_len(TLS_CONFIG *config, size_t size);

// TLS_CONFIG_freeze marks the given |config| as frozen.  Following this call,
// no further TLS_CONFIG_* API calls can be made using this |config| except
// |TLS_CONFIG_dup| and |TLS_CONFIG_cleanup|. This call must be made before this
// |config| can be used with |TLS_init|.
//
// This function is thread-safe when compiled with support for threads. It may
// only be called when a |config| has not yet been frozen.
tls_result_t TLS_CONFIG_freeze(TLS_CONFIG *config);

// TLS_CONFIG_cleanup zeros the memory used by the |config| and returns it. It
// will return NULL if |config| is NULL.
//
// This function is thread-safe when compiled with support for threads.
void *TLS_CONFIG_cleanup(TLS_CONFIG *config);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_PUBLIC_CONFIG_H
