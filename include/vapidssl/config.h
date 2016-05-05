/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef VAPIDSSL_CONFIG_H_
#define VAPIDSSL_CONFIG_H_

#include <stddef.h>
#include <stdint.h>

#include "vapidssl/error.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* This is the public TLS configuration API for VapidSSL.  It defines symbols
 * for the various algorithms and exposes a TLS_CONFIG structure  which can be
 * used to configure the client's TLS preferences.  VapidSSL promises not to
 * dynamically allocate any memory, so the API has routines to get the size of
 * opaque structures, and API calls that need memory take it as a parameter. */

/* TLS_CONFIG is a TLS configuration, defined in internal/config.h. This
 * structure is analogous to BoringSSL's SSL_CTX, defined as |struct ssl_ctx_st|
 * in openssl.ssl.h. */
typedef struct tls_config_st TLS_CONFIG;

/* Supported hash algorithms, numbered per RFC 5246, section 7.4.1.4.1
 * (https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1). These should
 * correspond to the ciphersuites enumerated by |ciphersuite_t|. When adding new
 * hash algorithms, be sure to update |VAPIDSSL_HASHES| in
 * vapidssl/internal/base.h. */
typedef enum tls_hash_t {
  kTlsHashSHA256 = 4,
  kTlsHashSHA384 = 5,
} tls_hash_t;

/* Supported TLS cipher IDs, numbered per
 * https://tools.ietf.org/html/rfc5246#appendix-A.5,
 * https://tools.ietf.org/html/rfc5289#section-3, and
 * https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-6.
 * When adding new ciphersuites, be sure to update |VAPIDSSL_CIPHERSUITES| in
 * vapidssl/internal/base.h. */
typedef enum tls_ciphersuite_t {
  kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
  kTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
  kTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
} tls_ciphersuite_t;

/* Supported TLS named EC curves, per
 * https://tools.ietf.org/html/draft-ietf-tls-curve25519-01. When adding new
 * elliptic curves, be sure to update |VAPIDSSL_CURVES| in
 * vapidssl/internal/base.h. */
typedef enum tls_curve_t {
  kTlsCurve25519 = 0x001D,
} tls_curve_t;

/* tls_parameter_pref_t is used by the caller to order various security
 * parameters to be negotiated with a server. Given a list of parameters,
 * setting a parameter to |kTlsPrefer| will add or move it to the beginning of
 * the list, setting it to |kTlsAccept| will add or move it to the end of the
 * list, and setting it to |kTlsReject| will remove it from the list. */
typedef enum tls_parameter_pref_t {
  kTlsPrefer,
  kTlsAccept,
  kTlsReject,
} tls_parameter_pref_t;

/* TLS_CONFIG_size sets |out| to be the amount of memory needed for a call to
 * |TLS_CONFIG_new| to be successful, given |num_thumbprints| to be trusted,
 * where each thumbprint is a |thumbprint_hash| digest of an X.509v3
 * certificate. */
tls_result_t TLS_CONFIG_size(size_t* out, tls_hash_t thumbprint_hash,
                             size_t num_thumbprints);

/* TLS_CONFIG_new takes a region of memory of |len| bytes starting at |mem| and
 * configures a TLS config that uses |thumbprint_hash| for trusted certificate
 * digests. */
TLS_CONFIG* TLS_CONFIG_new(void* mem, size_t len, tls_hash_t thumbprint_hash);

/* TLS_CONFIG_dup takes a region of memory of |len| bytes starting at |mem| and
 * configures a TLS config that is an unfrozen copy of |orig|.  This is useful
 * when a config has been frozen but subsequently needs to change (e.g. a cipher
 * suite needs to be disabled).  The workflow in this case is to:
 *  - Call |TLS_shutdown| and |TLS_cleanup| to destroy active connections.
 *  - Call |TLS_CONFIG_dup| and |TLS_CONFIG_cleanup| to copy and dispose of the
 *    old config.
 *  - Call |TLS_CONFIG_set_*| and |TLS_CONFIG_freeze| to modify and freeze the
 *    new config.
 *  - Call |TLS_new| and |TLS_connect| to reestablish the connections.
 *
 * This function is thread-safe when compiled with support for threads. */
TLS_CONFIG* TLS_CONFIG_dup(const TLS_CONFIG* orig, void* mem, size_t len);

/* TLS_CONFIG_add_trust adds trusted certificate |digest| of |len| bytes to
 * |config|.  |len| must match the output size of |config->thumbprint_hash|.
 *
 * This function is thread-safe when compiled with support for threads. It may
 * only be called when a |config| has not yet been frozen. */
tls_result_t TLS_CONFIG_add_trust(TLS_CONFIG* config, const uint8_t* digest,
                                  size_t len);

/* TLS_CONFIG_set_suite sets the preference |pref| for the cipher suite
 * identified by |id| in |config|.  |kTlsPrefer| moves the suite to the head of
 * the list, |kTlsAccept| moves it to the end, and |kTlsReject| removes it from
 * the list.
 *
 * This function is thread-safe when compiled with support for threads. It may
 * only be called when a |config| has not yet been frozen. */
tls_result_t TLS_CONFIG_set_suite(TLS_CONFIG* config, tls_ciphersuite_t id,
                                  tls_parameter_pref_t pref);

/* TLS_CONFIG_set_suite sets the preference |pref| for the elliptic curve
 * identified by |id| in |config|.  |kTlsPrefer| moves the suite to the head of
 * the list, |kTlsAccept| moves it to the end, and |kTlsReject| removes it from
 * the list.
 *
 * This function is thread-safe when compiled with support for threads. It may
 * only be called when a |config| has not yet been frozen. */
tls_result_t TLS_CONFIG_set_curve(TLS_CONFIG* config, tls_curve_t id,
                                  tls_parameter_pref_t pref);

/* TLS_CONFIG_set_max_name_len sets the maximum |size| for distinguished names
 * that can be parsed in X.509v3 certificates without causing an error.  This
 * size is only used to calculate the needed memory in |TLS_connect_size|. If a
 * certificate with a subject or issuer DN longer than |size| is encountered
 * during the handshake, the handshake may still succeed if the caller provided
 * sufficient memory.
 *
 * This function is thread-safe when compiled with support for threads. It may
 * only be called when a |config| has not yet been frozen. */
tls_result_t TLS_CONFIG_set_max_name_len(TLS_CONFIG* config, size_t size);

/* TLS_CONFIG_freeze marks the given |config| as frozen.  Following this call,
 * no further TLS_CONFIG_* API calls can be made using this |config| except
 * |TLS_CONFIG_dup| and |TLS_CONFIG_cleanup|. This call must be made before this
 * |config| can be used with |TLS_new|.
 *
 * This function is thread-safe when compiled with support for threads. It may
 * only be called when a |config| has not yet been frozen. */
tls_result_t TLS_CONFIG_freeze(TLS_CONFIG* config);

/* TLS_CONFIG_cleanup zeros the memory used by the |config| and returns it. It
 * will return NULL if |config| is NULL.
 *
 * This function is thread-safe when compiled with support for threads.  */
void* TLS_CONFIG_cleanup(TLS_CONFIG* config);

#if defined(__cplusplus)
}
#endif

#endif /* VAPIDSSL_CONFIG_H_ */
