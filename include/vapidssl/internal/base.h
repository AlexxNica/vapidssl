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

#ifndef VAPIDSSL_INTERNAL_BASE_H_
#define VAPIDSSL_INTERNAL_BASE_H_

#include "vapidssl/config.h"
#include "vapidssl/error.h"
#include "vapidssl/tls.h"

/* These macros and the ones below need to be preprocessor definitions in order
 * to be used with statically sized arrays. The first three are here instead of
 * with their corresponding enums because those enums are publicly visible in
 * vapidssl/config.h and these macros do not need to be. */
#define VAPIDSSL_HASHES 2
#define VAPIDSSL_CIPHERSUITES 3
#define VAPIDSSL_CURVES 1

/* Supported key exchange algorithms.  These should correspond to the
 * ciphersuites enumerated by |tls_ciphersuite_t|. 0 is avoided to require
 * |keyx_t| fields to be explicitly set. */
typedef enum keyx_t {
  kKeyxECDHE = 1,
} keyx_t;
#define VAPIDSSL_KEYXS 1

/* Supported signing algorithms, numbered per RFC 5246, section 7.4.1.4.1
 * (https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1). These should
 * correspond to the ciphersuites enumerated by |tls_ciphersuite_t|. */
typedef enum sign_t {
  kSignRSA = 1,
} sign_t;
#define VAPIDSSL_SIGNS 1 /* Must fit in uint8_t. */

/* Supported AEAD ciphers.  These should correspond to the ciphersuites
 * enumerated by |tls_ciphersuite_t|. 0 is avoided to require |aead_t| fields to
 * be explicitly set. */
typedef enum aead_t {
  kAeadAes128Gcm = 1,
  kAeadAes256Gcm,
  kAeadChaCha20Poly1305,
} aead_t;
#define VAPIDSSL_AEADS 3

/* bool_t simply represents a true/false value, and lets the compiler pick the
 * storage type.  This type is used to distinguish between success/failure of
 * |tls_result_t|. */
typedef enum bool_t {
  kFalse = 0,
  kTrue = 1,
} bool_t;

typedef tls_hash_t hash_t;

/* direction_t indicates whether data is being received from or sent to a
 * server. */
typedef enum direction_t {
  kRecv = 1,
  kSend = 2,
} direction_t;

/* uint24_t represents a 24 bit value, commonly used for lengths in the TLS
 * message layer.  This could be implemented as a uint8_t[3], but the additional
 * complexity does not currently justify the small savings in memory. */
typedef uint32_t uint24_t;

/* In theory, OO-style abstraction could be obtained by making these structs
 * opaque and using only pointers everywhere; in practice that leads to overhead
 * in both memory and code size that is to be avoided.  As a result, abstraction
 * as a principle is not rigorously enforced, except for security-sensitive code
 * where strong guarantees of correctness are desired (e.g. struct buf_st). */

/* Opaque AEAD cipher structure, defined in crypt/aead.h. */
typedef struct aead_st AEAD;

/* Opaque ASN.1/DER structure, defined in internal/asn1.h. */
typedef struct asn1_st ASN1;

/* Opaque buffer structure, defined in internal/buf.h. */
typedef struct buf_st BUF;

/* Opaque X.509v3 certificate structure, defined in internal/cert.h. */
typedef struct certificate_st CERTIFICATE;

/* Opaque cryptographic hash structure, defined in crypt/hash.h. */
typedef struct hash_st HASH;

/* Opaque handshake state structure, defined in internal/handshake.h. */
typedef struct handshake_st HANDSHAKE;

/* Opaque key exchange algorithm structure, defined in crypt/keyx.h. */
typedef struct keyx_st KEYX;

/* Opaque synchronization primitive structure, defined in arch/.../arch.c. */
typedef struct lock_st LOCK;

/* Opaque TLS message layer structure, defined in internal/message.h. */
typedef struct message_st MESSAGE;

/* Opaque TLS record layer structure, defined in internal/record.h. */
typedef struct record_st RECORD;

/* Opaque signature verification algorithm structure, defined in crypt/sign.h.*/
typedef struct sign_st SIGN;

/* Opaque TLS cipher ciphersuite structure, defined in internal/ciphersuite.h.
 */
typedef struct ciphersuite_st CIPHERSUITE;

/* STATIC_ASSERT is used to check invariants at compile time that might
 * introduce bugs or vulnerabilities if not true.  For example, we might check
 * that an |int| is at least 4 bytes. */
#define STATIC_ASSERT(expr, name) typedef char ASSERT_##name[((expr) ? 1 : -1)]

/* The following ensure we don't have more parameters than the protocol lets us
 * send or receive. */
STATIC_ASSERT(VAPIDSSL_HASHES <= 0xFF, number_of_hashes_fits_in_one_byte);
STATIC_ASSERT(VAPIDSSL_CIPHERSUITES <= 0xFF,
              number_of_ciphersuites_fits_in_one_byte);
STATIC_ASSERT(VAPIDSSL_CURVES <= 0xFFFF, number_of_curves_fits_in_one_byte);

#endif /* VAPIDSSL_INTERNAL_BASE_H_ */
