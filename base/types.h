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

#ifndef VAPIDSSL_BASE_TYPES_H
#define VAPIDSSL_BASE_TYPES_H
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* bool_t simply represents a true/false value, and lets the compiler pick the
 * storage type.  This type is distinct from |tls_result_t|, which is the
 * preferred return type to indicate the success or failure of a function. */
typedef enum bool_t {
  kFalse = 0,
  kTrue = 1,
} bool_t;

/* direction_t indicates whether data is being received from or sent to a
 * server. */
typedef enum direction_t {
  kRecv = 1,
  kSend = 2,
} direction_t;

/* end_t indicates the leading or trailing end of a sequence. */
typedef enum end_t {
  kFront,
  kBack,
} end_t;

/* data_protection_t indicates how data fields sent or received are protected.
 * Unprotected data is subject to interception and modification, authenticated
 * data has guaranteed integrity but is subject to interception, and encrypted
 * data has both integrity and confidentiality guarantees. */
typedef enum data_protection_t {
  kUnprotected,
  kAuthenticated,
  kEncrypted,
} data_protection_t;

/* uint24_t represents a 24 bit value, commonly used for lengths in the TLS
 * message layer.  This could be implemented as a uint8_t[3], but the additional
 * complexity does not currently justify the small savings in memory. */
typedef uint32_t uint24_t;

#if defined(__cplusplus)
}
#endif /* __cplusplus */
#endif /* VAPIDSSL_BASE_TYPES_H */
