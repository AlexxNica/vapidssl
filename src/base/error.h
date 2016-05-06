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

#ifndef VAPIDSSL_BASE_ERROR_H
#define VAPIDSSL_BASE_ERROR_H
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "vapidssl/error.h"

/* This is the internal API for error handling in VapidSSL.  See
 * vapidssl/error.h for more details on the public API. */

/* error_set records the |file|, |line|, |source|, and |reason| details of a
 * generated error.  These details can later be matched by |TLS_ERROR_test| or
 * retrieved with |TLS_ERROR_get|.
 *
 * NOTE: |error_set| does not follow the normal return value convention.  It
 * always returns |kTlsFailure| to allow callers to clearly indicate when they
 * are returning early do to an error, e.g. "return ERROR_SET(...);".  This
 * function cannot fail since APIs call and check |error_clear| before
 * proceeding as documented below. */
tls_result_t error_set(const char *file, int line, tls_error_source_t source,
                       int reason);

/* error_clear resets the error state to indicate no error.  It must be called
 * at the beginning of each public API routine and its return value must be
 * checked.  It returns |kTlsFailure| if |TLS_ERROR_init| has not been called by
 * this thread, and |kTlsSuccess| otherwise. */
tls_result_t error_clear(void);

/* The ERROR_SET macro automatically adds the __FILE__ and __LINE__
 * information to an |error_set| call. */
#define ERROR_SET(source, reason) error_set(__FILE__, __LINE__, source, reason)

#if defined(__cplusplus)
}
#endif /* __cplusplus */
#endif /* VAPIDSSL_BASE_ERROR_H */
