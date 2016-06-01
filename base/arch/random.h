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

#ifndef VAPIDSSL_BASE_ARCH_RANDOM_H
#define VAPIDSSL_BASE_ARCH_RANDOM_H
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h>

#include "base/buf.h"

/* This is the platform and/or OS specific interface for RNGs. */

/* random_buf fills a buffer's available space with random data.  With the
 * exception of implementation specifically designed for testing, bytes
 * generated must be uniformly distributed and unpredictable without additional
 * seeding, even to attacker with fine grained information about the library's
 * external state, such as the exact timing of calls to |random_buf|. */
void random_buf(BUF *out);

#if defined(__cplusplus)
}
#endif /* __cplusplus */
#endif /* VAPIDSSL_BASE_ARCH_RANDOM_H */