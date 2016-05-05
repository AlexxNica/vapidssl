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

#ifndef VAPIDSSL_ARCH_THREAD_H
#define VAPIDSSL_ARCH_THREAD_H

#include "vapidssl/internal/base.h"

/* This is the platform and/or OS specific interface for thread-local storage.
 * This file does NOT contain concurrency primitives; see arch/lock.h instead.
 * This file gives a way to set and retrieve memory specific to however many
 * threads are using the library, for as low as one. It is mainly used to keep
 * error stacks separate between threads (see error.h). */

/* thread_get_local returns a pointer to a region of memory dedicated to this
 * thread's use only previously set by |thread_set_local|, or NULL if
 * |thread_setlocal| has not been called. */
void *thread_get_local(void);

/* thread_set_local takes a region |mem| of memory and registers it as being
 * dedicated to this thread's use only.  Calling |thread_set_local| with NULL
 * unregisters the memory region from current thread.  It is the caller's
 * responsibility to zero and/or free the memory as appropriate. */
void thread_set_local(void *mem);

#endif /* VAPIDSSL_ARCH_THREAD_H */
