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

#ifndef VAPIDSSL_BASE_ARCH_THREAD_H
#define VAPIDSSL_BASE_ARCH_THREAD_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// This is the platform and/or OS specific interface for thread-local storage.
// This file does NOT contain concurrency primitives; see arch/lock.h instead.
// This file gives a way to set and retrieve memory specific to however many
// threads are using the library, for as low as one. It is mainly used to keep
// error stacks separate between threads (see error.h).

// thread_get_local returns a pointer to a region of memory dedicated to this
// thread's use only previously set by |thread_set_local|, or NULL if
// |thread_setlocal| has not been called.
void *thread_get_local(void);

// thread_set_local takes a region |mem| of memory and registers it as being
// dedicated to this thread's use only.  Calling |thread_set_local| with NULL
// unregisters the memory region from current thread.  It is the caller's
// responsibility to zero and/or free the memory as appropriate.
void thread_set_local(void *mem);

#if defined(__cplusplus)
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_ARCH_THREAD_H
