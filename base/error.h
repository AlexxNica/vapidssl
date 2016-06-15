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

#ifndef VAPIDSSL_BASE_ERROR_H
#define VAPIDSSL_BASE_ERROR_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "public/error.h"

// This is the internal API for error handling in VapidSSL.  See public/error.h
// for more details on the public API.

// error_set records the |file|, |line|, |source|, and |reason| details of a
// generated error.  These details can later be matched by |TLS_ERROR_test| or
// retrieved with |TLS_ERROR_get|.
//
// NOTE: |error_set| does not follow the normal return value convention.  It
// always returns |kTlsFailure| to allow callers to clearly indicate when they
// are returning early do to an error, e.g. "return ERROR_SET(...);".  This
// function cannot fail since APIs call and check |error_clear| before
// proceeding as documented below.
tls_result_t error_set(const char *file, int line, tls_error_source_t source,
                       int reason);

// error_clear resets the error state to indicate no error.  It must be called
// at the beginning of each public API routine and its return value must be
// checked.  It returns |kTlsFailure| if |TLS_ERROR_init| has not been called by
// this thread, and |kTlsSuccess| otherwise.
tls_result_t error_clear(void);

// The ERROR_SET macro automatically adds the __FILE__ and __LINE__ information
// to an |error_set| call.
#define ERROR_SET(source, reason) error_set(__FILE__, __LINE__, source, reason)

#if defined(__cplusplus)
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_ERROR_H
