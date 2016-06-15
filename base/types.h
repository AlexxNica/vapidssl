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

#ifndef VAPIDSSL_BASE_TYPES_H
#define VAPIDSSL_BASE_TYPES_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// bool_t simply represents a true/false value, and lets the compiler pick the
// storage type.  This type is distinct from |tls_result_t|, which is the
// preferred return type to indicate the success or failure of a function.
typedef enum bool_t {
  kFalse = 0,
  kTrue = 1,
} bool_t;

// direction_t indicates whether data is being received from or sent to a
// server.
typedef enum direction_t {
  kRecv = 1,
  kSend = 2,
} direction_t;

// end_t indicates the leading or trailing end of a sequence.
typedef enum end_t {
  kFront,
  kBack,
} end_t;

// data_protection_t indicates how data fields sent or received are protected.
// Unprotected data is subject to interception and modification, authenticated
// data has guaranteed integrity but is subject to interception, and encrypted
// data has both integrity and confidentiality guarantees.
typedef enum data_protection_t {
  kUnprotected,
  kAuthenticated,
  kEncrypted,
} data_protection_t;

// uint24_t represents a 24 bit value, commonly used for lengths in the TLS
// message layer.  This could be implemented as a uint8_t[3], but the additional
// complexity does not currently justify the small savings in memory.
typedef uint32_t uint24_t;

#if defined(__cplusplus)
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_TYPES_H
