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

#ifndef VAPIDSSL_BASE_MACROS_H
#define VAPIDSSL_BASE_MACROS_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

// This file includes preprocessor macro definitions that are not specific to a
// particular type of object.

// arraysize returns the size of an array.  It only works on arrays that have
// not decayed to pointers.  In other words, it does NOT return the correct size
// for arrays passed as parameters, dynamically allocated arrays, etc.
#define arraysize(a) (sizeof a / sizeof *a)

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_BASE_MACROS_H
