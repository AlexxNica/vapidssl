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

#ifndef VAPIDSSL_COMMON_HMAC_INTERNAL_H
#define VAPIDSSL_COMMON_HMAC_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "base/buf.h"
#include "crypto/hash.h"

// hmac_st represents the state needed to calculate and HMAC per RFC 2104.
// An HMAC using a given <key> over some <text> would be:
//    hash((key ^ opad)+hash((key ^ ipad)+text))
// where ^ is XOR, + is concatenation, and opad and ipad are a block of repeated
// 0x5C and 0x36 bytes, respectively.
struct hmac_st {
  // hash is the algorithm used to calculate the HMAC.
  const HASH *hash;
  // state is the HMAC state, which after |hmac_init|, this represents the state
  // for |hash| with (key ^ ipad) having already been added.
  BUF state;
  // pad is a buffer used to hold the ipad and opad data.
  BUF pad;
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_COMMON_HMAC_INTERNAL_H
