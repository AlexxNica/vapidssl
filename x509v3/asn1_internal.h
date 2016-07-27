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

#ifndef VAPIDSSL_X509V3_ASN1_INTERNAL_H
#define VAPIDSSL_X509V3_ASN1_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

#include "base/buf.h"
#include "common/stream.h"

typedef enum asn1_t {
  kAsn1Unread,
  kAsn1TypeRead,
  kAsn1LenLenRead,
  kAsn1LengthRead,
  kAsn1DataRead,
} asn1_t;

struct asn1_st {
  asn1_t state;
  STREAM *rx;
  BUF *region;
  uint8_t type;
  uint8_t len_len;
  uint32_t len;
  BUF *data;
  BUF internal;
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_X509V3_ASN1_INTERNAL_H
