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

#ifndef VAPIDSSL_X509V3_OID_H
#define VAPIDSSL_X509V3_OID_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>

#include "base/buf.h"
#include "common/stream.h"

// oid_t contains a short list of object IDs we recognize.  The full list is
// extensive, but these are all we need to parse X.509v3 certificates correctly.
typedef enum oid_t {
  kOidRsaEncryption,
  kOidMd5WithRsaEncryption,
  kOidSha1WithRsaEncryption,
  kOidSha256WithRsaEncryption,
  kOidSha384WithRsaEncryption,
  kOidX509v3CommonName,
  kOidX509v3KeyUsage,
  kOidX509v3SubjectAltNames,
  kOidX509v3BasicConstraints,
  kOidX509v3ExtendedKeyUsage,
  kOidX509v3AnyExtendedKeyUsage,
  kOidX509v3TlsWwwServerAuth,
  kOidUnknown,
} oid_t;

// oid_match tries to interpret the data in |buf| as an object ID.  If it
// recognizes an OID it returns the corresponding enum value.  Otherwise, it
// returns |kOidUnknown|.
oid_t oid_match(BUF *buf);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_X509V3_OID_H
