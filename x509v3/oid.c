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

#include "x509v3/oid.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base/buf.h"

typedef struct oid_st {
  oid_t oid;
  const char *data;
  size_t len;
} OID;

#define ADD_OID(oid, data) \
  { (oid), (data), sizeof(data) - 1 }
static const OID kOids[] = {
    ADD_OID(kOidRsaEncryption, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"),
    ADD_OID(kOidMd5WithRsaEncryption, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04"),
    ADD_OID(kOidSha1WithRsaEncryption, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05"),
    ADD_OID(kOidSha256WithRsaEncryption,
            "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"),
    ADD_OID(kOidSha384WithRsaEncryption,
            "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c"),
    ADD_OID(kOidX509v3CommonName, "\x55\x04\x03"),
    ADD_OID(kOidX509v3KeyUsage, "\x55\x1d\x0f"),
    ADD_OID(kOidX509v3SubjectAltNames, "\x55\x1d\x11"),
    ADD_OID(kOidX509v3BasicConstraints, "\x55\x1d\x13"),
    ADD_OID(kOidX509v3ExtendedKeyUsage, "\x55\x1d\x25"),
    ADD_OID(kOidX509v3AnyExtendedKeyUsage, "\x55\x1d\x25\x00"),
    ADD_OID(kOidX509v3TlsWwwServerAuth, "\x2b\x06\x01\x05\x05\x07\x03\x01"),
};
#undef ADD_OID

oid_t oid_match(BUF *buf) {
  assert(buf);
  assert(buf_consumed(buf) == 0);
  size_t len = buf_ready(buf);
  uint8_t *data = NULL;
  buf_consume(buf, len, &data);
  const OID *oid = NULL;
  for (size_t i = 0; i < kOidUnknown; ++i) {
    oid = &kOids[i];
    if (len == oid->len && memcmp(data, oid->data, len) == 0) {
      return oid->oid;
    }
  }
  return kOidUnknown;
}
