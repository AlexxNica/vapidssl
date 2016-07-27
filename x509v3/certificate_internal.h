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

#ifndef VAPIDSSL_X509V3_CERTIFICATE_INTERNAL_H
#define VAPIDSSL_X509V3_CERTIFICATE_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/list.h"
#include "crypto/hash.h"
#include "crypto/sign.h"
#include "public/config.h"
#include "public/error.h"
#include "x509v3/asn1.h"
#include "x509v3/oid.h"

struct certificate_st;

typedef tls_result_t (*certificate_f)(struct certificate_st *, ASN1 *);

enum certificate_state_t {
  kCertificateIdentity = 0,
  kCertificatePublicKey,
  kCertificateSignature,
};

enum key_usage_t {
  kKuDigitalSignature = 0x0001,
  kKuContentCommitment = 0x0002,
  kKuKeyEncipherment = 0x0004,
  kKuDataEncipherment = 0x0008,
  kKuKeyAgreement = 0x0010,
  kKuKeyCertSign = 0x0020,
  kKuCrlSign = 0x0040,
  kKuEncipherOnly = 0x0080,
  kKuDecipherOnly = 0x0100,
  kEkuAny = 0x0200,
  kEkuServerAuth = 0x0400,
  kEkulientAuth = 0x0800,
  kEkuCodeSigning = 0x1000,
  kEkuEmailProtection = 0x2000,
  kEkuTimeStamping = 0x4000,
  kEkuOcspSigning = 0x8000,
};

struct certificate_st {
  certificate_f next;
  enum certificate_state_t state;

  ASN1 asn1;
  STREAM *rx;
  BUF *region;
  BUF *sni;
  const LIST *truststore;
  BUF *leaf_key;

  BUF subject;
  BUF issuer;
  BUF hash_states;
  BUF digest;
  BUF signature;

  const SIGN *prev_sign;
  const SIGN *next_sign;
  oid_t oid;

  uint32_t depth;
  uint32_t path_len;
  uint16_t key_usage;

  uint8_t ca : 1;
  uint8_t has_path_len : 1;
  uint8_t name_match : 1;
  uint8_t empty_subject_dn : 1;

  bool_t trusted;
};

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_X509V3_CERTIFICATE_INTERNAL_H
