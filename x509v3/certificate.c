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

#include "x509v3/certificate.h"
#include "x509v3/certificate_internal.h"

#include <assert.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/list.h"
#include "base/platform/time.h"
// #include "common/idna.h"
#include "crypto/hash.h"
#include "crypto/sign.h"
#include "x509v3/asn1.h"
#include "x509v3/oid.h"
#include "x509v3/truststore.h"

// Forward declarations
static void certificate_hash_sizes(size_t *out_states_len,
                                   size_t *out_digest_len);
static bool_t certificate_wildcard_match(CERTIFICATE *chain, BUF *name);
static tls_result_t certificate_begin(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_tbs(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_tagged_field(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_version(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_serial_number(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_algorithm_begin(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_algorithm(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_rsa_params(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_algorithm_done(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_issuer(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_validity(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_validity_time(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_subject_ca(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_subject_leaf(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_rdn_begin(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_rdn_attr_begin(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_rdn_attr_type(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_common_name(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_rdn_attr_value(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_rdn_attr_done(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_subject_public_key_info(CERTIFICATE *chain,
                                                        ASN1 *asn1);
static tls_result_t certificate_key_or_signature(CERTIFICATE *chain,
                                                 ASN1 *asn1);
static tls_result_t certificate_unique_uid(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_extensions(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_extension_begin(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_extension_id(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_extension_type(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_extension_critical(CERTIFICATE *chain,
                                                   ASN1 *asn1);
static tls_result_t certificate_check_critical(CERTIFICATE *chain,
                                               bool_t critical);
static tls_result_t certificate_extension_value(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_key_usage(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_alt_name_begin(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_alt_name_tag(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_dns_name(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_other_name(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_alt_name_done(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_basic_constraints(CERTIFICATE *chain,
                                                  ASN1 *asn1);
static tls_result_t certificate_basic_constraints_ca(CERTIFICATE *chain,
                                                     ASN1 *asn1);
static tls_result_t certificate_basic_constraints_path_len(CERTIFICATE *chain,
                                                           ASN1 *asn1);
static tls_result_t certificate_extended_key_usage(CERTIFICATE *chain,
                                                   ASN1 *asn1);
static tls_result_t certificate_key_purpose_id(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_extension(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_extension_done(CERTIFICATE *chain, ASN1 *asn1);
static tls_result_t certificate_done(CERTIFICATE *chain, ASN1 *asn1);

static const uint8_t kX509v3 = 2;
static uint16_t kEpochYear = 1970;
static uint8_t kDaysPerMonth[] = {31, 28, 31, 30, 31, 30,
                                  31, 31, 30, 31, 30, 31};

size_t certificate_size(size_t max_name_len, size_t max_key_len) {
  size_t states_len = 0;
  size_t digest_len = 0;
  certificate_hash_sizes(&states_len, &digest_len);
  // Need to hold subject and issuer DN simultaneously
  // Need to hold signature and issuer key simultaneously
  // Need to hold multi-hash and TBS digest simultaneously
  // Check all overflows
  assert(max_name_len < max_name_len * 2);
  size_t size = max_name_len * 2;
  assert(max_key_len < max_key_len * 2);
  assert(size < size + (max_key_len * 2));
  size += max_key_len * 2;
  assert(size < size + states_len);
  size += states_len;
  assert(size < size + digest_len);
  size += digest_len;
  return size;
}

tls_result_t certificate_init(BUF *region, size_t max_name_len, BUF *leaf_key,
                              CERTIFICATE *out) {
  assert(region);
  assert(out);
  memset(out, 0, sizeof(CERTIFICATE));
  out->region = region;
  out->leaf_key = leaf_key;
  size_t states_len = 0;
  size_t digest_len = 0;
  size_t max_key_len = buf_size(leaf_key);
  certificate_hash_sizes(&states_len, &digest_len);
  // Preallocate all of our memory, leaving only |max_key_len| bytes left over.
  // This should be sufficient, as the CA's public key should be the longest
  // single field we need to read.
  return buf_malloc(region, max_name_len, &out->subject) &&
         buf_malloc(region, max_name_len, &out->issuer) &&
         buf_malloc(region, states_len, &out->hash_states) &&
         buf_malloc(region, digest_len, &out->digest) &&
         buf_malloc(region, max_key_len, &out->signature);
}

void certificate_set_stream(STREAM *rx, CERTIFICATE *out) {
  assert(rx);
  assert(out);
  out->rx = rx;
  asn1_init(out->region, rx, &out->asn1);
}

void certificate_set_name(BUF *sni, CERTIFICATE *out) {
  assert(sni);
  assert(out);
  assert(buf_size(sni) <= buf_size(&out->subject));
  out->sni = sni;
}

void certificate_set_trust(const LIST *truststore, CERTIFICATE *out) {
  assert(truststore);
  assert(out);
  out->truststore = truststore;
}

tls_result_t certificate_recv(CERTIFICATE *chain) {
  assert(chain);
  assert(chain->rx);
  assert(chain->sni);
  assert(chain->truststore);
  if (!chain->next) {
    chain->next = certificate_begin;
    asn1_reset(&chain->asn1);
    buf_reset(&chain->subject, 0);
    buf_copy(&chain->issuer, &chain->subject);
    buf_reset(&chain->issuer, 0);
  }
  while (chain->next) {
    if (!chain->next(chain, &chain->asn1)) {
      return kTlsFailure;
    }
  }
  ++chain->depth;
  return kTlsSuccess;
}

bool_t certificate_is_trusted(CERTIFICATE *chain) {
  assert(chain);
  return chain->trusted;
}

void certificate_cleanup(CERTIFICATE *chain) {
  buf_free(&chain->signature);
  buf_free(&chain->digest);
  buf_free(&chain->hash_states);
  buf_free(&chain->issuer);
  buf_free(&chain->subject);
  memset(chain, 0, sizeof(*chain));
}

// Static functions

// TODO(aarongreen): Ideally this would only count hashes matching
// non-rejected ciphersuites, but that happens at a higher layer.  Rework
// later.
static void certificate_hash_sizes(size_t *out_states_len,
                                   size_t *out_digest_len) {
  size_t total = 0;
  size_t digest = 0;
  size_t max_digest = 0;
  for (const HASH *hash = hash_next(NULL); hash; hash = hash_next(hash)) {
    total += hash_get_state_size(hash);
    digest = hash_get_output_size(hash);
    if (digest > max_digest) {
      max_digest = digest;
    }
  }
  *out_states_len = total;
  *out_digest_len = max_digest;
}

static bool_t certificate_wildcard_match(CERTIFICATE *chain, BUF *name) {
  assert(buf_consumed(name) == 0);
  assert(buf_consumed(chain->sni) == 0);
  if (buf_equal(chain->sni, name)) {
    return kTrue;
  }
  size_t dns_len = buf_ready(name);
  size_t sni_len = buf_ready(chain->sni);
  bool_t result = kFalse;
  uint32_t c = 0;
  if (buf_get_val(name, 1, &c) && c == '*' && buf_get_val(name, 1, &c) &&
      c == '.') {
    while (buf_get_val(chain->sni, 1, &c) && c != '.') {
    }
    result = c == '.' && buf_equal(chain->sni, name);
  }
  buf_reset(name, 0);
  buf_produce(name, dns_len, NULL);
  buf_reset(chain->sni, 0);
  buf_produce(chain->sni, sni_len, NULL);
  return result;
}

static tls_result_t certificate_begin(CERTIFICATE *chain, ASN1 *asn1) {
  // Matches |certificate_done|.
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  chain->state = kCertificateIdentity;
  if (!stream_add_hashes(chain->rx, &chain->hash_states)) {
    return kTlsFailure;
  }
  chain->next = certificate_tbs;
  return kTlsSuccess;
}

static tls_result_t certificate_tbs(CERTIFICATE *chain, ASN1 *asn1) {
  // Matches |certificate_tagged_field| and |certificate_extension_done|[4].
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = certificate_tagged_field;
  return kTlsSuccess;
}

static tls_result_t certificate_tagged_field(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_type(asn1)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  switch (asn1_get_type(asn1)) {
    // Explicit tag 0.
    case (kAsn1ContextSpecific | kAsn1Constructed | 0):
      if (chain->state != kCertificateIdentity) {
        return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
      }
      // Matches |certificate_version|
      if (!asn1_nested_begin(asn1, kAsn1Any)) {
        return kTlsFailure;
      }
      chain->next = certificate_version;
      break;
    // Implicit tag 1.
    case (kAsn1ContextSpecific | 1):
    // Implicit tag 2.
    case (kAsn1ContextSpecific | 2):
      if (chain->state != kCertificatePublicKey) {
        return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
      }
      chain->next = certificate_unique_uid;
      break;
    // Explicit tag 3.
    case (kAsn1ContextSpecific | kAsn1Constructed | 3):
      if (chain->state != kCertificatePublicKey) {
        return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
      }
      // Matches |certificate_extension_done|[3]
      if (!asn1_nested_begin(asn1, kAsn1Any)) {
        return kTlsFailure;
      }
      chain->next = certificate_extensions;
      break;
    default:
      // Matches |certificate_tbs|.
      if (!stream_nested_finish(chain->rx)) {
        return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
      }
      chain->next = certificate_algorithm_begin;
      break;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_version(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Integer)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  uint32_t version = 0;
  BUF *data = asn1_get_data(asn1);
  if (!buf_get_val(data, 1, &version) || buf_ready(data) != 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  if (version != kX509v3) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedCertificate);
  }
  // Matches |certificate_tagged_field|.
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  chain->next = certificate_serial_number;
  return kTlsSuccess;
}

static tls_result_t certificate_serial_number(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Integer)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  uint32_t serial_number = 0;
  BUF *data = asn1_get_data(asn1);
  if (!buf_get_val(data, 1, &serial_number) || (serial_number & 0x80)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  } else if (serial_number == 0 && (!buf_get_val(data, 1, &serial_number) ||
                                    !(serial_number & 0x80))) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  chain->next = certificate_algorithm_begin;
  return kTlsSuccess;
}

static tls_result_t certificate_algorithm_begin(CERTIFICATE *chain,
                                                ASN1 *asn1) {
  // Matches |certificate_algorithm_done|.
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = certificate_algorithm;
  return kTlsSuccess;
}

static tls_result_t certificate_algorithm(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1ObjectID)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  // Handle key type and exit early.
  if (chain->state == kCertificatePublicKey) {
    switch (oid_match(asn1_get_data(asn1))) {
      case kOidRsaEncryption:
        // TODO(aarongreen): As soon as we have more than just RSA
        // keys/signatures, we need to match the 'hash-and-sign' OIDs of a
        // certificate's signature with the 'sign-only' OID on the issuer's key.
        chain->next = certificate_rsa_params;
        return kTlsSuccess;
      default:
        return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedCertificate);
    }
  }
  // Handle signature types.
  const SIGN *sign = NULL;
  certificate_f next = NULL;
  switch (oid_match(asn1_get_data(asn1))) {
    case kOidMd5WithRsaEncryption:
      // Unsupported, but allowed for self-signed roots.
      sign = NULL;
      next = certificate_rsa_params;
      break;
    case kOidSha1WithRsaEncryption:
      // Unsupported, but allowed for self-signed roots.
      sign = NULL;
      next = certificate_rsa_params;
      break;
    case kOidSha256WithRsaEncryption:
      sign = sign_find(kSignRSA, kTlsHashSHA256);
      next = certificate_rsa_params;
      break;
    case kOidSha384WithRsaEncryption:
      sign = sign_find(kSignRSA, kTlsHashSHA384);
      next = certificate_rsa_params;
      break;
    default:
      return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedCertificate);
  }
  if (chain->state == kCertificateIdentity) {
    // Set the signing algorithm for this certificate and select the actual hash
    // we need. If the signing algorithm is unsupported, pick any hash to follow
    // along.
    const HASH *hash = hash_next(NULL);
    if (sign) {
      chain->next_sign = sign;
      hash = sign_get_hash(sign);
    }
    if (!stream_select_hash(chain->rx, hash)) {
      return kTlsFailure;
    }
  } else {
    // Make sure the algorithm hasn't changed, and move |next_sign| to
    // |prev_sign| so when reach a key in the next certificate we know how this
    // signature was constructed.
    if (sign != chain->next_sign) {
      return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
    }
    chain->prev_sign = chain->next_sign;
    chain->next_sign = NULL;
  }
  chain->next = next;
  return kTlsSuccess;
}

static tls_result_t certificate_rsa_params(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Null)) {
    return kTlsFailure;
  }
  chain->next = certificate_algorithm_done;
  return kTlsSuccess;
}

static tls_result_t certificate_algorithm_done(CERTIFICATE *chain, ASN1 *asn1) {
  chain->next = NULL;
  // Matches |certificate_algorithm_begin|.
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  if (chain->state == kCertificateIdentity) {
    chain->next = certificate_issuer;
  } else {
    chain->next = certificate_key_or_signature;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_issuer(CERTIFICATE *chain, ASN1 *asn1) {
  asn1_set_data(&chain->issuer, asn1);
  if (!asn1_recv_data(&chain->asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = certificate_validity;
  return kTlsSuccess;
}

static tls_result_t certificate_validity(CERTIFICATE *chain, ASN1 *asn1) {
  // Matches |certificate_validity_time|.
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = certificate_validity_time;
  return kTlsSuccess;
}

static tls_result_t certificate_validity_time(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Any)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  // We choose not to accept any UTC timed cert before 2000 or after 2099.
  uint32_t year;
  uint8_t type = asn1_get_type(asn1);
  BUF *data = asn1_get_data(asn1);
  if (type == (kAsn1Universal | kAsn1Primitive | kAsn1GeneralizedTime)) {
    buf_atou(data, 4, &year);
  } else if (type == (kAsn1Universal | kAsn1Primitive | kAsn1UtcTime)) {
    buf_atou(data, 2, &year);
    year += 2000;
  } else {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // Thanks, Pope Gregory XIII.
  if (year < kEpochYear) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  uint64_t date = (year - kEpochYear) * 365;
  date += (year - (kEpochYear - (kEpochYear % 4) + 1)) / 4;
  date -= (year - (kEpochYear - (kEpochYear % 100) + 1)) / 100;
  date += (year - (kEpochYear - (kEpochYear % 400) + 1)) / 400;
  bool_t is_leap_year = (!(year % 4) && ((year % 100) || !(year % 400)));
  uint32_t month;
  buf_atou(data, 2, &month);
  uint32_t day_of_month;
  buf_atou(data, 2, &day_of_month);
  // Does |date| makes sense for month (including Feb. 29th in leap years)?
  if (month == 0 || month > 12 || day_of_month == 0 ||
      (day_of_month > kDaysPerMonth[month - 1] &&
       (!is_leap_year || month != 2 || day_of_month != 29))) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // Post February in a leap year.
  if (month > 2 && is_leap_year) {
    date++;
  }
  // Add up months we've passed.
  while (--month != 0) {
    date += kDaysPerMonth[month];
  }
  // Convert |date| from days to seconds, but don't count today.
  date += (day_of_month - 1);
  date *= 86400;
  uint32_t hours;
  buf_atou(data, 2, &hours);
  date += hours * 3600;
  uint32_t minutes;
  buf_atou(data, 2, &minutes);
  date += minutes * 60;
  uint32_t seconds;
  buf_atou(data, 2, &seconds);
  date += seconds;
  uint32_t zed;
  if (hours > 23 || minutes > 59 || seconds > 59 ||
      !buf_get_val(data, 1, &zed) || zed != 'Z' || buf_ready(data) != 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // Check parsed date against current time. If the sequence is incomplete, we
  // must be in NotBefore; otherwise we're in NotAfter.
  uint64_t now = time_now();
  // Matches |certificate_validity|.
  if (!stream_nested_finish(chain->rx)) {
    if (now < date) {
      return ERROR_SET(kTlsErrVapid, kTlsErrExpiredCertificate);
    }
    chain->next = certificate_validity_time;
  } else {
    if (now > date) {
      return ERROR_SET(kTlsErrVapid, kTlsErrExpiredCertificate);
    } else if (chain->depth == 0) {
      chain->next = certificate_subject_leaf;
    } else {
      chain->next = certificate_subject_ca;
    }
  }
  return kTlsSuccess;
}

static tls_result_t certificate_subject_ca(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  BUF *data = asn1_get_data(asn1);
  if (!buf_equal(data, &chain->subject)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  chain->next = certificate_subject_public_key_info;
  return kTlsSuccess;
}

static tls_result_t certificate_subject_leaf(CERTIFICATE *chain, ASN1 *asn1) {
  // Matches |certificate_rdn_attr_done|[2].
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  if (stream_nested_finish(chain->rx)) {
    chain->empty_subject_dn = kTrue;
    chain->next = certificate_subject_public_key_info;
  } else {
    chain->next = certificate_rdn_begin;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_rdn_begin(CERTIFICATE *chain, ASN1 *asn1) {
  // Matches |certificate_rdn_attr_done|[1].
  if (!asn1_nested_begin(asn1, kAsn1Set)) {
    return kTlsFailure;
  }
  chain->next = certificate_rdn_attr_begin;
  return kTlsSuccess;
}

static tls_result_t certificate_rdn_attr_begin(CERTIFICATE *chain, ASN1 *asn1) {
  // Matches |certificate_rdn_attr_done|[0].
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = certificate_rdn_attr_type;
  return kTlsSuccess;
}

static tls_result_t certificate_rdn_attr_type(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1ObjectID)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  switch (oid_match(asn1_get_data(asn1))) {
    case kOidX509v3CommonName:
      chain->next = certificate_common_name;
      break;
    default:
      chain->next = certificate_rdn_attr_value;
      break;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_common_name(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Any)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  BUF *data = asn1_get_data(asn1);
  // TODO(aarongreen): We should pass the name through |idna_canonicalize|.
  chain->name_match |= certificate_wildcard_match(chain, data);
  chain->next = certificate_rdn_attr_done;
  return kTlsSuccess;
}

static tls_result_t certificate_rdn_attr_value(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Any)) {
    return kTlsFailure;
  }
  chain->next = certificate_rdn_attr_done;
  return kTlsSuccess;
}

static tls_result_t certificate_rdn_attr_done(CERTIFICATE *chain, ASN1 *asn1) {
  chain->next = NULL;
  // [0]: Matches |certificate_rdn_attr_begin|.
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // [1]: Matches |certificate_rdn_begin|.
  if (!stream_nested_finish(chain->rx)) {
    chain->next = certificate_rdn_attr_begin;
  }
  // [2]: Matches |certificate_leaf_subject|.
  if (!stream_nested_finish(chain->rx)) {
    chain->next = certificate_rdn_begin;
  } else {
    chain->next = certificate_subject_public_key_info;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_subject_public_key_info(CERTIFICATE *chain,
                                                        ASN1 *asn1) {
  // Matches |certificate_key_or_signature|.
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->state = kCertificatePublicKey;
  chain->next = certificate_algorithm_begin;
  return kTlsSuccess;
}

// Leave the bit string as an opaque DER-encoded public key or signature.
static tls_result_t certificate_key_or_signature(CERTIFICATE *chain,
                                                 ASN1 *asn1) {
  assert(chain->state != kCertificateIdentity);
  if (chain->state == kCertificateSignature) {
    // Read the data into |signature|
    asn1_set_data(&chain->signature, asn1);
  } else if (chain->depth == 0) {
    // If this is the first certificate, read the public key into |leaf_key|
    asn1_set_data(chain->leaf_key, asn1);
  }
  // Read the bit string
  if (!asn1_recv_data(asn1, kAsn1BitString)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  uint32_t unused_bits = 0;
  BUF *data = asn1_get_data(asn1);
  if (!buf_get_val(data, 1, &unused_bits) || unused_bits != 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // Save signature for later
  if (chain->state == kCertificateSignature) {
    chain->next = certificate_done;
    return kTlsSuccess;
  }
  // If not the leaf cert, verify the signature of the preceding cert
  if (chain->depth != 0) {
    if (!chain->prev_sign ||
        !sign_verify(chain->prev_sign, &chain->digest, &chain->signature,
                     data)) {
      return kTlsFailure;
    }
    chain->prev_sign = NULL;
    buf_reset(&chain->digest, 0);
    buf_reset(&chain->signature, 0);
  }
  // Matches |certificate_subject_public_key_info|
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  chain->next = certificate_tagged_field;
  return kTlsSuccess;
}

static tls_result_t certificate_unique_uid(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_encoding(asn1)) {
    return kTlsFailure;
  }
  chain->next = certificate_tagged_field;
  return kTlsSuccess;
}

static tls_result_t certificate_extensions(CERTIFICATE *chain, ASN1 *asn1) {
  // Matches |certificate_extension_done|[2].
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = certificate_extension_begin;
  return kTlsSuccess;
}

static tls_result_t certificate_extension_begin(CERTIFICATE *chain,
                                                ASN1 *asn1) {
  // Matches |certificate_extension_done|[1].
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = certificate_extension_id;
  return kTlsSuccess;
}

static tls_result_t certificate_extension_id(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1ObjectID)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  chain->oid = oid_match(asn1_get_data(asn1));
  chain->next = certificate_extension_type;
  return kTlsSuccess;
}

static tls_result_t certificate_extension_type(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_type(asn1)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  if (asn1_get_type(asn1) != kAsn1Boolean) {
    return certificate_check_critical(chain, kFalse /* not critical */);
  }
  chain->next = certificate_extension_critical;
  return kTlsSuccess;
}

static tls_result_t certificate_extension_critical(CERTIFICATE *chain,
                                                   ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Boolean)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  uint32_t val;
  BUF *data = asn1_get_data(asn1);
  buf_get_val(data, 1, &val);
  bool_t critical = (val == 0 ? kFalse : kTrue);
  return certificate_check_critical(chain, critical);
}

static tls_result_t certificate_check_critical(CERTIFICATE *chain,
                                               bool_t critical) {
  // See |certificate_extension_id| for the case mapping.
  switch (chain->oid) {
    case kOidX509v3KeyUsage:
      if (!critical) {
        return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
      }
      break;
    case kOidX509v3SubjectAltNames:
      if (chain->empty_subject_dn && !critical) {
        return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
      }
      break;
    case kOidX509v3BasicConstraints:
      if (chain->depth != 0 && !critical) {
        return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
      }
      break;
    case kOidX509v3ExtendedKeyUsage:
      break;
    default:
      // Missing support for a critical extension; we must fail per
      // https://tools.ietf.org/html/rfc5280#section-4.2.
      if (critical) {
        return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedCertificate);
      }
      break;
  }
  chain->next = certificate_extension_value;
  return kTlsSuccess;
}

static tls_result_t certificate_extension_value(CERTIFICATE *chain,
                                                ASN1 *asn1) {
  // Matches |certificate_extension_done|[0].
  if (!asn1_nested_begin(asn1, kAsn1OctetString)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  // See |certificate_extension_id| for the case mapping.
  switch (chain->oid) {
    case kOidX509v3KeyUsage:
      chain->next = certificate_key_usage;
      break;
    case kOidX509v3SubjectAltNames:
      chain->next = certificate_alt_name_begin;
      break;
    case kOidX509v3BasicConstraints:
      chain->next = certificate_basic_constraints;
      break;
    case kOidX509v3ExtendedKeyUsage:
      chain->next = certificate_extended_key_usage;
      break;
    default:
      chain->next = certificate_extension;
      break;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_key_usage(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1BitString)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  // For this to be a valid signing certificate, at least one field of KeyUsage
  // must be set and decipherOnly must NOT be set. The first condition means the
  // length is more than one, the second means it is less than three.
  if (asn1_get_len(asn1) != 2) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  uint32_t key_usage = 0;
  BUF *data = asn1_get_data(asn1);
  buf_get_val(data, 1, &key_usage);
  chain->key_usage = (uint16_t)key_usage;
  chain->next = certificate_extension_done;
  return kTlsSuccess;
}

static tls_result_t certificate_alt_name_begin(CERTIFICATE *chain, ASN1 *asn1) {
  // Matches |certificate_alt_name_done|.
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = certificate_alt_name_tag;
  return kTlsSuccess;
}

static tls_result_t certificate_alt_name_tag(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_type(asn1)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  uint8_t tag = asn1_get_type(asn1);
  if ((tag & kAsn1ContextSpecific) == 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  switch (tag & 0x1f) {
    case 2:  // DNS name.
      chain->next = certificate_dns_name;
      break;
    default:
      chain->next = certificate_other_name;
      break;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_dns_name(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_encoding(asn1)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  BUF *data = asn1_get_data(asn1);
  chain->name_match |= certificate_wildcard_match(chain, data);
  chain->next = certificate_alt_name_done;
  return kTlsSuccess;
}

static tls_result_t certificate_other_name(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_encoding(asn1)) {
    return kTlsFailure;
  }
  chain->next = certificate_alt_name_done;
  return kTlsSuccess;
}

static tls_result_t certificate_alt_name_done(CERTIFICATE *chain, ASN1 *asn1) {
  // Matches |certificate_alt_name_begin|.
  if (stream_nested_finish(chain->rx)) {
    chain->next = certificate_extension_done;
  } else {
    chain->next = certificate_alt_name_tag;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_basic_constraints(CERTIFICATE *chain,
                                                  ASN1 *asn1) {
  // Matches |certificate_basic_constraints_ca| or
  // |certificate_basic_constraints_path_len|.
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  if (stream_nested_finish(chain->rx)) {
    chain->ca = kFalse;
    chain->has_path_len = kFalse;
    chain->next = certificate_extension_done;
  } else {
    chain->next = certificate_basic_constraints_ca;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_basic_constraints_ca(CERTIFICATE *chain,
                                                     ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Boolean)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  uint32_t is_ca;
  BUF *data = asn1_get_data(asn1);
  if (!buf_get_val(data, 1, &is_ca)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  chain->ca = (is_ca != 0 ? kTrue : kFalse);
  // Matches |certificate_basic_constraints|.
  if (stream_nested_finish(chain->rx)) {
    chain->has_path_len = kFalse;
    chain->next = certificate_extension_done;
  } else {
    chain->has_path_len = chain->ca;
    chain->next = certificate_basic_constraints_path_len;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_basic_constraints_path_len(CERTIFICATE *chain,
                                                           ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Integer)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  BUF *data = asn1_get_data(asn1);
  buf_get_val(data, asn1_get_len(asn1), &chain->path_len);
  // Matches |certificate_basic_constraints|.
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  chain->next = certificate_extension_done;
  return kTlsSuccess;
}

static tls_result_t certificate_extended_key_usage(CERTIFICATE *chain,
                                                   ASN1 *asn1) {
  // Matches |certificate_key_purpose_id|.
  if (!asn1_nested_begin(asn1, kAsn1Sequence)) {
    return kTlsFailure;
  }
  chain->next = certificate_key_purpose_id;
  return kTlsSuccess;
}

static tls_result_t certificate_key_purpose_id(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1ObjectID)) {
    return kTlsFailure;
  }
  chain->next = NULL;
  switch (oid_match(asn1_get_data(asn1))) {
    case kOidX509v3AnyExtendedKeyUsage:
      chain->key_usage |= kEkuAny;
      break;
    case kOidX509v3TlsWwwServerAuth:
      chain->key_usage |= kEkuServerAuth;
      break;
    default:
      break;
  }
  // Matches |certificate_extended_key_usage|.
  if (!stream_nested_finish(chain->rx)) {
    chain->next = certificate_key_purpose_id;
  } else {
    chain->next = certificate_extension_done;
  }
  return kTlsSuccess;
}

static tls_result_t certificate_extension(CERTIFICATE *chain, ASN1 *asn1) {
  if (!asn1_recv_data(asn1, kAsn1Any)) {
    return kTlsFailure;
  }
  chain->next = certificate_extension_done;
  return kTlsSuccess;
}

static tls_result_t certificate_extension_done(CERTIFICATE *chain, ASN1 *asn1) {
  chain->next = NULL;
  // [0]: Matches |certificate_extension_value|.
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // [1]: Matches |certificate_extension_begin|.
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // [2]: Matches |certificate_extensions|.
  if (!stream_nested_finish(chain->rx)) {
    chain->next = certificate_extension_begin;
    return kTlsSuccess;
  }
  // [3]: Matches |certificate_tagged_field|
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // [4]: Matches |certificate_tbs|.
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // We need to invoke an |asn1_reset| to free |asn1->data|.
  asn1_reset(asn1);
  // Save the digest of the TBS certificate structure.
  stream_final_digest(chain->rx, &chain->digest);
  chain->state = kCertificateSignature;
  chain->next = certificate_algorithm_begin;
  return kTlsSuccess;
}

static tls_result_t certificate_done(CERTIFICATE *chain, ASN1 *asn1) {
  chain->next = NULL;
  // Matches |certificate_begin|.
  if (!stream_nested_finish(chain->rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // Leaf certificate should have an empty, digital signature, any, or server
  // authentication key usage.
  uint16_t ku_mask = (kKuDigitalSignature | kEkuAny | kEkuServerAuth);
  if (chain->depth == 0 && chain->key_usage != 0 &&
      (chain->key_usage & ku_mask) == 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // Non-leaf certificates must be CAs.
  if (chain->depth != 0 && !chain->ca) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // Certificates with keyCertSign key usage must be CAs.
  if (chain->key_usage != 0 && (chain->key_usage & kKuKeyCertSign) != 0 &&
      !chain->ca) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // The certificate depth should not exceed its path length constraint.
  if (chain->has_path_len && (chain->path_len < (chain->depth - 1))) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // The certificate should match either the SNI or the previous certificate's
  // issuer.
  if (!chain->name_match) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  // See if this was signed by a known issuer.
  if (!chain->trusted && chain->prev_sign &&
      truststore_check(chain->truststore, chain->prev_sign, &chain->issuer,
                       &chain->digest, &chain->signature)) {
    chain->trusted = kTrue;
  }
  return kTlsSuccess;
}
