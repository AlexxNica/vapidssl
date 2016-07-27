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

#include "tls1_2/config.h"
#include "tls1_2/config_internal.h"

#include <assert.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/macros.h"
#include "base/types.h"
#include "public/error.h"
#include "tls1_2/ciphersuite.h"
#include "x509v3/truststore.h"

static const uint8_t kMaxCiphersuites = 3;
static const uint8_t kMaxEcCurves = 1;
static const size_t kTicketDefault = 192;

// TODO(aarongreen): Add thread safety, primarily by adding a one-way switch
// that is tripped by |TLS_CONFIG_freeze| and checked by all setters and
// getters.

static bool_t config_has_param(LIST *list, uint16_t param);
static tls_result_t config_get_params(LIST *list, BUF *region, uint16_t first,
                                      BUF *out);
static tls_result_t config_set_param(LIST *list, uint16_t param,
                                     tls_parameter_pref_t pref);
static void config_reject_param(LIST *list, uint16_t param);
static tls_result_t config_accept_param(LIST *list, uint16_t param);
static tls_result_t config_prefer_param(LIST *list, uint16_t param);

static const tls_ciphersuite_t kDefaultCiphers[] = {
    kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    kTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    kTLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};

static const tls_eccurve_t kDefaultEcCurves[] = {
    kTlsCurve25519,
};

static const size_t kDefaultMaxNameLen = 192;
static const size_t kDefaultMaxKeyLen = 320;

// Public API.

size_t TLS_CONFIG_size(size_t max_signers) {
  return sizeof(TLS_CONFIG) + truststore_size(max_signers) +
         LIST_SIZE(uint16_t, kMaxCiphersuites) +
         LIST_SIZE(uint16_t, kMaxEcCurves);
}

tls_result_t TLS_CONFIG_init(void *mem, size_t len, size_t max_signers,
                             TLS_CONFIG **out) {
  size_t i = 0;
  size_t n = 0;
  if (!mem || max_signers == 0 || len < TLS_CONFIG_size(max_signers)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidArgument);
  }
  // Wrap the memory
  memset(mem, 0, len);
  TLS_CONFIG *config = (TLS_CONFIG *)mem;
  buf_wrap(mem, len, sizeof(TLS_CONFIG), &config->region);
  // TODO(aarongreen): Set up the lock
  // Set default lengths
  config->fragment = kFragmentDefault;
  config->ticket_size = kTicketDefault;
  // Set up truststore}
  if (!truststore_init(&config->region, max_signers, &config->truststore)) {
    return kTlsFailure;
  }
  // Set up ciphersuite list.  Use uint16_t instead of the enum to make the size
  // explicit.
  if (!LIST_NEW(uint16_t, &config->region, kMaxCiphersuites,
                &config->ciphersuites)) {
    return kTlsFailure;
  }
  n = arraysize(kDefaultCiphers);
  for (i = 0; i < n; ++i) {
    TLS_CONFIG_set_ciphersuite(config, kDefaultCiphers[i], kTlsAccept);
  }
  // Set up EC curves.  Use uint16_t instead of the enum to make the size
  // explicit.
  if (!LIST_NEW(uint16_t, &config->region, kMaxEcCurves, &config->eccurves)) {
    return kTlsFailure;
  }
  n = arraysize(kDefaultEcCurves);
  for (i = 0; i < n; ++i) {
    TLS_CONFIG_set_eccurve(config, kDefaultEcCurves[i], kTlsAccept);
  }
  // Set up other sizes.
  config->max_name_len = kDefaultMaxNameLen;
  config->max_key_len = kDefaultMaxKeyLen;
  *out = config;
  return kTlsSuccess;
}

tls_result_t TLS_CONFIG_trust_signer(TLS_CONFIG *config, const uint8_t *dn,
                                     size_t dn_len, const uint8_t *key,
                                     size_t key_len) {
  if (!config || !dn || dn_len == 0 || !key || key_len == 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidArgument);
  }
  return truststore_add(&config->truststore, dn, dn_len, key, key_len);
}

tls_result_t TLS_CONFIG_set_ciphersuite(TLS_CONFIG *config,
                                        tls_ciphersuite_t ciphersuite,
                                        tls_parameter_pref_t pref) {
  if (!config) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidArgument);
  }
  if (pref != kTlsReject && !ciphersuite_is_supported(ciphersuite)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedAlgorithm);
  }
  return config_set_param(&config->ciphersuites, ciphersuite, pref);
}

tls_result_t TLS_CONFIG_set_eccurve(TLS_CONFIG *config, tls_eccurve_t eccurve,
                                    tls_parameter_pref_t pref) {
  if (!config) {
    return ERROR_SET(kTlsErrVapid, kTlsErrInvalidArgument);
  }
  if (pref == kTlsReject) {
    config_reject_param(&config->eccurves, eccurve);
    return kTlsSuccess;
  }
  // See if we can find a key exchange that supports this DH group
  uint16_t *i = NULL;
  for (i = LIST_BEGIN(uint16_t, &config->ciphersuites); i;
       i = LIST_NEXT(uint16_t, &config->ciphersuites)) {
    if (ciphersuite_get_keyex((tls_ciphersuite_t)(*i), eccurve)) {
      break;
    }
  }
  if (!i) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedAlgorithm);
  }
  return config_set_param(&config->eccurves, eccurve, pref);
}

void *TLS_CONFIG_cleanup(TLS_CONFIG *config) {
  void *raw = NULL;
  if (config && buf_size(&config->region) != 0) {
    // This call flattens *everything* in |config|!
    raw = buf_unwrap(&config->region);
  }
  return raw;
}

// Library routines

config_fragment_size_t config_get_fragment_length(const TLS_CONFIG *config) {
  assert(config);
  return config->fragment;
}

size_t config_get_ticket_length(const TLS_CONFIG *config) {
  assert(config);
  return config->ticket_size;
}

bool_t config_has_ciphersuite(const TLS_CONFIG *config,
                              tls_ciphersuite_t ciphersuite) {
  assert(config);
  // Iterate over all supported ciphersuites.  Discard constness, but don't make
  // any changes to the list.
  LIST *list = (LIST *)&config->ciphersuites;
  return config_has_param(list, ciphersuite);
}

tls_result_t config_get_ciphersuites(const TLS_CONFIG *config, BUF *region,
                                     tls_ciphersuite_t resumed, BUF *out) {
  assert(config);
  assert(region);
  assert(out);
  // Iterate over all supported ciphersuites.  Discard constness, but don't make
  // any changes to the list.
  LIST *list = (LIST *)&config->ciphersuites;
  return config_get_params(list, region, resumed, out);
}

bool_t config_has_eccurve(const TLS_CONFIG *config, tls_eccurve_t curve) {
  assert(config);
  // Iterate over all supported EC curves.  Discard constness, but don't make
  // any changes to the list.
  LIST *list = (LIST *)&config->eccurves;
  return config_has_param(list, curve);
}

tls_result_t config_get_eccurves(const TLS_CONFIG *config, BUF *region,
                                 BUF *out) {
  // Iterate over all supported EC curves.  Discard constness, but don't make
  // any changes to the list.
  LIST *list = (LIST *)&config->eccurves;
  return config_get_params(list, region, 0, out);
}

bool_t config_has_signature_alg(const TLS_CONFIG *config,
                                uint16_t signature_alg) {
  assert(config);
  // Iterate over all supported EC curves.  Discard constness, but don't make
  // any changes to the list.
  LIST *list = (LIST *)&config->ciphersuites;
  for (uint16_t *ciphersuite = LIST_BEGIN(uint16_t, list); ciphersuite;
       ciphersuite = LIST_NEXT(uint16_t, list)) {
    if (signature_alg == ciphersuite_get_signature_algorithm(*ciphersuite)) {
      return kTrue;
    }
  }
  return kFalse;
}

tls_result_t config_get_signature_algs(const TLS_CONFIG *config, BUF *region,
                                       BUF *out) {
  // Iterate over all supported ciphersuites.  Discard constness, but don't make
  // any changes to the list.
  LIST *list = (LIST *)&config->ciphersuites;
  if (!buf_malloc(region, LIST_LEN(uint16_t, list) * sizeof(uint16_t), out)) {
    return kTlsFailure;
  }
  uint16_t signature_alg = 0;
  size_t produced = 0;
  uint32_t previous = 0;
  for (uint16_t *ciphersuite = LIST_BEGIN(uint16_t, list); ciphersuite;
       ciphersuite = LIST_NEXT(uint16_t, list)) {
    signature_alg = ciphersuite_get_signature_algorithm(*ciphersuite);
    while (buf_ready(out) >= sizeof(uint16_t)) {
      buf_get_val(out, sizeof(uint16_t), &previous);
      if (previous == signature_alg) {
        break;
      }
    }
    if (buf_ready(out) == 0) {
      assert(buf_available(out) >= sizeof(uint16_t));
      buf_put_val(out, sizeof(uint16_t), signature_alg);
    }
    produced = buf_consumed(out) + sizeof(uint16_t);
    buf_reset(out, 0);
    buf_produce(out, produced, NULL);
  }
  BUF tmp = buf_init();
  buf_split(out, buf_ready(out), &tmp);
  buf_free(&tmp);
  return kTlsSuccess;
}

size_t config_get_max_aead_size(const TLS_CONFIG *config) {
  assert(config);
  size_t size = 0;
  size_t max = 0;
  // Iterate over all supported ciphersuites.  Discard constness, but don't make
  // any changes to the list.
  LIST *list = (LIST *)&config->ciphersuites;
  for (uint16_t *ciphersuite = LIST_BEGIN(uint16_t, list); ciphersuite;
       ciphersuite = LIST_NEXT(uint16_t, list)) {
    size = aead_get_state_size(ciphersuite_get_aead(*ciphersuite));
    if (size > max) {
      max = size;
    }
  }
  return max;
}

size_t config_get_max_nonce_len(const TLS_CONFIG *config) {
  assert(config);
  size_t size = 0;
  size_t max = 0;
  // Iterate over all supported ciphersuites.  Discard constness, but don't make
  // any changes to the list.
  LIST *list = (LIST *)&config->ciphersuites;
  for (uint16_t *ciphersuite = LIST_BEGIN(uint16_t, list); ciphersuite;
       ciphersuite = LIST_NEXT(uint16_t, list)) {
    size = ciphersuite_fix_nonce_length(*ciphersuite);
    if (!ciphersuite_xor_nonce(*ciphersuite)) {
      size += ciphersuite_var_nonce_length(*ciphersuite);
    }
    if (size > max) {
      max = size;
    }
  }
  return max;
}

size_t config_get_max_hash_size(const TLS_CONFIG *config) {
  assert(config);
  size_t size = 0;
  size_t max = 0;
  // Iterate over all supported ciphersuites
  LIST *list = (LIST *)&config->ciphersuites;
  for (uint16_t *value = LIST_BEGIN(uint16_t, list); value;
       value = LIST_NEXT(uint16_t, list)) {
    size = hash_get_state_size(ciphersuite_get_hash(*value));
    if (size > max) {
      max = size;
    }
  }
  return max;
}

size_t config_get_hashes_size(const TLS_CONFIG *config) {
  assert(config);
  size_t total = 0;
  // Iterate over all hashes; if they're supported, add their size.
  LIST *list = (LIST *)&config->ciphersuites;
  for (const HASH *hash = hash_next(NULL); hash; hash = hash_next(hash)) {
    for (uint16_t *value = LIST_BEGIN(uint16_t, list); value;
         value = LIST_NEXT(uint16_t, list)) {
      if (hash == ciphersuite_get_hash(*value)) {
        total += hash_get_state_size(hash);
        break;
      }
    }
  }
  return total;
}

size_t config_get_max_name_length(const TLS_CONFIG *config) {
  assert(config);
  return config->max_name_len;
}

size_t config_get_max_key_length(const TLS_CONFIG *config) {
  assert(config);
  return config->max_key_len;
}

const LIST *config_get_truststore(const TLS_CONFIG *config) {
  assert(config);
  return &config->truststore;
}

// Static functions.

static bool_t config_has_param(LIST *list, uint16_t param) {
  assert(list);
  uint16_t *i = NULL;
  for (i = LIST_BEGIN(uint16_t, list); i && *i != param;
       i = LIST_NEXT(uint16_t, list)) {
  }
  return (i ? kTrue : kFalse);
}

static tls_result_t config_get_params(LIST *list, BUF *region, uint16_t first,
                                      BUF *out) {
  assert(list);
  assert(region);
  assert(out);
  if (LIST_LEN(uint16_t, list) == 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrNoAvailableOptions);
  }
  if (!buf_malloc(region, LIST_LEN(uint16_t, list) * sizeof(uint16_t), out)) {
    return kTlsFailure;
  }
  if (config_has_param(list, first)) {
    buf_put_val(out, sizeof(uint16_t), first);
  }
  for (uint16_t *i = LIST_BEGIN(uint16_t, list); i;
       i = LIST_NEXT(uint16_t, list)) {
    if (*i != first) {
      buf_put_val(out, sizeof(uint16_t), *i);
    }
  }
  return kTlsSuccess;
}

static tls_result_t config_set_param(LIST *list, uint16_t param,
                                     tls_parameter_pref_t pref) {
  assert(list);
  config_reject_param(list, param);
  if (pref == kTlsAccept) {
    return config_accept_param(list, param);
  } else if (pref == kTlsPrefer) {
    return config_prefer_param(list, param);
  } else {
    return kTlsSuccess;
  }
}

static void config_reject_param(LIST *list, uint16_t param) {
  assert(list);
  uint16_t *value = NULL;
  size_t n = LIST_LEN(uint16_t, list);
  size_t i = 0;
  // Find the element in question
  for (; i < n; ++i) {
    value = LIST_GET(uint16_t, list, i);
    if (*value == param) {
      break;
    }
  }
  // Return if not in the list.
  if (i == n) {
    return;
  }
  ++i;
  // Move it to the back, then delete it
  for (; i < n; ++i) {
    LIST_SWAP(uint16_t, list, i - 1, i);
  }
  LIST_DEL(uint16_t, list);
}

static tls_result_t config_accept_param(LIST *list, uint16_t param) {
  uint16_t *value = LIST_ADD(uint16_t, list);
  if (!value) {
    return kTlsFailure;
  }
  *value = param;
  return kTlsSuccess;
}

static tls_result_t config_prefer_param(LIST *list, uint16_t param) {
  uint16_t *value = LIST_ADD_FRONT(uint16_t, list);
  if (!value) {
    return kTlsFailure;
  }
  *value = param;
  return kTlsSuccess;
}
