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

#include "x509v3/asn1.h"
#include "x509v3/asn1_internal.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "common/stream.h"
#include "x509v3/oid.h"

// Macros
#define ASN1_TAG(asn1) (asn1->type & 0x1f)

// Forward declarations.

// asn1_is_valid checks conditions which should be invariant.
static void asn1_is_valid(ASN1 *asn1);
// asn1_valid_type examines the type and length previously read, and returns
// whether they are valid according to ASN.1/DER specifications.
static bool_t asn1_valid_type(ASN1 *asn1);

// Library routines

void asn1_init(BUF *region, STREAM *rx, ASN1 *out) {
  assert(region);
  assert(rx);
  assert(out);
  memset(out, 0, sizeof(*out));
  out->region = region;
  out->rx = rx;
  out->data = &out->internal;
  asn1_reset(out);
}

uint8_t asn1_get_type(ASN1 *asn1) {
  asn1_is_valid(asn1);
  assert(asn1->state >= kAsn1TypeRead);
  return asn1->type;
}

size_t asn1_get_len(ASN1 *asn1) {
  asn1_is_valid(asn1);
  assert(asn1->state >= kAsn1LengthRead);
  return asn1->len;
}

BUF *asn1_get_data(ASN1 *asn1) {
  asn1_is_valid(asn1);
  assert(asn1->state >= kAsn1DataRead);
  return asn1->data;
}

void asn1_set_data(BUF *external, ASN1 *out) {
  asn1_is_valid(out);
  assert(external);
  assert(out->state == kAsn1Unread || out->state == kAsn1DataRead);
  if (external != out->data) {
    asn1_reset(out);
  }
  out->data = external;
}

tls_result_t asn1_recv_type(ASN1 *asn1) {
  asn1_is_valid(asn1);
  if (asn1->state == kAsn1DataRead) {
    asn1_reset(asn1);
  }
  // Have we read the type yet?
  if (asn1->state < kAsn1TypeRead) {
    if (!stream_recv_u8(asn1->rx, &asn1->type)) {
      return kTlsFailure;
    }
    // No multi-byte tag support.
    if (ASN1_TAG(asn1) == 0x1f) {
      return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
    }
    asn1->state = kAsn1TypeRead;
  }
  // Have we read the short form or length of long form yet?
  if (asn1->state < kAsn1LenLenRead) {
    if (!stream_recv_u8(asn1->rx, &asn1->len_len)) {
      return kTlsFailure;
    }
    if (asn1->len_len < 0x80) {
      // Short form. Zero is allowed, e.g. |kAsn1Null|.
      asn1->len = asn1->len_len;
      asn1->len_len = 1;
      asn1->state = kAsn1LengthRead;
    } else if (asn1->len_len == 0x80 || asn1->len_len > 0x84) {
      // Long form must have at least one byte.
      // More than 4 GB of data at once is not supported.
      asn1_reset(asn1);
      return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
    } else {
      asn1->state = kAsn1LenLenRead;
    }
  }
  // Have we read the long form length yet?
  if (asn1->state < kAsn1LengthRead) {
    if (!stream_recv_uint(asn1->rx, (0x7f & asn1->len_len), &asn1->len)) {
      return kTlsFailure;
    }
    // A long form length must be expressed in the minimum number of bytes
    // possible. This means the leading byte must not be zero and the length
    // must be more than 127.
    size_t min = 0x80;
    if (asn1->len_len > 0x81) {
      min = 1 << (((0x7f & asn1->len_len) - 1) * 8);
    }
    if (asn1->len < min) {
      asn1_reset(asn1);
      return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
    }
    asn1->state = kAsn1LengthRead;
  }
  if (!asn1_valid_type(asn1)) {
    asn1_reset(asn1);
    return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
  }
  // If zero length, we've already read the 'data'.
  if (asn1->len == 0) {
    asn1->state = kAsn1DataRead;
  }
  return kTlsSuccess;
}

tls_result_t asn1_recv_encoding(ASN1 *asn1) {
  asn1_is_valid(asn1);
  assert(asn1->state == kAsn1LengthRead);
  assert(asn1->len > 0);
  size_t size = buf_size(asn1->data);
  // Allocate buffer on first try.
  if (size == 0 && asn1->len != 0 &&
      !buf_malloc(asn1->region, asn1->len, asn1->data)) {
    asn1_reset(asn1);
    return kTlsFailure;
  }
  // External data buffers may be larger than needed; clip them.
  size = buf_size(asn1->data);
  assert(asn1->len <= size);
  if (size > asn1->len) {
    buf_reset(asn1->data, size - asn1->len);
  }
  // Read the data.
  if (!stream_recv_buf(asn1->rx, NULL, 0, asn1->data)) {
    return kTlsFailure;
  }
  asn1->state = kAsn1DataRead;
  // Do some basic sanity checks on a few types.
  uint32_t val = 0;
  switch (ASN1_TAG(asn1)) {
    case kAsn1Boolean:
      if (!buf_get_val(asn1->data, 1, &val) || (val != 0x00 && val != 0xff)) {
        asn1_reset(asn1);
        return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
      }
      break;
    case kAsn1BitString:
      if (!buf_get_val(asn1->data, 1, &val) || val > 7) {
        asn1_reset(asn1);
        return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
      }
      break;
    default:
      return kTlsSuccess;
  }
  // For those types where we touched the data, rewind the buffer.
  buf_reset(asn1->data, size - asn1->len);
  buf_produce(asn1->data, asn1->len, NULL);
  return kTlsSuccess;
}

tls_result_t asn1_recv_data(ASN1 *asn1, asn1_tag_number_t tag) {
  asn1_is_valid(asn1);
  if (asn1->state == kAsn1DataRead) {
    asn1_reset(asn1);
  }
  if (asn1->state < kAsn1LengthRead && !asn1_recv_type(asn1)) {
    return kTlsFailure;
  }
  if (tag != kAsn1Any && tag != ASN1_TAG(asn1)) {
    asn1_reset(asn1);
    return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
  }
  if (asn1->state < kAsn1DataRead && !asn1_recv_encoding(asn1)) {
    return kTlsFailure;
  }
  return kTlsSuccess;
}

tls_result_t asn1_nested_begin(ASN1 *asn1, asn1_tag_number_t tag) {
  asn1_is_valid(asn1);
  if (!asn1_recv_type(asn1)) {
    return kTlsFailure;
  }
  switch (tag) {
    case kAsn1Any:
      // |kAsn1Any| is used for explicitly tagged nested types
      if ((asn1->type & kAsn1ContextSpecific) == 0 ||
          (asn1->type & kAsn1Constructed) == 0) {
        asn1_reset(asn1);
        return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
      }
      break;
    case kAsn1OctetString:
    case kAsn1Sequence:
    case kAsn1Set:
      // Normal and implicit nested types must match the given type
      if (tag != ASN1_TAG(asn1)) {
        asn1_reset(asn1);
        return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
      }
      break;
    default:
      asn1_reset(asn1);
      return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
  }
  if (!stream_nested_begin(asn1->rx, asn1->len)) {
    return kTlsFailure;
  }
  // Invalidate the parent element, so that subsequent calls to |asn1_recv_data|
  // read the child elements instead.
  asn1_reset(asn1);
  return kTlsSuccess;
}

void asn1_reset(ASN1 *asn1) {
  asn1_is_valid(asn1);
  asn1->state = kAsn1Unread;
  asn1->type = 0;
  asn1->len_len = 0;
  asn1->len = 0;
  asn1->data = &asn1->internal;
  if (buf_size(asn1->data) != 0) {
    buf_free(asn1->data);
  }
}

// Static functions.

static void asn1_is_valid(ASN1 *asn1) {
  assert(asn1);
  assert(asn1->region);
  assert((asn1->len >> (asn1->len_len * 8)) == 0);
  assert(asn1->data);
  assert(buf_size(&asn1->internal) == 0 ||
         buf_size(&asn1->internal) == asn1->len);
}

static bool_t asn1_valid_type(ASN1 *asn1) {
  assert(asn1);
  assert(asn1->state >= kAsn1TypeRead);
  // Return true if context-specific, since there's nothing else we can check
  // for implicitly or explicitly tagged types.
  if ((asn1->type & kAsn1ContextSpecific) != 0) {
    return kTrue;
  }
  // Check if the length and construction makes sense for each type
  switch (ASN1_TAG(asn1)) {
    case kAsn1Boolean:
      return (asn1->type & kAsn1Constructed) == 0 && asn1->len == 1;
    case kAsn1Integer:
    case kAsn1BitString:  // DER guarantees |len| of at least 1
    case kAsn1ObjectID:
    case kAsn1UtcTime:
    case kAsn1GeneralizedTime:
      return (asn1->type & kAsn1Constructed) == 0 && asn1->len != 0;
    case kAsn1OctetString:
    case kAsn1Utf8String:
    case kAsn1PrintableString:
    case kAsn1Ia5String:
      return (asn1->type & kAsn1Constructed) == 0;
    case kAsn1Null:
      return (asn1->type & kAsn1Constructed) == 0 && asn1->len == 0;
    case kAsn1Sequence:
    case kAsn1Set:
      return (asn1->type & kAsn1Constructed) != 0;
    default:
      return kFalse;
  }
}
