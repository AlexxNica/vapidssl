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

#ifndef VAPIDSSL_X509V3_ASN1_H
#define VAPIDSSL_X509V3_ASN1_H
#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "x509v3/asn1_internal.h"

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "public/error.h"
#include "x509v3/oid.h"

// The functions in this file receive data and parse it as ASN.1/DER-encodings.

// Opaque ASN.1/DER structure, defined in x509v3/asn1_internal.h.
typedef struct asn1_st ASN1;

// asn1_class_t defines the class of ASN.1 type.  If not explicitly specified,
// the class is |kAsn1Universal|.
enum asn1_class_t {
  kAsn1Universal = 0x00,
  kAsn1Application = 0x40,
  kAsn1ContextSpecific = 0x80,
  kAsn1Private = 0xc0,
};

// asn1_length_method_t indicates whether a type is primitive (default) or
// constructed, i.e. determined by child elements.
enum asn1_length_method_t {
  kAsn1Primitive = 0x00,
  kAsn1Constructed = 0x20,
};

// asn1_tag_number_t lists the ASN.1 tag numbers for different supported ANS.1
// types. Only the "low tag numbers" (i.e. less than 31) are supported here.
typedef enum asn1_tag_number_t {
  // This is actually 'reserved for BER', but we use it here to signal when a
  // tag number is not known.  It would be an error to see any DER encodings
  // with this tag number.
  kAsn1Any = 0x00,
  kAsn1Boolean = 0x01,
  kAsn1Integer = 0x02,
  kAsn1BitString = 0x03,
  kAsn1OctetString = 0x04,
  kAsn1Null = 0x05,
  kAsn1ObjectID = 0x06,
  kAsn1Utf8String = 0x0c,
  kAsn1Sequence = 0x10,
  kAsn1Set = 0x11,
  kAsn1PrintableString = 0x13,
  kAsn1Ia5String = 0x16,
  kAsn1UtcTime = 0x17,
  kAsn1GeneralizedTime = 0x18,
} asn1_tag_number_t;

// asn1_init clears the state in the ASN.1/DER structure, making it ready to
// read a new encoding from |rx|.
void asn1_init(BUF *region, STREAM *rx, ASN1 *out);

// asn1_get_type returns type of the most recent encoding |asn1| has received
// (or is receiving).  This type is only valid after a successful call to
// |asn1_recv_type| or |asn1_recv_data|.
uint8_t asn1_get_type(ASN1 *asn1);

// asn1_get_len returns length of the most recent encoding |asn1| has received
// (or is receiving).  This length is only valid after a successful call to
// |asn1_recv_type| or |asn1_recv_data|.
size_t asn1_get_len(ASN1 *asn1);

// asn1_get_data returns a pointer the buffer containing the most recent
// encoding |asn1| has received.  This buffer only contains valid data after a
// successful call to |asn1_recv_encoding| or |asn1_recv_data|.
BUF *asn1_get_data(ASN1 *asn1);

// asn1_set_data registers |src| as the buffer from which to read ASN.1/DER
// encoded data using |out|.
void asn1_set_data(BUF *src, ASN1 *out);

// asn1_recv_type reads the next ASN.1/DER type and length into |asn1|.  In
// general, other functions such as |asn1_recv_data| should be preferred over
// this one.  However it is useful when dealing with optionally-absent,
// implicitly-tagged, and/or explicitly-tagged types:
// - For optional types, the call to |asn1_recv_type| can be used to detect a
//   types absence, and followed by a call to |asn1_recv_encoding| to perform
//   the equivalent of |asn1_recv_data| on the subsequent encoding.
// - For implicitly-tagged types, the call to |asn1_recv_type| should be
//   followed by a call to |asn1_recv_encoding|.
// - For explicitly-tagged types, the call to |asn1_recv_type| should be
//   followed by a call to |asn1_recv_data|, |asn1_recv_oid|, or
//   |asn1_nested_begin|.
//
// Importantly, |asn1_recv_type| has NO effect after a successful call until the
// encoding has been read.  This means |asn1_nested_begin| can be called for its
// side effects even if |asn1_recv_type| was called directly.
tls_result_t asn1_recv_type(ASN1 *asn1);

// asn1_recv_encoding allocates space for and receives an ASN.1/DER encoding.
// It is an error to call |asn1_recv_encoding| without first calling
// |asn1_recv_type|.  In practice, this function should not be called directly,
// except as specified in |asn1_recv_type|.
tls_result_t asn1_recv_encoding(ASN1 *asn1);

// asn1_recv_data calls both |asn1_recv_type| and |asn1_recv_encoding| to
// receive a complete DER-encoded ASN.1 element.  It matches the element against
// the expected |tag|, which may be |kAsn1Any|.  If |tag| is not |kAsn1Any|, the
// tag number of the received type must match the given |tag| number. Errors
// generated include decoding errors which indicate the connection should be
// terminated, and I/O errors which indicate the call should be retried.
tls_result_t asn1_recv_data(ASN1 *asn1, asn1_tag_number_t tag);

// asn1_nested_begin reads the type and length of a constructed encoding.  It
// checks that type matches the given |tag| number, which must be one of the
// encodings with a constructed length (|kAsn1OctetString|, |kAsn1Sequence|, or
// |kAsn1Set|) or context-specific (i.e. an implicitly or explicitly tagged
// element). It calls |stream_begin_nested| to track length of the nested
// encoding. |stream_nested_finish| must be called after the nested encoding has
// been completely read before reading other encodings.
tls_result_t asn1_nested_begin(ASN1 *asn1, asn1_tag_number_t tag);

// asn1_reset clears |asn1|'s type, length, and data.
void asn1_reset(ASN1 *asn1);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // VAPIDSSL_X509V3_ASN1_H
