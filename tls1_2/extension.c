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

#include "tls1_2/extension.h"

#include <assert.h>
#include <string.h>

#include "base/error.h"
#include "base/macros.h"
#include "base/types.h"
#include "common/stream.h"
#include "public/error.h"
#include "tls1_2/config.h"
#include "tls1_2/ticket.h"
#include "tls1_2/tls.h"

// Type declarations

enum sni_t {
  kSniHostname = 0,
};

// Forward declarations

// TODO(aarongreen): Add ExtendedMasterSecret
// TODO(aarongreen): Add padding for ClientHello when between 256 and 511 bytes

static void extension_clear_data(EXTENSION *extension);
static tls_result_t extension_send_total(EXTENSION *extension);
static tls_result_t extension_send_next(EXTENSION *extension);
static tls_result_t extension_send_type(EXTENSION *extension);
static tls_result_t extension_send_length(EXTENSION *extension);
static tls_result_t extension_send_finish(EXTENSION *extension);
static tls_result_t extension_recv_total(EXTENSION *extension);
static tls_result_t extension_recv_next(EXTENSION *extension);
static tls_result_t extension_recv_type(EXTENSION *extension);
static tls_result_t extension_recv_length(EXTENSION *extension);
static tls_result_t extension_recv_finish(EXTENSION *extension);
static uint16_t extension_sni_client_hello_length(EXTENSION *extension);
static tls_result_t extension_sni_client_hello(EXTENSION *extension);
static tls_result_t extension_sni_client_hello_type(EXTENSION *extension);
static tls_result_t extension_sni_client_hello_data(EXTENSION *extension);
static uint16_t extension_mfl_client_hello_length(EXTENSION *extension);
static tls_result_t extension_mfl_client_hello(EXTENSION *extension);
static tls_result_t extension_mfl_server_hello(EXTENSION *extension);
static uint16_t extension_sec_client_hello_length(EXTENSION *extension);
static tls_result_t extension_sec_client_hello(EXTENSION *extension);
static uint16_t extension_sah_client_hello_length(EXTENSION *extension);
static tls_result_t extension_sah_client_hello(EXTENSION *extension);
static uint16_t extension_sst_client_hello_length(EXTENSION *extension);
static tls_result_t extension_sst_client_hello(EXTENSION *extension);

// Constants

// kExtensionOverhead is the number of bytes added to each extension: 2 bytes
// for type and 2 bytes for length.
static const uint16_t kExtensionOverhead = 4;

static const uint16_t kSniTypeLen = 1;
static const uint16_t kSniLengthLen = 2;
static const uint16_t kListLengthLen = 2;

static const struct extensions_st {
  extension_t type;
  uint16_t (*client_hello_length)(EXTENSION *extension);
  extension_f client_hello;
  extension_f server_hello;
} kExtensions[] = {
    // Per https://tools.ietf.org/html/rfc6066#section-3.
    {
        kExtServerNameIndication, extension_sni_client_hello_length,
        extension_sni_client_hello, extension_recv_finish,
    },
    // Per https://tools.ietf.org/html/rfc5077#section-3.2.
    {
        kExtStatelessSessionTicket, extension_sst_client_hello_length,
        extension_sst_client_hello, extension_recv_finish,
    },
    // Per https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1.
    {
        kExtSignatureAndHash, extension_sah_client_hello_length,
        extension_sah_client_hello, NULL,
    },
    // Per https://tools.ietf.org/html/rfc4492#section-5.1.
    // It is ambiguous as to whether servers can echo.  Ignore it if they do.
    {
        kExtSupportedEllipticCurve, extension_sec_client_hello_length,
        extension_sec_client_hello, extension_recv_finish,
    },
    // Per https://tools.ietf.org/html/rfc6066#section-4.
    {
        kExtMaxFragmentLength, extension_mfl_client_hello_length,
        extension_mfl_client_hello, extension_mfl_server_hello,
    },
};
static_assert((arraysize(kExtensions) < sizeof(uint8_t) * 8),
              "Too many extensions for bitmask.");

// Library routines

void extension_init(BUF *region, TLS *tls, EXTENSION *out) {
  assert(tls);
  assert(region);
  assert(out);
  memset(out, 0, sizeof(*out));
  out->tls = tls;
  out->region = region;
}

uint16_t extension_length(EXTENSION *extension) {
  assert(extension);
  uint24_t length = 0;
  uint24_t total = 0;
  size_t n = arraysize(kExtensions);
  for (size_t i = 0; i < n; ++i) {
    length = kExtensions[i].client_hello_length(extension);
    if (length != 0) {
      extension->sent |= (1UL << i);
      total += length;
    }
  }
  extension_clear_data(extension);
  return total;
}

tls_result_t extension_send(EXTENSION *extension) {
  assert(extension);
  if (extension->next == NULL) {
    extension->sent = 0;
    MESSAGE *message = tls_get_message(extension->tls, kSend);
    extension->stream = message_get_stream(message);
    extension->next = extension_send_total;
  }
  while (extension->next) {
    if (!extension->next(extension)) {
      return kTlsFailure;
    }
  }
  // Matches |extension_send_total|.
  if (!stream_nested_finish(extension->stream)) {
    assert(ERROR_SET(kTlsErrVapid, kTlsErrInternalError));
  }
  extension_clear_data(extension);
  return kTlsSuccess;
}

tls_result_t extension_recv(EXTENSION *extension) {
  assert(extension);
  if (extension->next == NULL) {
    extension->received = extension->sent;
    MESSAGE *message = tls_get_message(extension->tls, kRecv);
    extension->stream = message_get_stream(message);
    extension->next = extension_recv_total;
  }
  while (extension->next) {
    if (!extension->next(extension)) {
      return kTlsFailure;
    }
  }
  extension_clear_data(extension);
  return kTlsSuccess;
}

bool_t extension_echoed(EXTENSION *extension, extension_t type) {
  assert(extension);
  size_t n = arraysize(kExtensions);
  for (size_t i = 0; i < n; ++i) {
    if (kExtensions[i].type == type) {
      return (extension->received & (1UL << i) ? kTrue : kFalse);
    }
  }
  return kFalse;
}

// Static functions

static void extension_clear_data(EXTENSION *extension) {
  if (buf_size(&extension->internal) != 0) {
    buf_free(&extension->internal);
  }
  extension->data = NULL;
}

static tls_result_t extension_send_total(EXTENSION *extension) {
  uint16_t length = extension_length(extension);
  if (!stream_send_u16(extension->stream, length)) {
    return kTlsFailure;
  }
  extension->next = NULL;
  // Matches |extension_send|.
  if (!stream_nested_begin(extension->stream, length)) {
    return kTlsFailure;
  }
  extension->index = 0;
  extension->next = extension_send_next;
  return kTlsSuccess;
}

static tls_result_t extension_send_next(EXTENSION *extension) {
  extension->next = NULL;
  size_t i = extension->index;
  size_t n = arraysize(kExtensions);
  for (; i < n; ++i) {
    if (extension->sent & (1UL << i)) {
      extension->index = i;
      extension->next = extension_send_type;
      break;
    }
  }
  return kTlsSuccess;
}

// Send extensions

static tls_result_t extension_send_type(EXTENSION *extension) {
  if (!stream_send_u16(extension->stream, kExtensions[extension->index].type)) {
    return kTlsFailure;
  }
  extension->next = extension_send_length;
  return kTlsSuccess;
}

static tls_result_t extension_send_length(EXTENSION *extension) {
  uint16_t length =
      kExtensions[extension->index].client_hello_length(extension) -
      kExtensionOverhead;
  if (!stream_send_u16(extension->stream, length)) {
    return kTlsFailure;
  }
  extension->next = NULL;
  // Matches |extension_send_finish|.
  if (!stream_nested_begin(extension->stream, length)) {
    return kTlsFailure;
  }
  extension->next = kExtensions[extension->index].client_hello;
  return kTlsSuccess;
}

static tls_result_t extension_send_finish(EXTENSION *extension) {
  extension->next = NULL;
  // Matches |extension_send_len|.
  if (!stream_nested_finish(extension->stream)) {
    return kTlsFailure;
  }
  if (buf_size(&extension->internal)) {
    buf_free(&extension->internal);
  }
  ++extension->index;
  extension->next = extension_send_next;
  return kTlsSuccess;
}

// Receive extensions

static tls_result_t extension_recv_total(EXTENSION *extension) {
  uint16_t length = 0;
  if (!stream_recv_u16(extension->stream, &length)) {
    return kTlsFailure;
  }
  extension->next = NULL;
  // Matches |extension_recv|.
  if (!stream_nested_begin(extension->stream, length)) {
    return kTlsFailure;
  }
  extension->next = extension_recv_next;
  return kTlsSuccess;
}

static tls_result_t extension_recv_next(EXTENSION *extension) {
  extension->next = NULL;
  // Matches |extension_recv_total|.
  if (!stream_nested_finish(extension->stream)) {
    extension->next = extension_recv_type;
  }
  return kTlsSuccess;
}

static tls_result_t extension_recv_type(EXTENSION *extension) {
  uint16_t type = 0;
  if (!stream_recv_u16(extension->stream, &type)) {
    return kTlsFailure;
  }
  extension->next = NULL;
  size_t i = 0;
  size_t n = arraysize(kExtensions);
  for (; i < n; ++i) {
    if (kExtensions[i].type == type) {
      break;
    }
  }
  // Unknown or duplicate extension?
  if (i == n || ~extension->sent & (1UL << i)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedExtension);
  }
  extension->sent &= ~(1UL << i);
  extension->index = i;
  extension->next = extension_recv_length;
  return kTlsSuccess;
}

static tls_result_t extension_recv_length(EXTENSION *extension) {
  uint16_t length = 0;
  if (!stream_recv_u16(extension->stream, &length)) {
    return kTlsFailure;
  }
  // Matches |extension_recv_exit|.
  extension->next = NULL;
  if (!stream_nested_begin(extension->stream, length)) {
    return kTlsFailure;
  }
  extension->next = kExtensions[extension->index].server_hello;
  // If there's no server_hello callback, then server's MUST not echo.
  if (!extension->next) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedExtension);
  }
  return kTlsSuccess;
}

static tls_result_t extension_recv_finish(EXTENSION *extension) {
  extension->next = NULL;
  // Matches |extension_recv_len|.
  if (!stream_nested_finish(extension->stream)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
  }
  // Matches |extension_recv_total_len|.
  if (!stream_nested_finish(extension->stream)) {
    extension->next = extension_recv_type;
  }
  return kTlsSuccess;
}

// Server Name Indication

static uint16_t extension_sni_client_hello_length(EXTENSION *extension) {
  extension_clear_data(extension);
  extension->data = tls_get_sni(extension->tls);
  // SNI also includes a sub-type and sub-length
  return kExtensionOverhead + kListLengthLen + kSniTypeLen + kSniLengthLen +
         buf_size(extension->data);
}

static tls_result_t extension_sni_client_hello(EXTENSION *extension) {
  uint16_t length = extension_sni_client_hello_length(extension);
  length -= kExtensionOverhead;
  length -= kListLengthLen;
  if (!stream_send_u16(extension->stream, length)) {
    return kTlsFailure;
  }
  extension->next = extension_sni_client_hello_type;
  return kTlsSuccess;
}

static tls_result_t extension_sni_client_hello_type(EXTENSION *extension) {
  if (!stream_send_u8(extension->stream, kSniHostname)) {
    return kTlsFailure;
  }
  extension->next = extension_sni_client_hello_data;
  return kTlsSuccess;
}

static tls_result_t extension_sni_client_hello_data(EXTENSION *extension) {
  if (!stream_send_buf(extension->stream, kSniLengthLen, extension->data)) {
    return kTlsFailure;
  }
  extension->next = extension_send_finish;
  return kTlsSuccess;
}

// Maximum Fragment Length

static uint16_t extension_mfl_client_hello_length(EXTENSION *extension) {
  const TLS_CONFIG *config = tls_get_config(extension->tls);
  if (config_get_fragment_length(config) == kFragmentDefault) {
    return 0;
  }
  return kExtensionOverhead + sizeof(uint8_t);
}

static tls_result_t extension_mfl_client_hello(EXTENSION *extension) {
  const TLS_CONFIG *config = tls_get_config(extension->tls);
  size_t fragment_len = config_get_fragment_length(config);
  if (fragment_len != kFragmentDefault &&
      !stream_send_u8(extension->stream, (uint8_t)(fragment_len >> 8))) {
    return kTlsFailure;
  }
  extension->next = extension_send_finish;
  return kTlsSuccess;
}

static tls_result_t extension_mfl_server_hello(EXTENSION *extension) {
  uint8_t mfl = 0;
  if (!stream_recv_u8(extension->stream, &mfl)) {
    return kTlsFailure;
  }
  extension->next = NULL;
  const TLS_CONFIG *config = tls_get_config(extension->tls);
  if (mfl != (config_get_fragment_length(config) >> 8)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrIllegalParameter);
  }
  extension->next = extension_send_finish;
  return kTlsSuccess;
}

// Supported Elliptic Curves

static uint16_t extension_sec_client_hello_length(EXTENSION *extension) {
  extension_clear_data(extension);
  extension->data = &extension->internal;
  const TLS_CONFIG *config = tls_get_config(extension->tls);
  config_get_eccurves(config, extension->region, extension->data);
  return kExtensionOverhead + kListLengthLen + buf_size(extension->data);
}

static tls_result_t extension_sec_client_hello(EXTENSION *extension) {
  if (!stream_send_buf(extension->stream, kListLengthLen, extension->data)) {
    return kTlsFailure;
  }
  extension->next = extension_send_finish;
  return kTlsSuccess;
}

// Signature and Hash

static uint16_t extension_sah_client_hello_length(EXTENSION *extension) {
  extension_clear_data(extension);
  extension->data = &extension->internal;
  const TLS_CONFIG *config = tls_get_config(extension->tls);
  config_get_signature_algs(config, extension->region, extension->data);
  return kExtensionOverhead + kListLengthLen + buf_size(extension->data);
}

static tls_result_t extension_sah_client_hello(EXTENSION *extension) {
  if (!stream_send_buf(extension->stream, kListLengthLen, extension->data)) {
    return kTlsFailure;
  }
  extension->next = extension_send_finish;
  return kTlsSuccess;
}

// Stateless Session Tickets

static uint16_t extension_sst_client_hello_length(EXTENSION *extension) {
  extension_clear_data(extension);
  TICKET *ticket = tls_get_ticket(extension->tls);
  extension->data = ticket_data(ticket);
  size_t len = buf_size(extension->data);
  if (len != 0) {
    buf_reset(extension->data, 0);
    buf_produce(extension->data, len, NULL);
  }
  return kExtensionOverhead + buf_size(extension->data);
}

static tls_result_t extension_sst_client_hello(EXTENSION *extension) {
  if (buf_size(extension->data) != 0 &&
      !stream_send_buf(extension->stream, 0, extension->data)) {
    return kTlsFailure;
  }
  extension->next = extension_send_finish;
  return kTlsSuccess;
}
