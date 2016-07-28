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

#include "tls1_2/handshake.h"

#include <assert.h>
#include <string.h>
#include <time.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/platform/random.h"
#include "base/platform/time.h"
#include "common/stream.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto/keyex.h"
#include "crypto/sign.h"
#include "tls1_2/ciphersuite.h"
#include "tls1_2/config.h"
#include "tls1_2/extension.h"
#include "tls1_2/message.h"
#include "tls1_2/prf.h"
#include "tls1_2/record.h"
#include "tls1_2/ticket.h"
#include "tls1_2/tls.h"
#include "x509v3/certificate.h"

// This file contains a large number of small |handshake_io_f| functions,
// grouped by specific TLS handshake messages. With the exception of the
// |handshake_client_*_begin| functions, each |handshake_f| function begins by
// receiving or sending some data, then processing the data it read or
// preparing the next data to be sent, respectively.  This allows the function
// to be called repeatedly in the event of I/O failures (e.g. when using
// non-blocking I/O). As a final step, it sets the next |handshake_f| to be
// called.  Within a message group this is always well defined; between messages
// it is according to the flow chart below.  When transitioning from one message
// to the next, the next message is actually read in one of the
// |handshake_*_finish| functions, in order to correctly handle the
// "<$next_message == ...>" decisions in the flow chart. Any errors encountered
// cause the handshake to fail; in this case the next |handshake_f| is set to
// NULL and the function returns |kTlsFailure|.
//
// Per https://tools.ietf.org/html/rfc5246#section-7.3 and
// https://tools.ietf.org/html/rfc5077#section-3.1, the allowed message
// exchanges for TLS 1.2 can be described with the flow chart below. For the
// decisions in angle brackets, the true case case proceeds to the right, while
// the false case falls through.
//
//     {{BEGIN}}
//     [send ClientHello]
//     [recv ServerHello]
//     <next_msg == NewSessionTicket>----->[resumed = true]----------v (1)
//     [recv Certificate]                                            |
//     [recv ServerKeyExchange]                                      |  (2)
//     <next_msg == CertificateRequest>--->[certreq = true] |
//     [recv ServerHelloDone]<-------------[recv CertificateRequest] |
//     <certreq>-----------------------------------------------v     |
//     [send ClientKeyExchange]<-----------[send Certificate]<-+     |  (2, 3)
// >-->[send ChangeCipherSpec]                                       |  (4)
// |   [send Finished]                  v----------------------------<
// |   <resumed>------>{{END}}          |
// |   <next_msg == NewSessionTicket>--->->[recv NewSessionTicket]---v
// |   [recv ChangeCipherSpec]<--------------------------------------<
// |   [recv Finished]
// |   <!resumed>----->{{END}}
// ^---<
//
// Notes: 1) If the client sent an empty ticket, a NewSessionTicket is an error
// 2) All supported cipher ciphersuites require Server and Client KeyExchanges.
// 3) Client authentication is FUTURE work, so the client always sends an empty
// certificate list and omit the CertificateVerify message. 4) Despite the
// apparent loop, this is a simple graph in practice since mode    cannot change
// from after this point.

// Forward decalartions
static tls_result_t handshake_keyblock_init(HANDSHAKE *handshake);
static void handshake_keyblock_cleanup(HANDSHAKE *handshake);
static tls_result_t handshake_verify(HANDSHAKE *handshake, const char *label);

// These are the possible value of |handshake->next|.  They represent the points
// at which |TLS_connect| can resume the handshake after an I/O error.

// ClientHello.
static tls_result_t handshake_client_hello_begin(HANDSHAKE *handshake);
static tls_result_t handshake_client_hello_length(HANDSHAKE *handshake);
static tls_result_t handshake_client_hello_version(HANDSHAKE *handshake);
static tls_result_t handshake_client_hello_random(HANDSHAKE *handshake);
static tls_result_t handshake_client_hello_session(HANDSHAKE *handshake);
static tls_result_t handshake_client_hello_ciphersuites(HANDSHAKE *handshake);
static tls_result_t handshake_client_hello_compression(HANDSHAKE *handshake);
static tls_result_t handshake_client_hello_extensions(HANDSHAKE *handshake);
static tls_result_t handshake_client_hello_finish(HANDSHAKE *handshake);

// ServerHello.
static tls_result_t handshake_server_hello_begin(HANDSHAKE *handshake);
static tls_result_t handshake_server_hello_version(HANDSHAKE *handshake);
static tls_result_t handshake_server_hello_random(HANDSHAKE *handshake);
static tls_result_t handshake_server_hello_session(HANDSHAKE *handshake);
static tls_result_t handshake_server_hello_ciphersuite(HANDSHAKE *handshake);
static tls_result_t handshake_server_hello_compression(HANDSHAKE *handshake);
static tls_result_t handshake_server_hello_extensions(HANDSHAKE *handshake);

// NewSessionTicket.
static tls_result_t handshake_new_session_ticket_begin(HANDSHAKE *handshake);
static tls_result_t handshake_new_session_ticket_duration(HANDSHAKE *handshake);
static tls_result_t handshake_new_session_ticket(HANDSHAKE *handshake);

// Certificate (server).
static tls_result_t handshake_server_certificate_begin(HANDSHAKE *handshake);
static tls_result_t handshake_server_certificate_chain(HANDSHAKE *handshake);
static tls_result_t handshake_server_certificate_length(HANDSHAKE *handshake);
static tls_result_t handshake_server_certificate(HANDSHAKE *handshake);

// ServerKeyExchange.
static tls_result_t handshake_server_key_exchange_begin(HANDSHAKE *handshake);
static tls_result_t handshake_server_key_exchange_type(HANDSHAKE *handshake);
static tls_result_t handshake_server_key_exchange_curve(HANDSHAKE *handshake);
static tls_result_t handshake_server_key_exchange_peer(HANDSHAKE *handshake);
static tls_result_t handshake_server_key_exchange_algs(HANDSHAKE *handshake);
static tls_result_t handshake_server_key_exchange_verify(HANDSHAKE *handshake);

// CertificateRequest.
static tls_result_t handshake_certificate_request_begin(HANDSHAKE *handshake);
static tls_result_t handshake_certificate_request_type(HANDSHAKE *handshake);
static tls_result_t handshake_certificate_request_algs(HANDSHAKE *handshake);
static tls_result_t handshake_certificate_request_name(HANDSHAKE *handshake);

// ServerHelloDone
static tls_result_t handshake_server_hello_done_begin(HANDSHAKE *handshake);
static tls_result_t handshake_server_hello_done_done(HANDSHAKE *handshake);

// Certificate (client).
static tls_result_t handshake_client_certificate_begin(HANDSHAKE *handshake);
static tls_result_t handshake_client_certificate_list(HANDSHAKE *handshake);
static tls_result_t handshake_client_certificate_finish(HANDSHAKE *handshake);

// ClientKeyExchange.
static tls_result_t handshake_client_key_exchange_begin(HANDSHAKE *handshake);
static tls_result_t handshake_client_key_exchange_length(HANDSHAKE *handshake);
static tls_result_t handshake_client_key_exchange_accept(HANDSHAKE *handshake);
static tls_result_t handshake_client_key_exchange_finish(HANDSHAKE *handshake);

// ChangeCipherSpec (client).
static tls_result_t handshake_client_ccs_begin(HANDSHAKE *handshake);
static tls_result_t handshake_client_ccs(HANDSHAKE *handshake);

// Finished (client).
static tls_result_t handshake_client_finished_begin(HANDSHAKE *handshake);
static tls_result_t handshake_client_finished_digest(HANDSHAKE *handshake);
static tls_result_t handshake_client_finished_finish(HANDSHAKE *handshake);

// ChangeCipherSpec (server).
static tls_result_t handshake_server_ccs_begin(HANDSHAKE *handshake);
static tls_result_t handshake_server_ccs(HANDSHAKE *handshake);
static tls_result_t handshake_server_finished_begin(HANDSHAKE *handshake);

// Finished (server).
static tls_result_t handshake_server_finished(HANDSHAKE *handshake);

enum compression_t {
  kNullCompression = 0,
};

enum eccurve_type_t {
  kNamedCurve = 3,
};

static const uint8_t kRandomSize = 32;
static const uint8_t kSessionLengthLen = 1;
static const uint8_t kSessionMaxSize = 32;
static const uint8_t kKeyexLen = 1;
static const uint8_t kCiphersuitesLengthLen = 2;
static const uint8_t kCompressionLen = 1;
static const uint8_t kSignatureLen = 2;

static const char *kPrfMasterSecret = "master secret";
static const char *kPrfKeyExpansion = "key expansion";
static const char *kPrfClientFinished = "client finished";
static const char *kPrfServerFinished = "server finished";

// Library routines

size_t handshake_size(const TLS_CONFIG *config) {
  assert(config);
  // We need a whole bunch of values that depend on the individual
  // configuration.  Examine what is enabled by |config| and collect those
  // values.
  size_t size = 0;
  size_t max_name_len = config_get_max_name_length(config);
  size_t max_key_len = config_get_max_key_length(config);
  // Hash related values.
  const HASH *hash = NULL;
  size_t max_hash_state_size = 0;
  // Iterate over all enabled ciphersuites.
  for (tls_ciphersuite_t ciphersuite = ciphersuite_next(config, kCryptoAny);
       ciphersuite != kCryptoAny;
       ciphersuite = ciphersuite_next(config, ciphersuite)) {
    hash = ciphersuite_get_hash(ciphersuite);
    size = hash_get_state_size(hash);
    if (size > max_hash_state_size) {
      max_hash_state_size = size;
    }
  }
  // The randoms and selected hash are kept throughout
  size = kRandomSize * 2;
  size += LIST_SIZE(STREAM_HASH, VAPIDSSL_HASHES + 1);
  size += max_hash_state_size;
  // The "high water" mark in terms of memory should be the certificate chain
  // parsing, given the currently supported values.
  // TODO(aarongreen): Revisit when we add ECDSA or similar and the public keys
  // shrink a lot.
  size += max_key_len;
  size += sizeof(CERTIFICATE);
  size += certificate_size(max_name_len, max_key_len);
  return size;
}

tls_result_t handshake_init(BUF *region, TLS *tls, HANDSHAKE *out) {
  assert(region);
  assert(tls);
  assert(out);
  memset(out, 0, sizeof(*out));
  out->region = region;
  out->tls = tls;
  // Preallocate memory for the client and server's random numbers.
  if (!buf_malloc(region, kRandomSize, &out->client_random) ||
      !buf_malloc(region, kRandomSize, &out->server_random)) {
    return kTlsFailure;
  }
  // Set up hashes on the streams.  The hashes are shared, so
  // |stream_add_hashes|, etc. only needs to be called once.
  if (!LIST_NEW(STREAM_HASH, region, VAPIDSSL_HASHES + 1, &out->hashes)) {
    return kTlsFailure;
  }
  STREAM *rx = tls_get_stream(tls, kRecv);
  stream_set_hashes(rx, &out->hashes);
  if (!stream_add_hashes(rx, region)) {
    return kTlsFailure;
  }
  STREAM *tx = tls_get_stream(tls, kSend);
  stream_set_hashes(tx, &out->hashes);
  // Prepare the extensions
  extension_init(region, tls, &out->extension);
  return kTlsSuccess;
}

tls_result_t handshake_connect(HANDSHAKE *handshake) {
  assert(handshake);
  if (!handshake->next) {
    handshake->next = handshake_client_hello_begin;
  }
  while (handshake->next) {
    if (!handshake->next(handshake)) {
      // TODO(aarongreen): If the error is non-recoverable, we should erase the
      // ticket.
      return kTlsFailure;
    }
  }
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  stream_final_digest(rx, NULL);
  stream_set_hashes(rx, NULL);
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  stream_set_hashes(tx, NULL);
  return kTlsSuccess;
}

// Static functions

static tls_result_t handshake_keyblock_init(HANDSHAKE *handshake) {
  assert(buf_size(&handshake->client_write_key) == 0);
  assert(buf_size(&handshake->server_write_key) == 0);
  assert(buf_size(&handshake->client_write_iv) == 0);
  assert(buf_size(&handshake->server_write_iv) == 0);
  // Allocate keyblock memory.  Per
  // https://tools.ietf.org/html/rfc5246#section-6.3, the keyblock layout is:
  //    client write key
  //    server write key
  //    client write iv
  //    server write iv
  tls_ciphersuite_t ciphersuite = tls_get_ciphersuite(handshake->tls);
  const AEAD *aead = ciphersuite_get_aead(ciphersuite);
  size_t key_len = aead_get_key_size(aead);
  size_t iv_len = ciphersuite_fix_nonce_length(ciphersuite);
  BUF *keyblock = &handshake->message_buf1;
  if (!buf_malloc(handshake->region, (key_len + iv_len) * 2, keyblock)) {
    return kTlsFailure;
  }
  // Allocate the key and (fixed) IV buffers from the keyblock.
  if (!buf_malloc(keyblock, key_len, &handshake->client_write_key) ||
      !buf_malloc(keyblock, key_len, &handshake->server_write_key) ||
      !buf_malloc(keyblock, iv_len, &handshake->client_write_iv) ||
      !buf_malloc(keyblock, iv_len, &handshake->server_write_iv)) {
    return kTlsFailure;
  }
  // Generate the keyblock data.
  const HASH *hash = ciphersuite_get_hash(ciphersuite);
  BUF *master = tls_get_master_secret(handshake->tls);
  if (!prf(handshake->region, hash, master, kPrfKeyExpansion,
           &handshake->server_random, &handshake->client_random, keyblock)) {
    return kTlsFailure;
  }
  buf_produce(&handshake->client_write_key, key_len, NULL);
  buf_produce(&handshake->client_write_iv, iv_len, NULL);
  buf_produce(&handshake->server_write_key, key_len, NULL);
  buf_produce(&handshake->server_write_iv, iv_len, NULL);
  return kTlsSuccess;
}

static void handshake_keyblock_cleanup(HANDSHAKE *handshake) {
  BUF *keyblock = &handshake->message_buf1;
  buf_free(&handshake->server_write_iv);
  buf_free(&handshake->client_write_iv);
  buf_free(&handshake->server_write_key);
  buf_free(&handshake->client_write_key);
  buf_free(keyblock);
}

static tls_result_t handshake_verify(HANDSHAKE *handshake, const char *label) {
  tls_ciphersuite_t ciphersuite = tls_get_ciphersuite(handshake->tls);
  // Set up the output buffer.
  BUF *verify = &handshake->message_buf2;
  size_t verify_len = ciphersuite_get_verify_length(ciphersuite);
  if (!buf_malloc(handshake->region, verify_len, verify)) {
    return kTlsFailure;
  }
  // Set up the digest buffer.
  const HASH *hash = ciphersuite_get_hash(ciphersuite);
  size_t digest_len = hash_get_output_size(hash);
  BUF digest = buf_init();
  if (!buf_malloc(handshake->region, digest_len, &digest)) {
    return kTlsFailure;
  }
  // The streams share the hashes, so either will do here.
  STREAM *stream = tls_get_stream(handshake->tls, kRecv);
  // Don't finalize the stream hash until the verify memory all gets freed.
  if (!stream_clone_digest(stream, handshake->region, &digest)) {
    return kTlsFailure;
  }
  BUF *master = tls_get_master_secret(handshake->tls);
  if (!prf(handshake->region, hash, master, label, &digest, NULL, verify)) {
    return kTlsFailure;
  }
  buf_free(&digest);
  return kTlsSuccess;
}

// Client Hello

static tls_result_t handshake_client_hello_begin(HANDSHAKE *handshake) {
  handshake->next = NULL;
  // Get the ciphersuites, and save them for later.
  BUF *ciphersuites = &handshake->message_buf1;
  const TLS_CONFIG *config = tls_get_config(handshake->tls);
  tls_ciphersuite_t resumed = tls_get_ciphersuite(handshake->tls);
  if (!config_get_ciphersuites(config, handshake->region, resumed,
                               ciphersuites)) {
    return kTlsFailure;
  }
  // Calculate the length of our next message.
  handshake->message_len = kVersionLen;              // Version
  handshake->message_len += kRandomSize;             // Client random.
  handshake->message_len += sizeof(uint8_t);         // Session ID length (=0).
  handshake->message_len += kCiphersuitesLengthLen;  // Suites.
  handshake->message_len += buf_size(ciphersuites);  // Suites.
  handshake->message_len += kCompressionLen;         // Comp. length (=1).
  handshake->message_len += sizeof(uint8_t);         // Comp. value (=null).
  handshake->message_len += sizeof(uint16_t);        // Extensions
  handshake->message_len += extension_length(&handshake->extension);
  handshake->next = handshake_client_hello_length;
  return kTlsSuccess;
}

static tls_result_t handshake_client_hello_length(HANDSHAKE *handshake) {
  MESSAGE *tx = tls_get_message(handshake->tls, kSend);
  if (!message_send_handshake(tx, kClientHello, handshake->message_len)) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_hello_version;
  return kTlsSuccess;
}

static tls_result_t handshake_client_hello_version(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  if (!stream_send_u16(tx, kTlsVersion1_2)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  buf_reset(&handshake->client_random, 0);
  random_buf(&handshake->client_random);
  handshake->next = handshake_client_hello_random;
  return kTlsSuccess;
}

static tls_result_t handshake_client_hello_random(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  if (!stream_send_buf(tx, 0, &handshake->client_random)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  buf_reset(&handshake->client_random, 0);
  buf_produce(&handshake->client_random, kRandomSize, NULL);
  handshake->next = handshake_client_hello_session;
  return kTlsSuccess;
}

static tls_result_t handshake_client_hello_session(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  // Per https://tools.ietf.org/html/rfc4507#section-3.4, we omit the session
  // ID.  We use session tickets instead, and differentiate the flow based on
  // the server message received.
  if (!stream_send_u8(tx, 0)) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_hello_ciphersuites;
  return kTlsSuccess;
}

static tls_result_t handshake_client_hello_ciphersuites(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  BUF *ciphersuites = &handshake->message_buf1;
  BUF *compression = &handshake->message_buf2;
  if (!stream_send_buf(tx, kCiphersuitesLengthLen, ciphersuites)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  buf_free(ciphersuites);
  if (!buf_malloc(handshake->region, 1, compression)) {
    return kTlsFailure;
  }
  buf_put_val(compression, 1, kNullCompression);
  handshake->next = handshake_client_hello_compression;
  return kTlsSuccess;
}

static tls_result_t handshake_client_hello_compression(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  BUF *compression = &handshake->message_buf2;
  if (!stream_send_buf(tx, kCompressionLen, compression)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  buf_free(compression);
  handshake->next = handshake_client_hello_extensions;
  return kTlsSuccess;
}

static tls_result_t handshake_client_hello_extensions(HANDSHAKE *handshake) {
  if (!extension_send(&handshake->extension)) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_hello_finish;
  return kTlsSuccess;
}

static tls_result_t handshake_client_hello_finish(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  if (!stream_flush(tx)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_hello_begin;
  return kTlsSuccess;
}

// ServerHello
static tls_result_t handshake_server_hello_begin(HANDSHAKE *handshake) {
  MESSAGE *rx = tls_get_message(handshake->tls, kRecv);
  message_handshake_t type;
  if (!message_recv_handshake(rx, &type)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (type != kServerHello) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
  }
  handshake->next = handshake_server_hello_version;
  return kTlsSuccess;
}

static tls_result_t handshake_server_hello_version(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  uint16_t version = 0;
  if (!stream_recv_u16(rx, &version)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (version != kTlsVersion1_2) {
    return ERROR_SET(kTlsErrVapid, kTlsErrProtocolVersion);
  }
  handshake->next = handshake_server_hello_random;
  return kTlsSuccess;
}

static tls_result_t handshake_server_hello_random(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  if (!stream_recv_buf(rx, NULL, 0, &handshake->server_random)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_hello_session;
  return kTlsSuccess;
}

static tls_result_t handshake_server_hello_session(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  BUF *session = &handshake->message_buf2;
  if (!stream_recv_buf(rx, handshake->region, kSessionLengthLen, session)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (buf_ready(session) > kSessionMaxSize) {
    return ERROR_SET(kTlsErrVapid, kTlsErrDecodeError);
  }
  // Zero-length is allowed.
  if (buf_size(session) != 0) {
    buf_free(session);
  }
  handshake->next = handshake_server_hello_ciphersuite;
  return kTlsSuccess;
}

static tls_result_t handshake_server_hello_ciphersuite(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  uint16_t value = 0;
  if (!stream_recv_u16(rx, &value)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  tls_ciphersuite_t ciphersuite = (tls_ciphersuite_t)value;
  const TLS_CONFIG *config = tls_get_config(handshake->tls);
  if (!config_has_ciphersuite(config, ciphersuite)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrIllegalParameter);
  }
  tls_set_ciphersuite(handshake->tls, ciphersuite);
  const HASH *hash = ciphersuite_get_hash(ciphersuite);
  if (!stream_select_hash(rx, hash)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_hello_compression;
  return kTlsSuccess;
}

static tls_result_t handshake_server_hello_compression(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  uint8_t compression = 0;
  if (!stream_recv_u8(rx, &compression)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (compression != kNullCompression) {
    return ERROR_SET(kTlsErrVapid, kTlsErrIllegalParameter);
  }
  handshake->next = handshake_server_hello_extensions;
  return kTlsSuccess;
}

static tls_result_t handshake_server_hello_extensions(HANDSHAKE *handshake) {
  if (!extension_recv(&handshake->extension)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  // Assume we're resuming unless we see a Certificate message.
  if (extension_echoed(&handshake->extension, kExtStatelessSessionTicket)) {
    handshake->resumed = kTrue;
    handshake->next = handshake_new_session_ticket_begin;
  } else {
    handshake->resumed = kFalse;
    handshake->next = handshake_server_certificate_begin;
  }
  return kTlsSuccess;
}

static tls_result_t handshake_new_session_ticket_begin(HANDSHAKE *handshake) {
  MESSAGE *rx = tls_get_message(handshake->tls, kRecv);
  message_handshake_t type;
  if (!message_recv_handshake(rx, &type)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  // We don't know if we're resuming until we see the server's response.  If we
  // actually read the start of a Certificate message, we join that flow at the
  // start of the certificate chain processing.
  if (type == kNewSessionTicket) {
    handshake->next = handshake_new_session_ticket_duration;
  } else if (type == kCertificate) {
    handshake->resumed = kFalse;
    handshake->next = handshake_server_certificate_chain;
  } else {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
  }
  return kTlsSuccess;
}

// NewSessionTicket
static tls_result_t handshake_new_session_ticket_duration(
    HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  uint32_t duration = 0;
  if (!stream_recv_u32(rx, &duration)) {
    return kTlsFailure;
  }
  TICKET *ticket = tls_get_ticket(handshake->tls);
  ticket_renew(ticket, duration);
  handshake->next = handshake_new_session_ticket;
  return kTlsSuccess;
}

static tls_result_t handshake_new_session_ticket(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  TICKET *ticket = tls_get_ticket(handshake->tls);
  BUF *data = ticket_data(ticket);
  BUF *region = tls_get_region(handshake->tls);
  if (!stream_recv_buf(rx, region, sizeof(uint16_t), data)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_ccs_begin;
  return kTlsSuccess;
}

// Certificate (server).
static tls_result_t handshake_server_certificate_begin(HANDSHAKE *handshake) {
  MESSAGE *rx = tls_get_message(handshake->tls, kRecv);
  message_handshake_t type;
  if (!message_recv_handshake(rx, &type)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (type != kCertificate) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
  }
  handshake->next = handshake_server_certificate_chain;
  return kTlsSuccess;
}

static tls_result_t handshake_server_certificate_chain(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  uint24_t chain_len = 0;
  if (!stream_recv_u24(rx, &chain_len)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  const TLS_CONFIG *config = tls_get_config(handshake->tls);
  size_t key_len = config_get_max_key_length(config);
  if (!buf_malloc(handshake->region, key_len, &handshake->leaf_key) ||
      !buf_malloc(handshake->region, sizeof(CERTIFICATE),
                  &handshake->message_buf1)) {
    return kTlsFailure;
  }
  CERTIFICATE *chain = BUF_AS(CERTIFICATE, &handshake->message_buf1);
  size_t name_len = config_get_max_name_length(config);
  if (!certificate_init(handshake->region, name_len, &handshake->leaf_key,
                        chain)) {
    return kTlsFailure;
  }
  // Set stream.
  certificate_set_stream(rx, chain);
  // Set server name indication.
  BUF *sni = tls_get_sni(handshake->tls);
  certificate_set_name(sni, chain);
  // Set the trusted CA certificate store.
  const LIST *truststore = config_get_truststore(config);
  certificate_set_trust(truststore, chain);
  // Matches [1] in |handshake_server_certificate_finish|.
  if (!stream_nested_begin(rx, chain_len)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_certificate_length;
  return kTlsSuccess;
}

static tls_result_t handshake_server_certificate_length(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  uint24_t certificate_len = 0;
  if (!stream_recv_u24(rx, &certificate_len)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  // Matches [0] in |handshake_server_certificate_finish|.
  if (!stream_nested_begin(rx, certificate_len)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_certificate;
  return kTlsSuccess;
}

static tls_result_t handshake_server_certificate(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  CERTIFICATE *chain = BUF_AS(CERTIFICATE, &handshake->message_buf1);
  if (!certificate_recv(chain)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (!stream_nested_finish(rx)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrLengthMismatch);
  }
  // Are there more certificates to process?
  if (!stream_nested_finish(rx)) {
    handshake->next = handshake_server_certificate_length;
    return kTlsSuccess;
  }
  // Is the completed chain trusted?
  if (!certificate_is_trusted(chain)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrBadCertificate);
  }
  certificate_cleanup(chain);
  buf_free(&handshake->message_buf1);
  handshake->next = handshake_server_key_exchange_begin;
  return kTlsSuccess;
}

// ServerKeyExchange: required as all ciphers are authenticated ECDHE. */
static tls_result_t handshake_server_key_exchange_begin(HANDSHAKE *handshake) {
  MESSAGE *rx = tls_get_message(handshake->tls, kRecv);
  message_handshake_t type;
  if (!message_recv_handshake(rx, &type)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (type != kServerKeyExchange) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
  }
  handshake->next = handshake_server_key_exchange_type;
  return kTlsSuccess;
}

static tls_result_t handshake_server_key_exchange_type(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  uint8_t type = 0;
  if (!stream_recv_u8(rx, &type)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (type != kNamedCurve) {
    return ERROR_SET(kTlsErrVapid, kTlsErrIllegalParameter);
  }
  handshake->next = handshake_server_key_exchange_curve;
  return kTlsSuccess;
}

static tls_result_t handshake_server_key_exchange_curve(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  if (!stream_recv_u16(rx, &handshake->curve)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  const TLS_CONFIG *config = tls_get_config(handshake->tls);
  if (!config_has_eccurve(config, handshake->curve)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrIllegalParameter);
  }
  handshake->next = handshake_server_key_exchange_peer;
  return kTlsSuccess;
}

static tls_result_t handshake_server_key_exchange_peer(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  if (!stream_recv_buf(rx, handshake->region, kKeyexLen, &handshake->offer)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (buf_size(&handshake->offer) == 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrIllegalParameter);
  }
  handshake->next = handshake_server_key_exchange_algs;
  return kTlsSuccess;
}

static tls_result_t handshake_server_key_exchange_algs(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  uint16_t algs = 0;
  // Grab the hash and signature algorithms together.
  if (!stream_recv_u16(rx, &algs)) {
    return kTlsFailure;
  }
  // Is the key exchange signed by an algorithm we offered?
  const TLS_CONFIG *config = tls_get_config(handshake->tls);
  if (!config_has_signature_alg(config, algs)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrIllegalParameter);
  }
  // Get the specified algorithms, and save the signature algorithm.
  const HASH *hash = hash_find(algs >> 8);
  handshake->sign = sign_find(algs & 0xFF, algs >> 8);
  if (!hash || !handshake->sign) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnsupportedAlgorithm);
  }
  // Prepare the key exchange digest.
  BUF data = buf_init();
  BUF state = buf_init();
  BUF *digest = &handshake->message_buf2;
  size_t data_size = sizeof(uint8_t) + sizeof(uint16_t) + kKeyexLen;
  size_t state_size = hash_get_state_size(hash);
  size_t output_size = hash_get_output_size(hash);
  if (!buf_malloc(handshake->region, output_size, digest) ||
      !buf_malloc(handshake->region, state_size, &state) ||
      !buf_malloc(handshake->region, data_size, &data)) {
    return kTlsFailure;
  }
  // Recreate seen data.
  buf_put_val(&data, sizeof(uint8_t), kNamedCurve);
  buf_put_val(&data, sizeof(uint16_t), handshake->curve);
  buf_put_val(&data, kKeyexLen, buf_size(&handshake->offer));
  // Take the digest.
  hash_init(hash, &state);
  hash_update(hash, &state, &handshake->client_random);
  hash_update(hash, &state, &handshake->server_random);
  hash_update(hash, &state, &data);
  hash_update(hash, &state, &handshake->offer);
  hash_final(hash, &state, digest);
  // Clean up a bit.
  buf_free(&data);
  buf_free(&state);
  handshake->next = handshake_server_key_exchange_verify;
  return kTlsSuccess;
}

static tls_result_t handshake_server_key_exchange_verify(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  BUF *signature = &handshake->message_buf1;
  if (!stream_recv_buf(rx, handshake->region, kSignatureLen, signature)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (buf_size(signature) == 0) {
    return ERROR_SET(kTlsErrVapid, kTlsErrIllegalParameter);
  }
  BUF *digest = &handshake->message_buf2;
  if (!sign_verify(handshake->sign, digest, signature, &handshake->leaf_key)) {
    return kTlsFailure;
  }
  buf_free(signature);
  buf_free(digest);
  // To free |leaf_key|, we have to slide the server's |offer| in front of it.
  size_t peer_size = buf_size(&handshake->offer);
  buf_merge(&handshake->leaf_key, &handshake->offer);
  buf_recycle(&handshake->offer);
  buf_split(&handshake->offer, peer_size, &handshake->leaf_key);
  buf_free(&handshake->leaf_key);
  handshake->next = handshake_certificate_request_begin;
  return kTlsSuccess;
}

// CertificateRequest: client certificates are FUTURE work, but we validate the
// structure of the request.
static tls_result_t handshake_certificate_request_begin(HANDSHAKE *handshake) {
  MESSAGE *rx = tls_get_message(handshake->tls, kRecv);
  message_handshake_t type;
  if (!message_recv_handshake(rx, &type)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (type == kCertificateRequest) {
    handshake->certreq = 1;
    handshake->next = handshake_certificate_request_type;
  } else if (type == kServerHelloDone) {
    handshake->next = handshake_server_hello_done_done;
  } else {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
  }
  return kTlsSuccess;
}

static tls_result_t handshake_certificate_request_type(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  if (!stream_recv_buf(rx, NULL, 1, NULL)) {
    return kTlsFailure;
  }
  handshake->next = handshake_certificate_request_algs;
  return kTlsSuccess;
}

static tls_result_t handshake_certificate_request_algs(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  if (!stream_recv_buf(rx, NULL, 2, NULL)) {
    return kTlsFailure;
  }
  handshake->next = handshake_certificate_request_name;
  return kTlsSuccess;
}

static tls_result_t handshake_certificate_request_name(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  if (!stream_recv_buf(rx, NULL, 2, NULL)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_hello_done_begin;
  return kTlsSuccess;
}

// ServerHelloDone.
static tls_result_t handshake_server_hello_done_begin(HANDSHAKE *handshake) {
  MESSAGE *rx = tls_get_message(handshake->tls, kRecv);
  message_handshake_t type;
  if (!message_recv_handshake(rx, &type)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (type != kServerHelloDone) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
  }
  handshake->next = handshake_server_hello_done_done;
  return kTlsSuccess;
}

static tls_result_t handshake_server_hello_done_done(HANDSHAKE *handshake) {
  if (handshake->certreq) {
    handshake->next = handshake_client_certificate_begin;
  } else {
    handshake->next = handshake_client_key_exchange_begin;
  }
  return kTlsSuccess;
}

// Certificate (Client): client certificates are FUTURE work, but send an empty
// cert list if requested.
static tls_result_t handshake_client_certificate_begin(HANDSHAKE *handshake) {
  MESSAGE *tx = tls_get_message(handshake->tls, kSend);
  if (!message_send_handshake(tx, kCertificate, 3)) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_certificate_list;
  return kTlsSuccess;
}

static tls_result_t handshake_client_certificate_list(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  if (!stream_send_u24(tx, 0)) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_certificate_finish;
  return kTlsSuccess;
}

static tls_result_t handshake_client_certificate_finish(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  if (!stream_flush(tx)) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_key_exchange_begin;
  return kTlsSuccess;
}

// ClientKeyExchange: We always use ECDHE_*.
static tls_result_t handshake_client_key_exchange_begin(HANDSHAKE *handshake) {
  tls_ciphersuite_t ciphersuite = tls_get_ciphersuite(handshake->tls);
  const KEYEX *keyex = ciphersuite_get_keyex(ciphersuite, handshake->curve);
  handshake->message_len = kKeyexLen + keyex_get_accept_size(keyex);
  handshake->next = handshake_client_key_exchange_length;
  return kTlsSuccess;
}

static tls_result_t handshake_client_key_exchange_length(HANDSHAKE *handshake) {
  MESSAGE *tx = tls_get_message(handshake->tls, kSend);
  if (!message_send_handshake(tx, kClientKeyExchange, handshake->message_len)) {
    return kTlsFailure;
  }

  handshake->next = NULL;
  tls_ciphersuite_t ciphersuite = tls_get_ciphersuite(handshake->tls);
  const KEYEX *keyex = ciphersuite_get_keyex(ciphersuite, handshake->curve);
  // Prepare a buffer to hold the acceptance to send to the server.
  BUF *acceptance = &handshake->message_buf1;
  size_t acceptance_size = keyex_get_accept_size(keyex);
  if (!buf_malloc(handshake->region, acceptance_size, acceptance)) {
    return kTlsFailure;
  }
  // Prepare a buffer for the shared, premaster secret.
  BUF *output = &handshake->message_buf2;
  size_t output_size = keyex_get_output_size(keyex);
  if (!buf_malloc(handshake->region, output_size, output)) {
    return kTlsFailure;
  }
  // Accept the server's key exchange offer.
  if (!keyex_accept(keyex, handshake->region, &handshake->offer, acceptance,
                    output)) {
    return kTlsFailure;
  }


  handshake->next = handshake_client_key_exchange_accept;
  return kTlsSuccess;
}

static tls_result_t handshake_client_key_exchange_accept(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  BUF *acceptance = &handshake->message_buf1;
  if (!stream_send_buf(tx, kKeyexLen, acceptance)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  // Generate the master secret
  tls_ciphersuite_t ciphersuite = tls_get_ciphersuite(handshake->tls);
  const HASH *hash = ciphersuite_get_hash(ciphersuite);
  BUF *output = &handshake->message_buf2;
  BUF *master = tls_get_master_secret(handshake->tls);
  buf_reset(master, 0);
  if (!prf(handshake->region, hash, output, kPrfMasterSecret,
           &handshake->client_random, &handshake->server_random, master)) {
    return kTlsFailure;
  }
  buf_free(output);
  buf_free(acceptance);
  buf_free(&handshake->offer);
  handshake->next = handshake_client_key_exchange_finish;
  return kTlsSuccess;
}

static tls_result_t handshake_client_key_exchange_finish(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  if (!stream_flush(tx)) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_ccs_begin;
  return kTlsSuccess;
}

// ChangeCipherSpec (Client)
static tls_result_t handshake_client_ccs_begin(HANDSHAKE *handshake) {
  handshake->next = NULL;
  if (!handshake->resumed && !handshake_keyblock_init(handshake)) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_ccs;
  return kTlsSuccess;
}

static tls_result_t handshake_client_ccs(HANDSHAKE *handshake) {
  MESSAGE *tx = tls_get_message(handshake->tls, kSend);
  tls_ciphersuite_t ciphersuite = tls_get_ciphersuite(handshake->tls);
  BUF *aead_states = tls_get_aead_states(handshake->tls);
  if (!message_send_ccs(tx, aead_states, ciphersuite,
                        &handshake->client_write_key,
                        &handshake->client_write_iv)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (handshake->resumed) {
    handshake_keyblock_cleanup(handshake);
  }
  if (!handshake_verify(handshake, kPrfClientFinished)) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_finished_begin;
  return kTlsSuccess;
}

// Finished (Client)
static tls_result_t handshake_client_finished_begin(HANDSHAKE *handshake) {
  MESSAGE *tx = tls_get_message(handshake->tls, kSend);
  BUF *client_verify = &handshake->message_buf2;
  if (!message_send_handshake(tx, kFinished, buf_size(client_verify))) {
    return kTlsFailure;
  }
  handshake->next = handshake_client_finished_digest;
  return kTlsSuccess;
}

static tls_result_t handshake_client_finished_digest(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  BUF *client_verify = &handshake->message_buf2;
  if (!stream_send_buf(tx, 0, client_verify)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  buf_free(client_verify);
  if (!handshake->resumed) {
    handshake->next = handshake_client_finished_finish;
  }
  // 1st of 2 possible state machine exits.
  return kTlsSuccess;
}

static tls_result_t handshake_client_finished_finish(HANDSHAKE *handshake) {
  STREAM *tx = tls_get_stream(handshake->tls, kSend);
  MESSAGE *rx = tls_get_message(handshake->tls, kRecv);
  record_content_t type;
  if (!stream_flush(tx) || !message_peek_type(rx, &type)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (type == kChangeCipherSpec) {
    handshake->next = handshake_server_ccs_begin;
  } else if (type == kHandshake && !handshake->resumed) {
    handshake->next = handshake_new_session_ticket_begin;
  } else {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
  }
  return kTlsSuccess;
}

// ChangeCipherSpec (Server)
static tls_result_t handshake_server_ccs_begin(HANDSHAKE *handshake) {
  handshake->next = NULL;
  if (handshake->resumed && !handshake_keyblock_init(handshake)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_ccs;
  return kTlsSuccess;
}

static tls_result_t handshake_server_ccs(HANDSHAKE *handshake) {
  MESSAGE *rx = tls_get_message(handshake->tls, kRecv);
  tls_ciphersuite_t ciphersuite = tls_get_ciphersuite(handshake->tls);
  BUF *aead_states = tls_get_aead_states(handshake->tls);
  if (!message_recv_ccs(rx, aead_states, ciphersuite,
                        &handshake->server_write_key,
                        &handshake->server_write_iv)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  // We can now release the keyblock
  if (!handshake->resumed) {
    handshake_keyblock_cleanup(handshake);
  }
  if (!handshake_verify(handshake, kPrfServerFinished)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_finished_begin;
  return kTlsSuccess;
}

static tls_result_t handshake_server_finished_begin(HANDSHAKE *handshake) {
  MESSAGE *rx = tls_get_message(handshake->tls, kRecv);
  message_handshake_t type;
  if (!message_recv_handshake(rx, &type)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  if (type != kFinished) {
    return ERROR_SET(kTlsErrVapid, kTlsErrUnexpectedMessage);
  }
  BUF *server_verify = &handshake->message_buf1;
  BUF *client_verify = &handshake->message_buf2;
  if (!buf_malloc(handshake->region, buf_size(client_verify), server_verify)) {
    return kTlsFailure;
  }
  handshake->next = handshake_server_finished;
  return kTlsSuccess;
}

// Finished (Server)
static tls_result_t handshake_server_finished(HANDSHAKE *handshake) {
  STREAM *rx = tls_get_stream(handshake->tls, kRecv);
  BUF *server_verify = &handshake->message_buf1;
  if (!stream_recv_buf(rx, NULL, 0, server_verify)) {
    return kTlsFailure;
  }
  handshake->next = NULL;
  BUF *client_verify = &handshake->message_buf2;
  if (!buf_equal(client_verify, server_verify)) {
    return ERROR_SET(kTlsErrVapid, kTlsErrDecryptError);
  }
  buf_free(server_verify);
  buf_free(client_verify);
  if (handshake->resumed) {
    handshake->next = handshake_client_ccs_begin;
  }
  // 2nd of 2 possible state machine exits.
  return kTlsSuccess;
}
