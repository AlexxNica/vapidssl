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

#ifndef VAPIDSSL_TLS1_2_TEST_TLS_HELPER_H
#define VAPIDSSL_TLS1_2_TEST_TLS_HELPER_H

#include "common/test/stream_helper.h"

#include <stddef.h>
#include <string>

#include "base/test/scoped_buf.h"
#include "base/types.h"
#include "public/tls.h"
#include "tls1_2/config.h"
#include "tls1_2/message.h"
#include "tls1_2/test/config_helper.h"

namespace vapidssl {

// TlsHelper extends StreamHelper to provide a convenient abstraction for
// creating and using TLS connections in unit testing.  As in the base class, a
// test data file provides expected output from the client, input from the
// server, and callback points for when the server input must be derived
// algorithmically.
class TlsHelper : public StreamHelper {
 public:
  TlsHelper();
  virtual ~TlsHelper() = default;
  TlsHelper &operator=(const TlsHelper &) = delete;
  TlsHelper(const TlsHelper &) = delete;

  virtual TLS *GetTLS(void);

  // GetConfig returns the TLS configuration object.
  virtual const TLS_CONFIG *GetConfig();

  // GetStream returns either client's or server's sending or receiving stream,
  // depending on the values of |io| and |direction|.
  STREAM *GetStream(io_mock_t io, direction_t direction) override;

  // GetMessage returns the client's sending or receiving record layer,
  // depending on |direction|.
  virtual CHUNK *GetRecord(direction_t direction);

  // SetSNI sets the server name indication to send in a ClientHello.  |name|
  // will also be used to validate the leaf certificate returned by the server.
  virtual void SetSNI(const std::string &name);

  // SetHash sets the hash algorithm the server will end up selecting as part of
  // the handshake.  This allows the helper to calculate the stream hash without
  // the typical fussiness of maintaining multiple rolling hashes until the
  // Hello messages have been exchanged.
  virtual void SetHash(const HASH *hash);

  // SetCryptoHelper sets the |crypto_helper_| to be used to emulate server
  // using a test data file.  Data sent by the client will be compared against
  // what is expected, and data will be taken from the file to generate the
  // server's responses.
  void SetCryptoHelper(CryptoHelper &crypto_helper) override;

 protected:
  // MemorySize returns the amount of memory needed for the endpoint given by
  // |io|.
  size_t MemorySize(io_mock_t io) override;

  // ChunkSize returns the maximum amount of I/O data sent as one chunk.
  size_t ChunkSize() override;

  // ResetHashes reallocates memory for tracking hashes and adds the hashes to
  // the appropriate streams.
  void ResetHashes(io_mock_t io) override;

  // ResetClient resets the streams associated with the |client_| endpoint.
  void ResetClient() override;

  // ResetServer resets the streams associated with the |server_| endpoint.
  void ResetServer() override;

  // ResetStream reinitializes |out| as the chunk for a stream for the flow
  // given by |io| and |direction|.
  void ResetChunk(io_mock_t io, direction_t dir, CHUNK *out) override;

  // InvokeCallback checks if there are any callbacks registed for the current
  // label returned by |GetLabel|, and if so, calls them with the given
  // direction |dir| and data |buf|.
  void InvokeCallback(direction_t dir, ScopedBuf &buf) override;

 private:
  // GetType returns the expected record type.
  record_content_t GetType();

  // tls_ is the TLS connection object.
  TLS *tls_;
  // hash_ is the server-selected handshake hash algorithm.
  const HASH *hash_;
  // server_tx_ is a handle to the server's sending stream chunk.
  CHUNK *server_tx_;
  // server_tx_ is a handle to the server's receiving stream chunk.
  CHUNK *server_rx_;
  // config_helper_ manages the TLS configuration object.
  ConfigHelper config_helper_;
  // type_ holds the expected record type.
  ScopedBuf type_;
  // record_type_ holds the observed record type.
  record_content_t record_type_;
  // sni_ is the server name indication for this connection.
  std::string sni_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_TLS1_2_TEST_TLS_HELPER_H
