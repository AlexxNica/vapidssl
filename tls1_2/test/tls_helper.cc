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

#include "tls1_2/test/tls_helper.h"
#include "tls1_2/tls_internal.h"

#include <stddef.h>

#include "base/platform/test/io_mock.h"
#include "base/test/scoped_buf.h"
#include "public/tls.h"
#include "tls1_2/config.h"
#include "tls1_2/tls.h"
#include "x509v3/test/truststore_helper.h"

namespace vapidssl {

namespace {

const char *kType = "TYPE";

}  // namespace

// Public Methods

TlsHelper::TlsHelper() : tls_(nullptr), hash_(nullptr), sni_("localhost") {
  SetSegments(kSegments);
  SetNesting(kRecv, kRecvNesting);
  SetNesting(kSend, kSendNesting);
  Reset();
}

const TLS_CONFIG *TlsHelper::GetConfig() {
  return config_helper_.GetConfig();
}

TLS *TlsHelper::GetTLS() {
  assert(tls_);
  return tls_;
}

STREAM *TlsHelper::GetStream(io_mock_t io, direction_t dir) {
  if (io == kIoServer) {
    return StreamHelper::GetStream(io, dir);
  } else if (io == kIoClient) {
    MESSAGE *message = tls_get_message(tls_, dir);
    return message_get_stream(message);
  } else {
    abort();
  }
}

CHUNK *TlsHelper::GetRecord(direction_t dir) {
  return (dir == kRecv ? server_rx_ : server_tx_);
}

void TlsHelper::SetSNI(const std::string &name) {
  sni_ = name;
}

void TlsHelper::SetHash(const HASH *hash) {
  hash_ = hash;
}

void TlsHelper::SetCryptoHelper(CryptoHelper &crypto_helper) {
  crypto_helper.AddHexAttribute(kType, type_, true);
  StreamHelper::SetCryptoHelper(crypto_helper);
}

// Protected Methods

size_t TlsHelper::MemorySize(io_mock_t io) {
  size_t size = 0;
  if (io == kIoClient) {
    size += TLS_size(GetConfig());
  } else {
    size += StreamHelper::MemorySize(io);
    if (hash_) {
      size += LIST_SIZE(STREAM_HASH, 1);
      size += hash_get_state_size(hash_);
    }
  }
  return size;
}

size_t TlsHelper::ChunkSize() {
  return record_size(GetConfig());
}

void TlsHelper::ResetHashes(io_mock_t io) {
  StreamHelper::ResetHashes(io);
  if (io == kIoServer && hash_) {
    // Add the selected hash to the server, so we can calculate Finished hashes
    ScopedBuf *region = GetMemory(kIoServer);
    STREAM *server_send = GetStream(kIoServer, kRecv);
    ASSERT_TRUE(stream_add_hash(server_send, region->Get(), hash_));
  }
}

void TlsHelper::ResetClient() {
  ResetMemory(kIoClient);
  ScopedBuf *region = GetMemory(kIoClient);
  EXPECT_TRUE(TLS_init(GetConfig(), region->Raw(), region->Len(), kIoClient,
                       sni_.c_str(), &tls_));
  ResetHashes(kIoClient);
}

void TlsHelper::ResetServer() {
  StreamHelper::ResetServer();
  record_type_ = kHandshake;
  ResetHashes(kIoServer);
}

void TlsHelper::ResetChunk(io_mock_t io, direction_t dir, CHUNK *out) {
  // kIoClient should be handled by |TlsHelper::ResetClient|
  assert(io == kIoServer);
  ScopedBuf *region = GetMemory(io);
  // Save handles to the records.
  if (dir == kSend) {
    server_tx_ = out;
  } else {
    server_rx_ = out;
  }
  EXPECT_TRUE(record_init(GetConfig(), region->Get(), dir, out));
}

void TlsHelper::InvokeCallback(direction_t dir, ScopedBuf &buf) {
  const std::string &label = GetLabel();
  CHUNK *record = GetRecord(dir);
  if (dir == kSend) {
    // Set the type before sending to the client.
    EXPECT_TRUE(record_set_type(record, GetType())) << "At " << label;
  }
  StreamHelper::InvokeCallback(dir, buf);
  if (dir == kRecv) {
    // Peek and check type before receiving at the server.
    STREAM *server_recv = GetStream(kIoServer, kRecv);
    EXPECT_TRUE(stream_peek(server_recv));
    EXPECT_EQ(record_get_type(record), GetType()) << "At " << label;
  }
}

// Private Methods

record_content_t TlsHelper::GetType() {
  uint32_t type = record_type_;
  if (HasAttribute(kType)) {
    buf_reset(type_.Get(), 0);
    buf_produce(type_.Get(), 1, nullptr);
    EXPECT_TRUE(buf_get_val(type_.Get(), 1, &type));
    record_type_ = (record_content_t)type;
  }
  if (hash_) {
    STREAM *server_send = GetStream(kIoServer, kSend);
    stream_set_hashing(server_send, type == kHandshake ? kOn : kOff);
    STREAM *server_recv = GetStream(kIoServer, kRecv);
    stream_set_hashing(server_recv, type == kHandshake ? kOn : kOff);
  }
  return record_type_;
}

}  // namespace vapidssl
