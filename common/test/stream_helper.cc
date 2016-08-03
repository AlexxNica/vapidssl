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

#include "common/test/stream_helper.h"

#include <stddef.h>

#include "base/platform/test/io_mock.h"
#include "base/test/scoped_buf.h"
#include "base/types.h"
#include "common/chunk.h"
#include "crypto/hash.h"
#include "crypto/test/hash_test.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

namespace {

const char *kLabel = "LABEL";
const char *kServer = "SERVER";
const char *kClient = "CLIENT";
const char *kErrorSource = "SOURCE";
const char *kErrorReason = "REASON";
const char *kRevert = "REVERT";
const char *kSnapshot = "SNAPSHOT";
const char *kIgnore = "IGNORE";
const char *kCallback = "CALLBACK";

}  // namespace

// Public Methods

StreamHelper::StreamHelper()
    : parent_(nullptr),
      mtu_(0),
      pending_(2),
      segments_(2),
      data_len_(0x100),
      state_size_(0),
      state_(nullptr),
      crypto_helper_(nullptr) {}

CryptoTest *StreamHelper::GetParent() {
  return parent_;
}

STREAM *StreamHelper::GetStream(io_mock_t io, direction_t direction) {
  struct stream_flow_st *flow = GetFlow(io, direction);
  return &flow->stream;
}

const std::string &StreamHelper::GetLabel() {
  return label_;
}

void StreamHelper::SetParent(CryptoTest &parent) {
  parent_ = &parent;
}

void StreamHelper::SetCryptoHelper(CryptoHelper &crypto_helper) {
  assert(!crypto_helper_);
  crypto_helper_ = &crypto_helper;
  crypto_helper_->AddStringAttribute(kLabel, label_);
  crypto_helper_->AddHexAttribute(kServer, server_.data, true);
  crypto_helper_->AddHexAttribute(kClient, client_.data, true);
  crypto_helper_->AddStringAttribute(kErrorSource, source_, true);
  crypto_helper_->AddStringAttribute(kErrorReason, reason_, true);
}

void StreamHelper::SetMtu(size_t mtu) {
  mtu_ = mtu;
}

void StreamHelper::SetPending(size_t pending) {
  pending_ = pending;
}

void StreamHelper::SetNesting(direction_t direction, size_t nesting) {
  struct stream_flow_st *flow = nullptr;
  flow = GetFlow(kIoClient, direction);
  flow->nesting = nesting;
  flow = GetFlow(kIoServer, direction);
  flow->nesting = nesting;
}

void StreamHelper::SetState(void *state, size_t state_size) {
  assert(!state || !state_);
  assert(state || state_size != 0);
  state_ = state;
  state_size_ = state_size;
}

void StreamHelper::AddCallback(const std::string &label, Callback callback) {
  callbacks_[label] = callback;
}

void StreamHelper::Reset() {
  ResetClient();
  client_.buffer.Reset(ChunkSize() * pending_);
  if (!crypto_helper_) {
    io_mock_init(mtu_, client_.buffer.Get(), client_.buffer.Get());
  } else {
    ResetServer();
    server_.buffer.Reset(ChunkSize() * pending_);
    io_mock_init(mtu_, client_.buffer.Get(), server_.buffer.Get());
  }
}

void StreamHelper::Flush(void) {
  STREAM *client_send = GetStream(kIoClient, kSend);
  while (!stream_flush(client_send)) {
    ASSERT_ERROR(kTlsErrPlatform, io_mock_retry());
  }
  if (crypto_helper_) {
    STREAM *server_send = GetStream(kIoServer, kSend);
    while (!stream_flush(server_send)) {
      ASSERT_ERROR(kTlsErrPlatform, io_mock_retry());
    }
  }
}

bool StreamHelper::ReadNext() {
  // ReadNext only works with non-loopback streams.
  if (!crypto_helper_) {
    return false;
  }
  // Are the any outstanding, unexpected errors?
  if (!CheckErrors()) {
    return false;
  }
  // Can we compare what the client has sent?
  if (!ReadAndRecvFromClient()) {
    return false;
  }
  // Do we need to send data from the server?
  if (!ReadAndSendFromServer()) {
    return false;
  }
  return true;
}

bool StreamHelper::HasAttribute(const std::string &tag) {
  if (!crypto_helper_) {
    return false;
  }
  return crypto_helper_->HasAttribute(tag);
}

// Protected Methods

size_t StreamHelper::MemorySize(io_mock_t io) {
  struct stream_end_st *end = GetEnd(io);
  return stream_size(segments_, end->send.nesting) + ChunkSize() +
         stream_size(segments_, end->recv.nesting) + ChunkSize();
}

void StreamHelper::ResetMemory(io_mock_t io) {
  size_t size = MemorySize(io);
  struct stream_end_st *end = GetEnd(io);
  if (io != kIoServer) {
    size += LIST_SIZE(STREAM_HASH, VAPIDSSL_HASHES + 1);
  }
  end->region.Reset(size);
}

ScopedBuf *StreamHelper::GetMemory(io_mock_t io) {
  return (io == kIoServer ? &server_.region : &client_.region);
}

void StreamHelper::SetSegments(size_t segments) {
  segments_ = segments;
}

void StreamHelper::SetDataLen(size_t data_len) {
  data_len_ = data_len;
}

size_t StreamHelper::ChunkSize() {
  return sizeof(uint32_t) + data_len_;
}

void StreamHelper::ResetHashes(io_mock_t io) {
  size_t num = 1;
  struct stream_end_st *end = GetEnd(io);
  if (io != kIoServer) {
    num += VAPIDSSL_HASHES;
  }
  EXPECT_TRUE(LIST_NEW(STREAM_HASH, end->region.Get(), num, &end->hashes));
  stream_set_hashes(GetStream(io, kRecv), &end->hashes);
  stream_set_hashes(GetStream(io, kSend), &end->hashes);
}

void StreamHelper::ResetClient() {
  ResetMemory(kIoClient);
  STREAM *client_recv = GetStream(kIoClient, kRecv);
  ResetStream(kIoClient, kRecv, client_recv);
  STREAM *client_send = GetStream(kIoClient, kSend);
  ResetStream(kIoClient, kSend, client_send);
  ResetHashes(kIoClient);
}

void StreamHelper::ResetServer() {
  ResetMemory(kIoServer);
  STREAM *server_recv = GetStream(kIoServer, kRecv);
  ResetStream(kIoServer, kRecv, server_recv);
  STREAM *server_send = GetStream(kIoServer, kSend);
  ResetStream(kIoServer, kSend, server_send);
}

void StreamHelper::ResetStream(io_mock_t io, direction_t dir, STREAM *out) {
  struct stream_end_st *end = GetEnd(io);
  struct stream_flow_st *flow = GetFlow(io, dir);
  EXPECT_TRUE(
      stream_init(end->region.Get(), io, dir, segments_, flow->nesting, out));
  CHUNK *chunk = stream_get_chunk(out);
  ResetChunk(io, dir, chunk);
}

void StreamHelper::ResetChunk(io_mock_t io, direction_t direction, CHUNK *out) {
  struct stream_end_st *end = GetEnd(io);
  EXPECT_TRUE(chunk_set_region(out, end->region.Get(), sizeof(uint32_t),
                               kAuthenticated));
  EXPECT_TRUE(chunk_set_segment(out, 0, sizeof(uint32_t), kAuthenticated));
  EXPECT_TRUE(chunk_set_region(out, end->region.Get(), data_len_, kEncrypted));
  EXPECT_TRUE(chunk_set_text(out, 1, GetSize));
  if (direction == kSend) {
    chunk_set_processing(out, NULL, SetSize, NULL);
  }
}

void StreamHelper::InvokeCallback(direction_t dir, ScopedBuf &buf) {
  if (!crypto_helper_->HasAttribute(kCallback)) {
    return;
  }
  auto i = callbacks_.find(label_);
  if (i == callbacks_.end()) {
    std::cerr << "Missing callback for '" << label_ << "'!" << std::endl;
    abort();
  }
  EXPECT_TRUE(i->second(*this, buf));
}

// Private Methods

tls_result_t StreamHelper::SetSize(CHUNK *chunk) {
  BUF *buf = chunk_get_segment(chunk, 0);
  BUF *text = chunk_get_text(chunk);
  buf_reset(buf, 0);
  buf_put_val(buf, 4, (uint32_t)buf_ready(text));
  return kTlsSuccess;
}

tls_result_t StreamHelper::GetSize(CHUNK *chunk, size_t *out) {
  BUF *buf = chunk_get_segment(chunk, 0);
  uint32_t len = 0;
  buf_reset(buf, 0);
  buf_produce(buf, 4, NULL);
  if (!buf_get_val(buf, 4, &len)) {
    return kTlsFailure;
  }
  *out = len;
  return kTlsSuccess;
}

bool StreamHelper::CanRetry() {
  if (!TLS_ERROR_test(kTlsErrPlatform, io_mock_retry())) {
    return false;
  }
  error_clear();
  return true;
}

bool StreamHelper::CheckErrors() {
  // Take a closer look at any outstanding error.
  tls_error_source_t source;
  int reason = 0;
  TLS_ERROR_get(&source, &reason, nullptr, nullptr);
  if (crypto_helper_->HasAttribute(kErrorSource) &&
      crypto_helper_->HasAttribute(kErrorReason)) {
    // Check if we expected an error to have been generated by the last
    // iteration.
    EXPECT_EQ(source_, ErrorHelper::GetSourceAsString(source)) << "At "
                                                               << label_;
    EXPECT_EQ(reason_, ErrorHelper::GetReasonAsString(source, reason))
        << "At " << label_;
  } else if ((source != 0 || reason != 0) &&
             (source != kTlsErrVapid || reason != kTlsErrDisconnected)) {
    // The only other "expected" error is |kTlsErrDisconnected|, used by
    // io_mock.c to signal when no more data is available to read in the
    // current iteration.
    ADD_FAILURE() << "At " << label_;
    return false;
  }
  error_clear();
  // Check if we should rewind to an earlier state, and if not, if we should
  // save the current state for later rewinding.
  if (crypto_helper_->HasAttribute(kRevert)) {
    state_helper_.Revert(state_, state_size_);
  } else if (crypto_helper_->HasAttribute(kSnapshot)) {
    state_helper_.Snapshot(state_, state_size_);
  }
  return true;
}

bool StreamHelper::ReadAndRecvFromClient() {
  // Check for test data file EOF.
  if (!crypto_helper_->HasAttribute(kClient) && !crypto_helper_->ReadNext()) {
    return false;
  }
  // Use getter to allow subclasses to override the message in use.
  STREAM *client_send = GetStream(kIoClient, kSend);
  while (!stream_flush(client_send) && CanRetry()) {
  }
  if (!CheckErrors()) {
    return false;
  }
  STREAM *server_recv = GetStream(kIoServer, kRecv);
  while (crypto_helper_->HasAttribute(kClient)) {
    assert(!crypto_helper_->HasAttribute(kServer));
    server_.data.Reset(client_.data.Len());
    // Need to invoke the callback before touching the stream, since it may be
    // changing the cipher settings.
    InvokeCallback(kRecv, client_.data);
    while (!stream_recv_buf(server_recv, nullptr, 0, server_.data.Get()) &&
           CanRetry()) {
    }
    if (!CheckErrors()) {
      return false;
    }
    if (!crypto_helper_->HasAttribute(kIgnore)) {
      EXPECT_PRED2(buf_equal, client_.data.Get(), server_.data.Get()) << "At "
                                                                      << label_;
    }
    // Stop on EOF, but let the client continue processing.
    if (!crypto_helper_->ReadNext()) {
      label_ = "EOF";
      break;
    }
  }
  assert(!crypto_helper_->HasAttribute(kClient));
  return true;
}

bool StreamHelper::ReadAndSendFromServer() {
  STREAM *server_send = GetStream(kIoServer, kSend);
  while (crypto_helper_->HasAttribute(kServer)) {
    assert(!crypto_helper_->HasAttribute(kClient));
    InvokeCallback(kSend, server_.data);
    // It's possible our callback consumed all the data.
    while (buf_ready(server_.data.Get()) != 0 &&
           !stream_send_buf(server_send, 0, server_.data.Get()) && CanRetry()) {
    }
    if (!CheckErrors()) {
      return false;
    }
    // Stop on EOF, but let the client continue processing.
    if (!crypto_helper_->ReadNext()) {
      label_ = "EOF";
      break;
    }
  }
  assert(!crypto_helper_->HasAttribute(kServer));
  while (!stream_flush(server_send) && CanRetry()) {
  }
  return CheckErrors();
}

struct stream_end_st *StreamHelper::GetEnd(io_mock_t io) {
  return (io == kIoServer ? &server_ : &client_);
}

struct stream_flow_st *StreamHelper::GetFlow(io_mock_t io, direction_t dir) {
  stream_end_st *end = GetEnd(io);
  return (dir == kSend ? &end->send : &end->recv);
}

}  // namespace vapidssl
