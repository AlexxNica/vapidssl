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

#ifndef VAPIDSSL_COMMON_TEST_STREAM_HELPER_H
#define VAPIDSSL_COMMON_TEST_STREAM_HELPER_H

#include <stddef.h>

#include "base/platform/test/io_mock.h"
#include "base/test/scoped_buf.h"
#include "base/types.h"
#include "common/chunk.h"
#include "common/stream.h"
#include "common/stream_internal.h"
#include "common/test/state_helper.h"
#include "crypto/test/hash_test.h"

namespace vapidssl {

// stream_flow_st holds the configuration of a unidirectional stream of data.
struct stream_flow_st {
  // stream represents the flow of data in one direction.
  STREAM stream;
  // nesting indicates the maximum amount of nesting in this direction.
  size_t nesting;
};

// stream_end_st represents one endpoint of a connection, including buffers to
// hold the endpoints state and two unidirectional flows.
struct stream_end_st {
  // data holds the current test data attribute for this endpoint.
  ScopedBuf data;
  // region is the memory used for this endpoint during testing.
  ScopedBuf region;
  // buffer holds I/O data for this endpoint for io_mock.h.
  ScopedBuf buffer;
  // hashes is the list of running hashes of data sent and/or received.
  LIST hashes;
  // send is the unidirectional flow of data away from this endpoint.
  struct stream_flow_st send;
  // recv is the unidirectional flow of data toward from this endpoint.
  struct stream_flow_st recv;
};

// Callback is a function pointer that can be invoked when a particular label is
// encountered in a test data file.  See |AddCallback| and |InvokeCallback|
// below.
class StreamHelper;
using Callback = bool (*)(StreamHelper &stream_helper, ScopedBuf &buf);

// StreamHelper is intended to make it easier to write and run unit tests that
// involve streams.  It abstracts a pair of unidirectional streams and allows
// control of various I/O related parameters that would normally be determined
// by the platform and/or network.
class StreamHelper {
 public:
  StreamHelper();
  virtual ~StreamHelper() = default;
  StreamHelper &operator=(const StreamHelper &) = delete;
  StreamHelper(const StreamHelper &) = delete;

  // GetParent returns the test that is using this object, if it was set using
  // |SetParent|, or NULL otherwise.
  CryptoTest *GetParent();

  // GetStream returns either client's or server's sending or receiving stream,
  // depending on the values of |io| and |direction|.
  virtual STREAM *GetStream(io_mock_t io, direction_t direction);

  // GetLabel returns the test data attribute indicates which set of attributes
  // is currently being processed.  See also |AddCallback|.
  virtual const std::string &GetLabel();

  // SetParent registers |parent| as the test using this object.  This is useful
  // as it allows the test to be retrieved via |GetParent| within
  // |InvokeCallback|.
  virtual void SetParent(CryptoTest &parent);

  // SetCryptoHelper sets the |crypto_helper_| to be used to emulate server
  // using a test data file.  Data sent by the client will be compared against
  // what is expected, and data will be taken from the file to generate the
  // server's responses.
  virtual void SetCryptoHelper(CryptoHelper &crypto_helper);

  // SetMtu updates io_mock.h with a maximum transfer unit of |mtu|.
  virtual void SetMtu(size_t mtu);

  // SetPending updates the number of sent chunks that can be simultaneously
  // outstanding.
  virtual void SetPending(size_t pending);

  // SetNesting updates the length of the nesting lists in the given |direction|
  // to |nesting|.
  virtual void SetNesting(direction_t direction, size_t nesting);

  // SetState registers the memory region of given by |state| or length
  // |state_size| for use in snapshotting.  If a set of test data attributes in
  // a test data file includes "SNAPSHOT: 1", the memory at |state| will be
  // copied.  If it includes "REVERT: 1", the memory at |state| will be
  // overwritten with the last copy taken.
  virtual void SetState(void *state, size_t state_size);

  // AddCallback registers the function pointer given by |callback| to be
  // invoked when a particular |label| is encountered in a test data file.
  virtual void AddCallback(const std::string &label, Callback callback);

  // Reset obliterates the current state by resetting |region_| and |loopback_|.
  // It then rebuilds the |rx_| and |tx_| streams and configures their chunks to
  // have two segments: a length segment and and text segment.  It registers
  // |AlwaysContinue|, |GetSize|, and |SetSize| as appropriate.
  virtual void Reset(void);

  // Flush will call |stream_flush| on |tx_| repeatedly until it returns
  // successfully or an error occurs that precludes retrying the I/O.
  virtual void Flush(void);

  // ReadNext uses |crypto_helper_| and its test data file to both compare data
  // sent by the client to what is expected as well as to generate data from the
  // server to be received by the client.
  virtual bool ReadNext();

  // HasAttribute returns true if the last set of test data attributes read from
  // the test data file included an attribute named |tag|.
  virtual bool HasAttribute(const std::string &tag);

 protected:
  // MemorySize returns the amount of memory needed for the endpoint given by
  // |io|.
  virtual size_t MemorySize(io_mock_t io);

  // Reset memory resets the memory region for one of the stream endpoints, as
  // indicated by |io|.
  virtual void ResetMemory(io_mock_t io);

  // GetMemory returns the memory used for the stream endpoint given by |io|.
  // ScopedBuf *GetMemory(io_mock_t io);

  // SetSegments sets the number of |segments| in the streams' chunks.
  virtual void SetSegments(size_t segments);

  // SetDataLen resets the streams and updates the maximum amount of data per
  // chunk to |data_len|.
  virtual void SetDataLen(size_t data_len);

  // ChunkSize returns the maximum amount of I/O data sent as one chunk.
  virtual size_t ChunkSize();

  // ResetHashes reallocates memory for tracking hashes and adds the hashes to
  // the appropriate streams given by |io|.
  virtual void ResetHashes(io_mock_t io);

  // ResetClient resets the streams associated with the |client_| endpoint.
  virtual void ResetClient();

  // ResetServer resets the streams associated with the |server_| endpoint.
  virtual void ResetServer();

  // ResetStream reinitializes |out| as a stream for the flow given by |io| and
  // |direction|.
  virtual void ResetStream(io_mock_t io, direction_t direction, STREAM *out);

  // ResetStream reinitializes |out| as the chunk for a stream for the flow
  // given by |io| and |direction|.
  virtual void ResetChunk(io_mock_t io, direction_t direction, CHUNK *out);

  // InvokeCallback checks if there are any callbacks registed for the given
  // |label|, and if so, it calls them.
  virtual void InvokeCallback(direction_t direction, ScopedBuf &label);

 private:
  // GetSize is a |text_size_f| that can be used with the two segment chunk
  // created by |StreamHelper::Reset| to read the size of text segment from the
  // length segment.
  static tls_result_t GetSize(CHUNK *chunk, size_t *out);

  // SetSize is a |chunk_f| that can be used as a |process_chunk| parameter in
  // |chunk_set_process| It can be used with the two segment sending chunk
  // created by |StreamHelper::Reset| to set the length segment with the size of
  // the text segment.
  static tls_result_t SetSize(CHUNK *chunk);

  // CanRetry returns whether the most recent error indicates a non-fatal I/O
  // error that can be retried.
  virtual bool CanRetry();

  // CheckErrors returns whether the current error matches the one expected
  // based on the test data file.
  virtual bool CheckErrors();

  // ReadAndRecvFromClient receives data from the client's 'send' stream to the
  // server's 'receive' stream, and then checks it against the current test data
  // attributes.
  virtual bool ReadAndRecvFromClient();

  // ReadAndSendFromServer uses the current set of test data attributes to send
  // data from the server's 'send' stream to the client's 'receive' stream.
  virtual bool ReadAndSendFromServer();

  // GetFlow returns the unidirectional flow for the given |io| and |direction|.
  struct stream_flow_st *GetFlow(io_mock_t io, direction_t direction);

  // GetEnd gets the endpoint for the given |io|.
  struct stream_end_st *GetEnd(io_mock_t io);

  // parent_ is the test using this object. See |SetParent|.
  CryptoTest *parent_;
  // mtu_ is the maximum transfer unit for io_mock.h.
  size_t mtu_;
  // pending is the maximum number of chunks that can be "in-flight".
  size_t pending_;
  // segments_ is the number of the streams' chunks' segments.
  size_t segments_;
  // data_len_ is the maximum amount of data in the streams' chunks.
  size_t data_len_;
  // state_size is the size of |state_|.
  size_t state_size_;
  // state_ holds snapshots if the test needs to be rewound.
  void *state_;
  // crypto_helper_ is used if data is being injected from a test data file.
  CryptoHelper *crypto_helper_;
  // state_helper_ allows the test to snapshot resume |state_|.
  StateHelper state_helper_;
  // label_ is a test data attribute to aid debugging.
  std::string label_;
  // source_ is a test data attribute that indicates an expected error source.
  std::string source_;
  // source_ is a test data attribute that indicates an expected error reason.
  std::string reason_;
  // callbacks_ are functions that get involved when a |label_| matches.
  std::map<std::string, Callback> callbacks_;
  // server_ represents the server end of the streams.
  struct stream_end_st server_;
  // client_ represents the client end of the streams.
  struct stream_end_st client_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_COMMON_TEST_STREAM_HELPER_H
