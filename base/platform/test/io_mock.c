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

#include "base/platform/test/io_mock.h"
#include "base/platform/io.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/types.h"
#include "public/error.h"
#include "public/tls.h"

// Global variables.

static size_t g_mtu = 0;
static BUF *g_recv = NULL;
static BUF *g_send = NULL;
bool_t g_verbose = kFalse;

// Forward declarations.

static tls_result_t io_mock_recv(tls_connection_id_t cid, BUF *src, BUF *dst);
static tls_result_t io_mock_send(tls_connection_id_t cid, BUF *src, BUF *dst);
static void io_mock_header(tls_connection_id_t cid, direction_t direction,
                           size_t n);
static void io_mock_hexdump(const uint8_t *buf, size_t n);

// Library routines.

void io_mock_init(size_t mtu, BUF *recv, BUF *send) {
  g_mtu = mtu;
  g_recv = recv;
  g_send = send;
}

int io_mock_retry() {
  return EAGAIN;
}

tls_result_t io_data(tls_connection_id_t cid, direction_t direction, BUF *buf) {
  assert(buf);
  if (cid == kIoServer && direction == kRecv) {
    return io_mock_recv(cid, g_send, buf);
  } else if (cid == kIoServer) {
    return io_mock_send(cid, buf, g_recv);
  } else if (direction == kRecv) {
    return io_mock_recv(cid, g_recv, buf);
  } else {
    return io_mock_send(cid, buf, g_send);
  }
}

void io_mock_set_verbose(bool_t enabled) {
  g_verbose = enabled;
}

// Static functions

static tls_result_t io_mock_recv(tls_connection_id_t cid, BUF *src, BUF *dst) {
  assert(src);
  buf_recycle(src);
  size_t n = buf_available(dst);
  // Returning |EAGAIN| when we've exhausted our data is a great way to get
  // infinite loops in the stream and chunk tests, but we need a non-fatal way
  // to run out of data in the certificate, extension, and handshake tests. Act
  // like the peer disconnected.
  if (buf_ready(src) < n) {
    return ERROR_SET(kTlsErrVapid, kTlsErrDisconnected);
  }
  if (g_mtu != 0 && g_mtu < n) {
    n = g_mtu;
  }
  uint8_t *src_raw = NULL;
  buf_consume(src, n, &src_raw);
  uint8_t *dst_raw = NULL;
  buf_produce(dst, n, &dst_raw);
  memcpy(dst_raw, src_raw, n);
  if (n != 0 && g_verbose) {
    io_mock_header(cid, kRecv, n);
    io_mock_hexdump(src_raw, n);
  }
  if (buf_available(dst) != 0) {
    return ERROR_SET(kTlsErrPlatform, EAGAIN);
  }
  return kTlsSuccess;
}

static tls_result_t io_mock_send(tls_connection_id_t cid, BUF *src, BUF *dst) {
  assert(dst);
  size_t n = buf_ready(src);
  assert(n <= buf_available(dst));
  if (g_mtu != 0 && g_mtu < n) {
    n = g_mtu;
  }
  uint8_t *src_raw = NULL;
  buf_consume(src, n, &src_raw);
  if (dst) {
    uint8_t *dst_raw = NULL;
    buf_produce(dst, n, &dst_raw);
    memcpy(dst_raw, src_raw, n);
  }
  if (n != 0 && g_verbose) {
    io_mock_header(cid, kSend, n);
    io_mock_hexdump(src_raw, n);
  }
  if (buf_ready(src) != 0) {
    return ERROR_SET(kTlsErrPlatform, EAGAIN);
  }
  buf_recycle(dst);
  return kTlsSuccess;
}

static void io_mock_header(tls_connection_id_t cid, direction_t direction,
                           size_t n) {
  printf("\n");
  if (cid == kIoServer) {
    printf("Server");
  } else if (cid == kIoClient) {
    printf("Client");
  } else {
    printf("Loopback");
  }
  if (direction == kSend) {
    printf(" sent ");
  } else {
    printf(" received ");
  }
  printf("%zu bytes:", n);
}

static void io_mock_hexdump(const uint8_t *buf, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (i % 32 == 0) {
      printf("\n%04lx", i);
    }
    if (i % 16 == 0) {
      printf("  ");
    }
    if (i % 4 == 0) {
      printf(" ");
    }
    printf(" %02x", buf[i]);
  }
  printf("\n");
}
