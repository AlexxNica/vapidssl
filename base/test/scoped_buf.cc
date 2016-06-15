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

#include "base/test/scoped_buf.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <vector>

#include "base/buf.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

ScopedBuf::ScopedBuf() : buf_() {}

ScopedBuf::ScopedBuf(size_t len) : buf_() {
  Reset(len);
}

ScopedBuf::ScopedBuf(const std::vector<uint8_t> &bytes) : buf_() {
  Reset(bytes);
}

ScopedBuf::~ScopedBuf() {
  Reset(0);
}

BUF *ScopedBuf::Get() {
  return &buf_;
}

void ScopedBuf::Reset(size_t len) {
  uint8_t *raw = nullptr;
  if (buf_size(&buf_) != 0) {
    raw = (uint8_t *)buf_unwrap(&buf_);
  }
  if (raw) {
    delete[] raw;
  }
  if (len == 0) {
    return;
  }
  raw = new (std::nothrow) uint8_t[len];
  if (!raw) {
    std::cerr << "Failed to allocate memory; aborting!" << std::endl;
    abort();
  }
  buf_wrap(raw, len, &buf_);
  buf_zero(&buf_);
}

void ScopedBuf::Reset(ScopedBuf &buf) {
  ScopedBuf::Reset(buf_size(buf.Get()));
  buf_copy(buf.Get(), &buf_);
}

void ScopedBuf::Reset(const std::vector<uint8_t> &bytes) {
  size_t len = bytes.size();
  ScopedBuf::Reset(len);
  uint8_t *raw = nullptr;
  buf_produce(&buf_, len, &raw);
  std::copy(bytes.begin(), bytes.end(), raw);
}

namespace {

// Static functions.

void print_hex(::std::ostream &os, uint8_t byte) {
  char s[2];
  s[1] = 0;
  uint8_t nybble = (byte & 0xf0) >> 4;
  s[0] = (nybble > 9 ? nybble - 10 + 'A' : nybble + '0');
  os << s;
  nybble = byte & 0x0f;
  s[0] = (nybble > 9 ? nybble - 10 + 'A' : nybble + '0');
  os << s;
}

}  // namespace

}  // namespace vapidssl

// We have to reach into the internals here since the buffer is const.
::std::ostream &operator<<(::std::ostream &os, const BUF *buf) {
  if (buf->offset != 0) {
    os << "..." << buf->offset << " consumed bytes...";
  }
  for (size_t i = 0; buf->offset + i < buf->length; ++i) {
    if ((i % 16) == 0) {
      os << std::endl;
    }
    ::vapidssl::print_hex(os, buf->raw[buf->offset + i]);
    if ((i % 16) != 15) {
      os << " ";
    }
  }
  os << std::endl;
  if (buf->length != buf->max) {
    os << "..." << (buf->max - buf->length) << " available bytes...";
    os << std::endl;
  }
  return os;
}
