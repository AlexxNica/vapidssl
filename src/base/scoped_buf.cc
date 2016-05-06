/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "base/scoped_buf.h"

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

void ScopedBuf::Reset(const BUF &buf) {
  Reset(buf_size(&buf));
  buf_copy(&buf, &buf_);
}

void ScopedBuf::Reset(const std::vector<uint8_t> &bytes) {
  size_t len = bytes.size();
  Reset(len);
  uint8_t *raw = nullptr;
  buf_produce(&buf_, len, &raw);
  std::copy(bytes.begin(), bytes.end(), raw);
}

namespace {

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* Static functions. */

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

} /* namespace */

} /* namespace vapidssl */

/* We have to reach into the internals here since the buffer is const. */
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
