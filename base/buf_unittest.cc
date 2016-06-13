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


#include "base/buf.h"
#include "base/buf_internal.h"

#include <stdlib.h>
#include <memory>

#include "base/arch/random.h"
#include "public/error.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

class BufTest : public ::testing::Test {
 protected:
  BufTest() : buf1_(), raw1_(), buf2_(), raw2_() {}

  virtual void SetUp() {
    buf1_ = {NULL, NULL, 0, 0x10000, 0x10000, 0};
    raw1_.reset(new (std::nothrow) uint8_t[buf1_.max]);
    if (!raw1_.get()) {
      abort();
    }
    buf1_.raw = raw1_.get();
    buf2_ = {NULL, NULL, 0x100, 0x300, 0x400, 0};
    raw2_.reset(new (std::nothrow) uint8_t[buf2_.max]);
    if (!raw2_.get()) {
      abort();
    }
    buf2_.raw = raw2_.get();
  }

  BUF buf1_;
  std::unique_ptr<uint8_t[]> raw1_;
  BUF buf2_;
  std::unique_ptr<uint8_t[]> raw2_;
};

using BufDeathTest = BufTest;

TEST_F(BufDeathTest, ReserveMemory) {
  void *mem0 = buf2_.raw;
  void *mem1 = mem0;
  size_t len0 = buf2_.max;
  size_t len1 = len0;
  /* Check null parameters. */
  EXPECT_ASSERT(buf_reserve(1, NULL, &len0));
  EXPECT_ASSERT(buf_reserve(1, &mem0, NULL));
  buf_reserve(0, &mem0, &len0);
  /* Check buf_reserve advances correctly. */
  EXPECT_EQ(mem0, mem1);
  EXPECT_EQ(len0, len1);
  buf_reserve(1, &mem0, &len0);
  EXPECT_EQ(mem0, (uint8_t *)mem1 + 1);
  EXPECT_EQ(len0, len1 - 1);
  /* Check buf_reserve cannot reserve more than max. */
  EXPECT_ASSERT(buf_reserve(buf2_.max, &mem0, &len0));
  buf_reserve(buf2_.max - 1, &mem0, &len0);
  EXPECT_EQ(mem0, (uint8_t *)mem1 + buf2_.max);
  EXPECT_EQ(len0, 0U);
  EXPECT_ASSERT(buf_reserve(1, &mem0, &len0));
}

TEST_F(BufTest, InitializeBuffer) {
  BUF buf = buf_init();
  /* Check the buffer really is empty. */
  EXPECT_EQ(buf.region, nullptr);
  EXPECT_EQ(buf.raw, nullptr);
  EXPECT_EQ(buf.offset, 0U);
  EXPECT_EQ(buf.length, 0U);
  EXPECT_EQ(buf.max, 0U);
}

TEST_F(BufDeathTest, WrapAndUnwrapBuf) {
  size_t len = 0x100;
  std::unique_ptr<uint8_t[]> mem(new (std::nothrow) uint8_t[len]);
  ASSERT_NE(mem.get(), nullptr);
  BUF buf = buf_init();
  /* Check null parameters. */
  EXPECT_ASSERT(buf_wrap(mem.get(), len, NULL));
  EXPECT_ASSERT(buf_wrap(NULL, len, &buf));
  EXPECT_ASSERT(buf_wrap(mem.get(), 0, &buf));
  /* Check wrapping works. */
  EXPECT_TRUE(buf_wrap(mem.get(), len, &buf));
  EXPECT_EQ(buf.raw, mem.get());
  EXPECT_EQ(buf.offset, 0U);
  EXPECT_EQ(buf.length, len);
  EXPECT_EQ(buf.max, len);
  /* Check re-wrapping only succeeds if the buffer is unchanged. */
  EXPECT_FALSE(buf_wrap(mem.get(), len - 1, &buf));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrBufferChanged);
  EXPECT_TRUE(buf_wrap(mem.get(), len, &buf));
  /* Check unwrapping works. */
  EXPECT_EQ(buf_unwrap(&buf), mem.get());
  EXPECT_EQ(buf.raw, nullptr);
  EXPECT_EQ(buf.offset, 0U);
  EXPECT_EQ(buf.length, 0U);
  EXPECT_EQ(buf.max, 0U);
  /* Check unwrapping an unwrapped buffer works. */
  EXPECT_EQ(buf_unwrap(&buf), nullptr);
}

TEST_F(BufDeathTest, AllocAndFreeBuf) {
  BUF buf = buf_init();
  /* Check null and invalid parameters for EXPECT_EQ(buf_malloc. */
  EXPECT_ASSERT(buf_malloc(&buf1_, 0x1000, NULL));
  EXPECT_ASSERT(buf_malloc(NULL, 0x1000, &buf));
  EXPECT_ASSERT(buf_malloc(&buf1_, 0x1000, &buf2_));
  EXPECT_ASSERT(buf_malloc(&buf1_, 0, &buf));
  /* Check allocation works. */
  EXPECT_TRUE(buf_malloc(&buf1_, 0x1000, &buf));
  EXPECT_NE(buf.raw, nullptr);
  EXPECT_EQ(buf.offset, 0U);
  EXPECT_EQ(buf.length, 0U);
  EXPECT_EQ(buf.max, 0x1000U);
  /* Check null parameters for buf_free. */
  EXPECT_ASSERT(buf_free(NULL));
  /* Check deallocation works. */
  buf_free(&buf);
  EXPECT_EQ(buf.raw, nullptr);
  EXPECT_EQ(buf.offset, 0U);
  EXPECT_EQ(buf.length, 0U);
  EXPECT_EQ(buf.max, 0U);
  BUF buf2 = buf_init();
  /* Check allocation fails when OOM. */
  EXPECT_TRUE(buf_malloc(&buf1_, buf1_.max, &buf2));
  EXPECT_FALSE(buf_malloc(&buf1_, 1, &buf));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
  buf_free(&buf2);
  EXPECT_TRUE(buf_malloc(&buf1_, buf1_.max, &buf));
  buf_free(&buf);
}

TEST_F(BufDeathTest, SplitAndMergeBuf) {
  BUF buf1 = buf_init();
  BUF buf2 = buf_init();
  ASSERT_TRUE(buf_malloc(&buf1_, 0x1000, &buf1));
  /* Check we can split a buffer. */
  buf1.offset = 0x100;
  buf1.length = 0x200;
  buf_split(&buf1, 0x400, &buf2);
  EXPECT_EQ(buf1.offset, 0x100U);
  EXPECT_EQ(buf1.length, 0x200U);
  EXPECT_EQ(buf1.max, 0x400U);
  EXPECT_EQ(buf2.offset, 0U);
  EXPECT_EQ(buf2.length, 0U);
  EXPECT_EQ(buf2.max, 0xc00U);
  /* Check we can merge the buffers back together. */
  buf_merge(&buf2, &buf1);
  EXPECT_EQ(buf1.offset, 0U);
  EXPECT_EQ(buf1.length, 0x100U);
  EXPECT_EQ(buf1.max, 0x1000U);
  EXPECT_EQ(buf2.offset, 0U);
  EXPECT_EQ(buf2.length, 0U);
  EXPECT_EQ(buf2.max, 0U);
  /* Check a split with offset and length occurring after the split. */
  buf1.offset = 0x600;
  buf1.length = 0x800;
  buf_split(&buf1, 0x400, &buf2);
  EXPECT_EQ(buf1.offset, 0x400U);
  EXPECT_EQ(buf1.length, 0x400U);
  EXPECT_EQ(buf1.max, 0x400U);
  EXPECT_EQ(buf2.offset, 0x200U);
  EXPECT_EQ(buf2.length, 0x400U);
  EXPECT_EQ(buf2.max, 0xc00U);
  /* Check we can merge the buffers back together in opposite order. */
  buf1.offset = 0x300;
  buf_merge(&buf1, &buf2);
  EXPECT_EQ(buf1.offset, 0U);
  EXPECT_EQ(buf1.length, 0U);
  EXPECT_EQ(buf1.max, 0U);
  EXPECT_EQ(buf2.offset, 0U);
  EXPECT_EQ(buf2.length, 0x300U);
  EXPECT_EQ(buf2.max, 0x1000U);
}

TEST_F(BufDeathTest, ResetBuf) {
  /* Check null parameters. */
  EXPECT_ASSERT(buf_reset(NULL, 0));
  /* Check offset and length can be set to [0, max]. */
  buf_reset(&buf2_, 0);
  EXPECT_EQ(buf2_.offset, 0U);
  EXPECT_EQ(buf2_.length, 0U);
  buf_reset(&buf2_, buf2_.max);
  EXPECT_EQ(buf2_.offset, buf2_.max);
  EXPECT_EQ(buf2_.length, buf2_.max);
  /* Check offset and length cannot be set to (max, inf). */
  EXPECT_ASSERT(buf_reset(&buf2_, buf2_.max + 1));
  /* Check unwrapped buffers can be reset to 0 only. */
  BUF buf = buf_init();
  buf_reset(&buf, 0);
  EXPECT_ASSERT(buf_reset(&buf, 1));
}

TEST_F(BufDeathTest, RecycleBuf) {
  BUF buf = buf_init();
  /* Check null parameters. */
  EXPECT_ASSERT(buf_recycle(NULL));
  /* Check recycling on a buffer without consumed data. */
  buf_recycle(&buf);
  EXPECT_EQ(buf.offset, 0U);
  EXPECT_EQ(buf.length, 0U);
  /* Check recycling on a buffer with consumed data. */
  buf_recycle(&buf2_);
  EXPECT_EQ(buf2_.offset, 0U);
  EXPECT_EQ(buf2_.length, 0x200U);
  /* Check recycling on a buffer with only consumed data. */
  buf2_.length = buf2_.max;
  buf2_.offset = buf2_.length;
  buf_recycle(&buf2_);
  EXPECT_EQ(buf2_.offset, 0U);
  EXPECT_EQ(buf2_.length, 0U);
}

/* Getters. */
TEST_F(BufDeathTest, GetSizes) {
  /* Check null parameters. */
  EXPECT_ASSERT(buf_size(NULL));
  /* Check various maximums. */
  EXPECT_EQ(buf_size(&buf1_), 0x10000U);
  EXPECT_EQ(buf_size(&buf2_), 0x400U);
}

TEST_F(BufDeathTest, GetConsumed) {
  /* Check null parameters. */
  EXPECT_ASSERT(buf_consumed(NULL));
  /* Check various amounts of ready data. */
  EXPECT_EQ(buf_consumed(&buf1_), 0U);
  EXPECT_EQ(buf_consumed(&buf2_), 0x100U);
}

TEST_F(BufDeathTest, GetReady) {
  /* Check null parameters. */
  EXPECT_ASSERT(buf_ready(NULL));
  /* Check various amounts of ready data. */
  EXPECT_EQ(buf_ready(&buf1_), 0x10000U);
  EXPECT_EQ(buf_ready(&buf2_), 0x200U);
}

TEST_F(BufDeathTest, GetAvailable) {
  /* Check null parameters. */
  EXPECT_ASSERT(buf_available(NULL));
  /* Check various amounts of available space. */
  EXPECT_EQ(buf_available(&buf1_), 0U);
  EXPECT_EQ(buf_available(&buf2_), 0x100U);
}

TEST_F(BufDeathTest, GetAllocated) {
  /* Check null parameters. */
  EXPECT_ASSERT(buf_allocated(NULL));
  /* Check various amounts of allocated space. */
  EXPECT_EQ(buf_allocated(&buf1_), 0U);
  BUF buf = buf_init();
  EXPECT_TRUE(buf_malloc(&buf1_, 0x1000, &buf));
  EXPECT_EQ(buf_allocated(&buf1_), 0x1000U);
  buf_free(&buf);
  EXPECT_EQ(buf_allocated(&buf1_), 0U);
}

/* Data transfers */
TEST_F(BufDeathTest, ProduceAndConsumeBuf) {
  BUF buf = buf_init();
  uint8_t *out = NULL;
  /* Check null, empty, and zero parameters for buf_consume. */
  EXPECT_ASSERT(buf_consume(NULL, 0x200, &out));
  EXPECT_TRUE(buf_consume(&buf, 0, &out));
  EXPECT_EQ(out, nullptr);
  EXPECT_EQ(buf2_.offset, 0x100U);
  /* Check zero-length buf_consume */
  EXPECT_TRUE(buf_consume(&buf2_, 0, &out));
  EXPECT_EQ(out, nullptr);
  EXPECT_EQ(buf2_.offset, 0x100U);
  /* Check buf_consume without out. */
  EXPECT_TRUE(buf_consume(&buf2_, 0x100, NULL));
  EXPECT_EQ(out, nullptr);
  EXPECT_EQ(buf2_.offset, 0x200U);
  /* Check normal buf_consume. */
  EXPECT_TRUE(buf_consume(&buf2_, 0x100, &out));
  EXPECT_EQ(out, buf2_.raw + buf2_.offset - 0x100);
  EXPECT_EQ(buf2_.offset, 0x300U);
  /* Check buf_consume fails when no data is ready. */
  EXPECT_FALSE(buf_consume(&buf2_, 1, &out));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfBounds);
  /* Check null, empty, and zero parameters for buf_produce. */
  out = NULL;
  EXPECT_ASSERT(buf_produce(NULL, 0x100, &out));
  buf_produce(&buf, 0, &out);
  EXPECT_EQ(out, nullptr);
  EXPECT_EQ(buf2_.length, 0x300U);
  /* Check zero-length buf_produce */
  buf_produce(&buf2_, 0, &out);
  EXPECT_EQ(out, nullptr);
  EXPECT_EQ(buf2_.length, 0x300U);
  /* Check buf_produce without out. */
  buf_produce(&buf2_, 0x80, NULL);
  EXPECT_EQ(out, nullptr);
  EXPECT_EQ(buf2_.length, 0x380U);
  /* Check normal buf_produce. */
  buf_produce(&buf2_, 0x80, &out);
  EXPECT_EQ(out, buf2_.raw + buf2_.length - 0x80);
  EXPECT_EQ(buf2_.length, 0x400U);
  /* Check buf_produce fails when no space is available. */
  EXPECT_TRUE(buf_consume(&buf2_, 0x100, &out));
  EXPECT_EQ(out, buf2_.raw + buf2_.offset - 0x100);
  EXPECT_EQ(buf2_.offset, 0x400U);
  EXPECT_ASSERT(buf_produce(&buf2_, 1, &out));
}

TEST_F(BufDeathTest, PutAndGetValues) {
  BUF buf = buf_init();
  /* Check null and invalid parameters for buf_put_val. */
  EXPECT_ASSERT(buf_put_val(NULL, 1, 1));
  EXPECT_ASSERT(buf_put_val(&buf, 1, 1));
  buf1_.length = buf1_.max;
  buf1_.offset = buf1_.length;
  EXPECT_ASSERT(buf_put_val(&buf1_, 1, 1));
  buf1_.length = 0;
  buf1_.offset = buf1_.length;
  EXPECT_ASSERT(buf_put_val(&buf1_, 5, 1));
  /* Check we can put bytes in network order. */
  buf_put_val(&buf1_, 4, 0x41424344);
  EXPECT_EQ(buf1_.offset, 0U);
  EXPECT_EQ(buf1_.length, 4U);
  buf_put_val(&buf1_, 2, 0x41424344);
  EXPECT_EQ(buf1_.offset, 0U);
  EXPECT_EQ(buf1_.length, 6U);
  uint32_t out;
  /* Check null and invalid parameters for buf_get_val. */
  EXPECT_ASSERT(buf_get_val(NULL, 1, &out));
  EXPECT_ASSERT(buf_get_val(&buf, 1, NULL));
  EXPECT_FALSE(buf_get_val(&buf, 1, &out));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfBounds);
  buf1_.offset = buf1_.length;
  buf1_.offset = 0;
  EXPECT_ASSERT(buf_get_val(&buf1_, 5, &out));
  /* Check we can get bytes in network order. */
  EXPECT_TRUE(buf_get_val(&buf1_, 2, &out));
  EXPECT_EQ(out, 0x4142U);
  EXPECT_EQ(buf1_.offset, 2U);
  EXPECT_EQ(buf1_.length, 6U);
  EXPECT_TRUE(buf_get_val(&buf1_, 4, &out));
  EXPECT_EQ(out, 0x43444344U);
  EXPECT_EQ(buf1_.offset, 6U);
  EXPECT_EQ(buf1_.length, 6U);
}

/* Data manipulations */
TEST_F(BufDeathTest, CompareBufs) {
  size_t len = 0x400;
  BUF buf1 = buf_init();
  ASSERT_TRUE(buf_malloc(&buf1_, len, &buf1));
  BUF buf2 = buf_init();
  ASSERT_TRUE(buf_malloc(&buf1_, len, &buf2));
  buf_reset(&buf2, 0);
  random_buf(&buf2);
  /* Check null parameters. */
  EXPECT_ASSERT(buf_equal(NULL, &buf2));
  EXPECT_ASSERT(buf_equal(&buf1, NULL));
  /* Check buf_equal determines equality. */
  EXPECT_EQ(buf_copy(&buf2, &buf1), buf_ready(&buf2));
  EXPECT_TRUE(buf_equal(&buf1, &buf2)) << &buf1 << " vs. " << &buf2;
  buf1.offset = 1;
  EXPECT_FALSE(buf_equal(&buf1, &buf2)) << &buf1 << " vs. " << &buf2;
  buf1.offset = 0;
  EXPECT_TRUE(buf_equal(&buf1, &buf2)) << &buf1 << " vs. " << &buf2;
  buf1.raw[0] += 1;
  EXPECT_FALSE(buf_equal(&buf1, &buf2)) << &buf1 << " vs. " << &buf2;
  /* Check equality when neither buffer has data ready. */
  buf_reset(&buf1, 0);
  buf_reset(&buf2, buf_size(&buf2));
  EXPECT_TRUE(buf_equal(&buf1, &buf2)) << &buf1 << " vs. " << &buf2;
}

TEST_F(BufDeathTest, ZeroBuf) {
  /* Check null parameters. */
  EXPECT_ASSERT(buf_zero(NULL));
  /* Check if buffer is zeroed. */
  memset(buf2_.raw, 0x41, buf2_.max);
  buf_zero(&buf2_);
  EXPECT_EQ(buf2_.offset, 0U);
  EXPECT_EQ(buf2_.length, 0U);
  EXPECT_EQ(buf2_.max, 0x400U);
  size_t i = 0;
  for (; i < buf2_.max && buf2_.raw[i] == 0; ++i) {
  }
  EXPECT_EQ(i, buf2_.max);
}

TEST_F(BufDeathTest, FillBuf) {
  BUF buf = buf_init();
  /* Check null parameters and empty buffers. */
  EXPECT_ASSERT(buf_fill(NULL, 0x41));
  buf_fill(&buf, 0x41);
  /* Check if buffer's existing data is unchanged. */
  memset(buf2_.raw, 0x41, buf2_.max);
  buf2_.offset = buf2_.length;
  buf_fill(&buf2_, 0x42);
  EXPECT_EQ(buf2_.length, 0x400U);
  size_t i = 0;
  for (; i < buf2_.max && buf2_.raw[i] == 0x41; ++i) {
  }
  EXPECT_EQ(i, buf2_.offset);
  /* Check if buffer's available space was filled with the given value. */
  for (; i < buf2_.max && buf2_.raw[i] == 0x42; ++i) {
  }
  EXPECT_EQ(i, buf2_.max);
}

TEST_F(BufDeathTest, ExclusiveOrBuf) {
  BUF buf1 = buf_init();
  BUF buf2 = buf_init();
  BUF buf3 = buf_init();
  /* Check null parameters. */
  EXPECT_ASSERT(buf_xor(&buf1, NULL));
  EXPECT_ASSERT(buf_xor(NULL, &buf1));
  ASSERT_TRUE(buf_malloc(&buf1_, 0x800, &buf1));
  buf_fill(&buf1, 0x41);
  ASSERT_TRUE(buf_malloc(&buf1_, 0x400, &buf2));
  buf_fill(&buf2, 0x42);
  ASSERT_TRUE(buf_malloc(&buf1_, 0x400, &buf3));
  buf_fill(&buf3, 0x43);
  buf_xor(&buf1, &buf3);
  size_t i = 0;
  /* Check long buffer XOR'd onto a shorter one works. */
  for (; i < buf3.max && buf3.raw[i] == 0x02; ++i) {
  }
  EXPECT_EQ(i, buf3.max);
  /* Check short buffer XOR'd onto a longer one works. */
  buf2.offset = 0x200;
  buf_xor(&buf2, &buf3);
  for (i = 0; i < buf3.max && buf3.raw[i] == 0x40; ++i) {
  }
  EXPECT_EQ(i, buf2.length - buf2.offset);
  for (; i < buf3.max && buf3.raw[i] == 0x02; ++i) {
  }
  EXPECT_EQ(i, buf3.max);
}

TEST_F(BufDeathTest, CounterBuf) {
  /* Check null parameters and buffers without data ready. */
  EXPECT_ASSERT(buf_counter(NULL));
  buf_zero(&buf2_);
  buf2_.length = 2;
  buf2_.offset = buf2_.length;
  EXPECT_FALSE(buf_counter(&buf2_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrIntegerOverflow);
  /* Check that increment valid buffers correctly. */
  buf2_.length = 4;
  EXPECT_TRUE(buf_counter(&buf2_));
  EXPECT_EQ(buf2_.offset, 2U);
  EXPECT_EQ(buf2_.length, 4U);
  EXPECT_EQ(buf2_.raw[2], 0U);
  EXPECT_EQ(buf2_.raw[3], 1U);
  /* Check that we detect overflows. */
  buf2_.raw[2] = 0xFF;
  buf2_.raw[3] = 0xFF;
  EXPECT_FALSE(buf_counter(&buf2_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrIntegerOverflow);
}

TEST_F(BufTest, ConvertAsciiToUnsigned) {
  BUF zeros = {NULL, (uint8_t *)"0000000000", 0, 10, 10, 0};
  BUF alpha = {NULL, (uint8_t *)"1deadbeef0", 0, 10, 10, 0};
  BUF twopi = {NULL, (uint8_t *)"6283185307", 0, 10, 10, 0};
  BUF nines = {NULL, (uint8_t *)"9999999999", 0, 10, 10, 0};
  uint32_t out;
  /* Check null and invalid parameters. */
  EXPECT_ASSERT(buf_atou(NULL, 1, &out));
  EXPECT_ASSERT(buf_atou(&zeros, 1, NULL));
  EXPECT_ASSERT(buf_atou(&zeros, 0, &out));
  EXPECT_ASSERT(buf_atou(&zeros, 10, &out));
  /* Check valid numbers can be converted. */
  EXPECT_TRUE(buf_atou(&nines, 1, &out));
  EXPECT_EQ(out, 9U);
  EXPECT_TRUE(buf_atou(&zeros, 9, &out));
  EXPECT_EQ(out, 0U);
  EXPECT_TRUE(buf_atou(&twopi, 5, &out));
  EXPECT_EQ(out, 62831U);
  EXPECT_TRUE(buf_atou(&twopi, 5, &out));
  EXPECT_EQ(out, 85307U);
  /* Check the errors when out of data or non-numeric. */
  EXPECT_FALSE(buf_atou(&twopi, 1, &out));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfBounds);
  EXPECT_FALSE(buf_atou(&alpha, 3, &out));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrDecodeError);
}

TEST_F(BufDeathTest, CopyBuf) {
  /* C/R/A is consumed/ready/available. */
  BUF buf1 = buf_init();
  ASSERT_TRUE(buf_malloc(&buf1_, 8, &buf1));
  memcpy(buf1.raw, "CCRRAAAA", 8);
  buf1.offset = 2;
  buf1.length = 4;
  /* C/R/A is consumed/ready/available. */
  BUF buf2 = buf_init();
  ASSERT_TRUE(buf_malloc(&buf1_, 8, &buf2));
  memcpy(buf2.raw, "cccrraaa", 8);
  buf2.offset = 3;
  buf2.length = 5;
  /* Check null parameters. */
  EXPECT_ASSERT(buf_copy(&buf1, NULL));
  EXPECT_ASSERT(buf_copy(NULL, &buf1));
  /* Check that buf1's ready data was copied to buf2's available space. */
  EXPECT_EQ(buf_copy(&buf1, &buf2), 2U);
  EXPECT_EQ(memcmp(buf1.raw, "CCRRAAAA", 8), 0);
  EXPECT_EQ(memcmp(buf2.raw, "cccrrRRa", 8), 0);
  /* Check truncation when there's isn't enough space. */
  EXPECT_EQ(buf_copy(&buf1, &buf2), 1U);
  EXPECT_EQ(memcmp(buf1.raw, "CCRRAAAA", 8), 0);
  EXPECT_EQ(memcmp(buf2.raw, "cccrrRRR", 8), 0);
  /* Check copy when either buffer is unwrapped. */
  buf_free(&buf2);
  EXPECT_EQ(buf_copy(&buf1, &buf2), 0U);
  EXPECT_EQ(buf_copy(&buf2, &buf1), 0U);
}

TEST_F(BufDeathTest, MoveBuf) {
  BUF buf1 = buf_init();
  ASSERT_TRUE(buf_malloc(&buf1_, 8, &buf1));
  memcpy(buf1.raw, "deadbeef", 8);
  buf1.offset = 2;
  buf1.length = 4;
  BUF buf2 = buf_init();
  ASSERT_TRUE(buf_malloc(&buf1_, 8, &buf2));
  memcpy(buf2.raw, "feedface", 8);
  buf2.offset = 3;
  buf2.length = 5;
  /* Check null parameters. */
  EXPECT_ASSERT(buf_move(&buf1, NULL));
  EXPECT_ASSERT(buf_move(NULL, &buf1));
  /* Check failure when buf2 is allocated. */
  EXPECT_ASSERT(buf_move(&buf1, &buf2));
  buf_free(&buf2);
  /* Check that buf2 was completely replaced by buf1. */
  buf_move(&buf1, &buf2);
  EXPECT_EQ(memcmp(buf2.raw, "deadbeef", 8), 0);
  EXPECT_EQ(buf_consumed(&buf2), 2U);
  EXPECT_EQ(buf_ready(&buf2), 2U);
  EXPECT_EQ(buf_available(&buf2), 4U);
  EXPECT_EQ(buf_allocated(&buf1_), buf_size(&buf2));
  EXPECT_EQ(buf_size(&buf1), 0U);
  buf_free(&buf2);
  EXPECT_EQ(buf_allocated(&buf1_), 0U);
}

} /* namespace vapidssl */
