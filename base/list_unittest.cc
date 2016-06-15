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

#include "base/list.h"
#include "base/list_internal.h"

#include <stddef.h>
#include <stdint.h>

#include "base/buf.h"
#include "base/error.h"
#include "base/test/scoped_buf.h"
#include "public/error.h"
#include "test/macros.h"
#include "third_party/gtest/googletest/include/gtest/gtest.h"

namespace vapidssl {

class ListTest : public ::testing::Test {
 protected:
  ListTest() : region_(), list_(), max_(8), ignored_(nullptr) {}

  virtual void SetUp() {
    region_.Reset(sizeof(BUF) * max_);
  }

  // region_ wraps the memory that other BUFs will be allocated from.
  ScopedBuf region_;
  // list_ represents the data under test.
  LIST list_;
  // max_ is the maximum number of elements in |list_|.
  size_t max_;
  // ignored_ is used to suppress warnings caused by |LIST_*| return values
  // being ignored when in an |EXPECT_ASSERT|. */
  void *ignored_;
};

typedef ListTest ListDeathTest;

TEST_F(ListDeathTest, NewWithOverflow) {
  // Bypass macro to fake a huge elem_size.
  EXPECT_ASSERT(list_new(region_.Get(), (size_t)-1, 0xFF, &list_));
}

TEST_F(ListTest, NewWithInsufficentMemory) {
  EXPECT_EQ(LIST_SIZE(uint16_t, 0), 0U);
  EXPECT_EQ(LIST_SIZE(size_t, 1), sizeof(size_t));
  region_.Reset(LIST_SIZE(BUF, max_) - 1);
  EXPECT_FALSE(LIST_NEW(BUF, region_.Get(), max_, &list_));
  EXPECT_ERROR(kTlsErrVapid, kTlsErrOutOfMemory);
}

TEST_F(ListDeathTest, ListIsNull) {
  EXPECT_ASSERT(LIST_NEW(BUF, region_.Get(), max_, nullptr));
  EXPECT_ASSERT(ignored_ = LIST_GET(BUF, nullptr, 0));
  EXPECT_ASSERT(ignored_ = LIST_GET(BUF, nullptr, 0));
  EXPECT_ASSERT(ignored_ = LIST_ADD(BUF, nullptr));
  EXPECT_ASSERT(ignored_ = LIST_ADD(BUF, nullptr));
  EXPECT_ASSERT(LIST_DEL_FRONT(BUF, nullptr));
  EXPECT_ASSERT(LIST_DEL(BUF, nullptr));
  EXPECT_ASSERT(ignored_ = LIST_BEGIN(BUF, nullptr));
  EXPECT_ASSERT(ignored_ = LIST_ITER(BUF, nullptr));
  EXPECT_ASSERT(ignored_ = LIST_NEXT(BUF, nullptr));
  EXPECT_ASSERT(LIST_LEN(BUF, nullptr));
  EXPECT_ASSERT(LIST_SWAP(BUF, nullptr, 0, 0));
}

TEST_F(ListDeathTest, WrongType) {
  EXPECT_TRUE(LIST_NEW(BUF, region_.Get(), max_, &list_));
  EXPECT_ASSERT(ignored_ = LIST_GET(size_t, &list_, 0));
  EXPECT_ASSERT(ignored_ = LIST_GET(uint16_t, &list_, 0));
  EXPECT_ASSERT(ignored_ = LIST_ADD_FRONT(LIST, &list_));
  EXPECT_ASSERT(ignored_ = LIST_ADD(size_t, &list_));
  EXPECT_ASSERT(LIST_DEL_FRONT(uint16_t, &list_));
  EXPECT_ASSERT(LIST_DEL(LIST, &list_));
  EXPECT_ASSERT(ignored_ = LIST_BEGIN(size_t, &list_));
  EXPECT_ASSERT(ignored_ = LIST_ITER(uint16_t, nullptr));
  EXPECT_ASSERT(ignored_ = LIST_NEXT(LIST, &list_));
  EXPECT_ASSERT(LIST_LEN(size_t, &list_));
  EXPECT_ASSERT(LIST_SWAP(uint16_t, &list_, 0, 0));
}

TEST_F(ListTest, GetWhenEmpty) {
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  EXPECT_EQ(LIST_LEN(size_t, &list_), 0U);
  EXPECT_EQ(LIST_GET(size_t, &list_, 0), nullptr);
  EXPECT_EQ(LIST_GET(size_t, &list_, max_ - 1), nullptr);
}

TEST_F(ListDeathTest, DeleteWhenEmpty) {
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  EXPECT_EQ(LIST_LEN(size_t, &list_), 0U);
  EXPECT_ASSERT(LIST_DEL_FRONT(size_t, &list_));
  EXPECT_ASSERT(LIST_DEL(size_t, &list_));
}

TEST_F(ListTest, AddWhenFull) {
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  for (size_t i = 0; i < max_; ++i) {
    LIST_ADD(size_t, &list_);
  }
  EXPECT_EQ(LIST_LEN(size_t, &list_), max_);
  EXPECT_EQ(LIST_ADD_FRONT(size_t, &list_), nullptr);
  EXPECT_EQ(LIST_ADD(size_t, &list_), nullptr);
}

TEST_F(ListTest, NextWhenEmptyOrNotIterating) {
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  EXPECT_EQ(LIST_LEN(size_t, &list_), 0U);
  EXPECT_EQ(LIST_NEXT(size_t, &list_), nullptr);
  LIST_BEGIN(size_t, &list_);
  EXPECT_EQ(LIST_NEXT(size_t, &list_), nullptr);
}

TEST_F(ListTest, IterateWhenPartiallyFilled) {
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  size_t *val = nullptr;
  for (size_t i = 0; i < max_ / 2; ++i) {
    val = LIST_ADD(size_t, &list_);
    *val = i;
  }
  EXPECT_EQ(LIST_LEN(size_t, &list_), max_ / 2);
  LIST_BEGIN(size_t, &list_);
  for (size_t i = 0; i < max_ / 2; ++i) {
    val = LIST_ITER(size_t, &list_);
    EXPECT_EQ(val, LIST_ITER(size_t, &list_));
    EXPECT_EQ(*val, i);
    LIST_NEXT(size_t, &list_);
  }
  EXPECT_EQ(LIST_NEXT(size_t, &list_), nullptr);
}

TEST_F(ListTest, IterateWhenFull) {
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  size_t *val = nullptr;
  for (size_t i = 0; i < max_; ++i) {
    val = LIST_ADD(size_t, &list_);
    *val = i;
  }
  EXPECT_EQ(LIST_LEN(size_t, &list_), max_);
  LIST_BEGIN(size_t, &list_);
  for (size_t i = 0; i < max_; ++i) {
    val = LIST_ITER(size_t, &list_);
    EXPECT_EQ(val, LIST_ITER(size_t, &list_));
    EXPECT_EQ(*val, i);
    LIST_NEXT(size_t, &list_);
  }
  EXPECT_EQ(LIST_NEXT(size_t, &list_), nullptr);
}

TEST_F(ListTest, AddWhileIterating) {
  ASSERT_GT(max_, 2U);
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  size_t *val = nullptr;
  for (size_t i = 0; i < max_ / 2; ++i) {
    val = LIST_ADD(size_t, &list_);
    *val = i;
  }
  LIST_BEGIN(size_t, &list_);
  EXPECT_NE(LIST_NEXT(size_t, &list_), nullptr);
  LIST_ADD(size_t, &list_);
  EXPECT_EQ(LIST_LEN(size_t, &list_), max_ / 2 + 1);
  EXPECT_EQ(LIST_NEXT(size_t, &list_), nullptr);
}

TEST_F(ListTest, DeleteWhileIterating) {
  ASSERT_GT(max_, 5U);
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  size_t *val = nullptr;
  for (size_t i = 0; i < max_ / 2; ++i) {
    val = LIST_ADD(size_t, &list_);
    *val = i;
  }
  LIST_BEGIN(size_t, &list_);
  EXPECT_NE(LIST_NEXT(size_t, &list_), nullptr);
  LIST_DEL(size_t, &list_);
  EXPECT_EQ(LIST_LEN(size_t, &list_), max_ / 2 - 1);
  EXPECT_EQ(LIST_NEXT(size_t, &list_), nullptr);
}

TEST_F(ListTest, AddAndDelete) {
  ASSERT_GT(max_, 1U);
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  size_t *val = nullptr;
  size_t j = 0;
  size_t k = 0;
  size_t l = 0;
  // Add to front.
  for (size_t i = 0; i < max_; ++i) {
    val = LIST_ADD_FRONT(size_t, &list_);
    *val = j++;
  }
  EXPECT_EQ(LIST_LEN(size_t, &list_), max_);
  // Sequence should be decreasing.
  l = k = j;
  val = LIST_BEGIN(size_t, &list_);
  for (size_t i = 0; i < max_; ++i) {
    k--;
    EXPECT_NE(val, nullptr);
    EXPECT_EQ(*val, k);
    val = LIST_NEXT(size_t, &list_);
  }
  // Delete from back.
  for (size_t i = 0; i < max_ / 2; ++i) {
    LIST_DEL(size_t, &list_);
  }
  EXPECT_EQ(LIST_LEN(size_t, &list_), max_ / 2);
  // Sequence should be truncated and decreasing.
  k = l;
  val = LIST_BEGIN(size_t, &list_);
  for (size_t i = 0; i < max_ / 2; ++i) {
    k--;
    EXPECT_NE(val, nullptr);
    EXPECT_EQ(*val, k);
    val = LIST_NEXT(size_t, &list_);
  }
  EXPECT_EQ(LIST_NEXT(size_t, &list_), nullptr);
  // Add to back.
  for (size_t i = 0; i < max_ / 2; ++i) {
    val = LIST_ADD(size_t, &list_);
    *val = j++;
  }
  EXPECT_EQ(LIST_LEN(size_t, &list_), max_);
  // Sequence should be in half decreasing, half increasing.
  k = l;
  val = LIST_BEGIN(size_t, &list_);
  for (size_t i = 0; i < max_ / 2; ++i) {
    k--;
    EXPECT_NE(val, nullptr);
    EXPECT_EQ(*val, k);
    val = LIST_NEXT(size_t, &list_);
  }
  k = l;
  for (size_t i = 0; i < max_ / 2; ++i) {
    EXPECT_NE(val, nullptr);
    EXPECT_EQ(*val, k);
    k++;
    val = LIST_NEXT(size_t, &list_);
  }
  // Delete from front.
  for (size_t i = 0; i < max_ / 2; ++i) {
    LIST_DEL_FRONT(size_t, &list_);
  }
  EXPECT_EQ(LIST_LEN(size_t, &list_), max_ / 2);
  // Sequence should be increasing.
  k = l;
  val = LIST_BEGIN(size_t, &list_);
  for (size_t i = 0; i < max_ / 2; ++i) {
    EXPECT_NE(val, nullptr);
    EXPECT_EQ(*val, k);
    k++;
    val = LIST_NEXT(size_t, &list_);
  }
  EXPECT_EQ(LIST_NEXT(size_t, &list_), nullptr);
}

TEST_F(ListTest, SwapOutOfBounds) {
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  LIST_ADD(size_t, &list_);
  size_t val = 0xdeadbeef;
  size_t *ptr = LIST_GET(size_t, &list_, 0);
  *ptr = val;
  EXPECT_ASSERT(LIST_SWAP(size_t, &list_, 0, 1));
  EXPECT_ASSERT(LIST_SWAP(size_t, &list_, 1, 0));
}

TEST_F(ListTest, SwapSameElement) {
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  size_t *ptr = LIST_ADD(size_t, &list_);
  size_t val = 0xdeadbeef;
  *ptr = val;
  LIST_SWAP(size_t, &list_, 0, 0);
  ptr = LIST_GET(size_t, &list_, 0);
  EXPECT_EQ(*ptr, val);
}

TEST_F(ListTest, SwapDistinct) {
  ASSERT_GT(max_, 3U);
  EXPECT_TRUE(LIST_NEW(size_t, region_.Get(), max_, &list_));
  size_t *val = nullptr;
  for (size_t i = 0; i < max_; ++i) {
    val = LIST_ADD(size_t, &list_);
    *val = i;
  }
  LIST_SWAP(size_t, &list_, 1, max_ - 2);
  val = LIST_GET(size_t, &list_, 1);
  EXPECT_EQ(*val, max_ - 2);
  val = LIST_GET(size_t, &list_, max_ - 2);
  EXPECT_EQ(*val, 1U);
}

}  // namespace vapidssl
