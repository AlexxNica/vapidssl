# .../src/base/CMakeLists.txt
# Builds utility objects

add_library(
  base

  OBJECT

  buf.c
  error.c
  list.c
)

add_library(
  base-unittests

  OBJECT

  buf_unittest.cc
  error_unittest.cc
  list_unittest.cc

  error_test_helper.cc
  error_test_event_listener.cc
  scoped_buf.cc
)
