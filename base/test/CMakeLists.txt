# .../base/test/CMakeLists.txt
# Builds test framework objects

add_library(
  base-test

  OBJECT

  error_test_helper.cc
  error_listener.cc
  scoped_buf.cc
)
