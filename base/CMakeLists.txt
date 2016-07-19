# .../src/base/CMakeLists.txt
# Builds base framework objects

add_subdirectory(platform)
add_subdirectory(test)

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
)
