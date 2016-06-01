# .../base/CMakeLists.txt
# Build utility objects

add_subdirectory(arch)
add_subdirectory(test)

add_library(
  base

  OBJECT

  buf.c
  error.c
#  list.c
)

add_library(
  base-unittests

  OBJECT

  buf_unittest.cc
  error_unittest.cc
#  list_unittest.cc
)
