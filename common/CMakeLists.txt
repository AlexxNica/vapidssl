# .../common/CMakeLists.txt
# Builds object files common to all protocols.

add_subdirectory(test)

add_library(
  common

  OBJECT

  chunk.c
  hmac.c
)

add_library(
  common-unittests

  OBJECT

  chunk_unittest.cc
  hmac_unittest.cc
  #stream_unittest.cc
)
