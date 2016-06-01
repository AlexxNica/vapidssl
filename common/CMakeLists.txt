# .../common/CMakeLists.txt
# Builds object files common to all protocols.

add_library(
  common

  OBJECT

  chunk.c
  stream.c
)

add_library(
  common-unittests

  OBJECT

  chunk_unittest.cc
  stream_unittest.cc
)
