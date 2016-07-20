# .../common/test/CMakeLists.txt
# Builds object files for testing code common to all protocols.

add_library(
  common-test

  OBJECT

  chunk_test.cc
  #state_helper.cc
  #stream_helper.cc
)
