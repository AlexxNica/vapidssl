# .../src/tls1_2/CMakeLists.txt
# Builds object files for TLS 1.2.

add_subdirectory(test)

add_library(
  tls1_2

  OBJECT

  ciphersuite.c
  config.c
  #extension.c
  #handshake.c
  message.c
  prf.c
  record.c
  ticket.c
  tls.c
)

add_library(
  tls1_2-unittests

  OBJECT

  #extension_unittest.cc
  #handshake_unittest.cc
  message_unittest.cc
  prf_unittest.cc
  record_unittest.cc
)
