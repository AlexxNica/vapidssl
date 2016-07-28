# .../tls1_2/test/CMakeLists.txt
# Builds object files for testing code TLS 1.2 protocol code

add_library(
  tls1_2-test

  OBJECT

  config_helper.cc
  record_test.cc
  tls_helper.cc
)
