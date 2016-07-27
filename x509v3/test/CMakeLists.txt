# .../x509v3/test/CMakeLists.txt
# Builds object files for testing code X.509v3 certificate parsing

add_library(
  x509v3-test

  OBJECT

  truststore_helper.cc
)
