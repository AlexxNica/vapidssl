# .../crypto/test/CMakeLists.txt
# Builds object files for testing the crypto adapters.

add_library(
  crypto-tests-generic

  OBJECT

  #aead_test.cc
  crypto_test.cc
  #hash_test.cc
)
