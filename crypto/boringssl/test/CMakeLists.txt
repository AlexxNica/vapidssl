# .../crypto/boringssl/test/CMakeLists.txt
# Builds object files for BoringSSL adapter.

add_library(
  crypto-tests-specific

  OBJECT

  boringssl_helper.cc
  crypto_test_boringssl.cc
  ${BORINGSSL_ROOT}/crypto/test/file_test.cc
)
