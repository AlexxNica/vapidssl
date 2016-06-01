# .../crypto/boringssl/CMakeLists.txt
# Builds object files for BoringSSL adapter.

add_library(
  vapid-crypto-specific

  OBJECT

  aead_boringssl.c
  crypto_boringssl.c
  hash_boringssl.c
  keyx_boringssl.c
  sign_boringssl.c
)

add_library(
  vapid-crypto-unittests-specific

  OBJECT

  boringssl_test_helper.cc
  crypto_test_boringssl.cc
  ${BORINGSSL_ROOT}/crypto/test/file_test.cc
)
