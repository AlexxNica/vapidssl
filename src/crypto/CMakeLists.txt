# .../src/crypto/CMakeLists.txt
# Builds object files for crypto adapters.
# TODO(aarongreen): Add more versions for different crypto implementations.

add_library(
  crypto-generic

  OBJECT

  aead.c
  crypto.c
  hash.c
  keyx.c
  sign.c
)

add_library(
  crypto-unittests-generic

  OBJECT

  aead_unittest.cc
  hash_unittest.cc
  keyx_unittest.cc
  sign_unittest.cc
)

if(${CRYPTO} STREQUAL "boringssl")
add_library(
  crypto-specific

  aead_boringssl.c
  crypto_boringssl.c
  hash_boringssl.c
  keyx_boringssl.c
  sign_boringssl.c
)
target_link_libraries(crypto-specific crypto)

add_library(
  crypto-unittests-specific

  ${BORINGSSL_ROOT}/crypto/test/file_test.cc
)
target_link_libraries(crypto-unittests-specific crypto)
else()
message(FATAL_ERROR "Unsupported CRYPTO: " ${CRYPTO})
endif()
