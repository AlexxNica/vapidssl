# .../crypto/boringssl/CMakeLists.txt
# Builds object files for BoringSSL adapter.

add_subdirectory(test)

add_library(
  crypto-specific

  OBJECT

  aead_boringssl.c
  crypto_boringssl.c
  hash_boringssl.c
  keyex_boringssl.c
  sign_boringssl.c
)
