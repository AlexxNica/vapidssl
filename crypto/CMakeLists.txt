# .../crypto/CMakeLists.txt
# Builds object files for crypto adapters.

add_library(
  vapid-crypto-generic

  OBJECT

  crypto.c
  aead.c
  hash.c
  keyx.c
  sign.c
)

add_library(
  vapid-crypto-unittests-generic

  OBJECT

  crypto_test.cc
  aead_test.cc
  hash_test.cc
  aead_unittest.cc
  hash_unittest.cc
  keyx_unittest.cc
  sign_unittest.cc
)

if(${CRYPTO} STREQUAL "boringssl")
  add_subdirectory(boringssl)

  add_library(
    vapid-crypto

    $<TARGET_OBJECTS:vapid-crypto-generic>
    $<TARGET_OBJECTS:vapid-crypto-specific>
  )
  target_link_libraries(vapid-crypto crypto)

  add_library(
    vapid-crypto-unittests

    $<TARGET_OBJECTS:vapid-crypto-unittests-generic>
    $<TARGET_OBJECTS:vapid-crypto-unittests-specific>
  )
  target_link_libraries(vapid-crypto-unittests vapid-crypto)
else()
  message(FATAL_ERROR "Unsupported CRYPTO: " ${CRYPTO})
endif()
