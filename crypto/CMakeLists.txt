# .../crypto/CMakeLists.txt
# Builds object files for crypto adapters.

add_subdirectory(test)

add_library(
  crypto-generic

  OBJECT

  crypto.c
  aead.c
  hash.c
  keyex.c
  #sign.c
)

add_library(
  vapid-crypto

  $<TARGET_OBJECTS:crypto-generic>
  $<TARGET_OBJECTS:crypto-specific>
)

add_library(
  crypto-unittests

  OBJECT

  aead_unittest.cc
  hash_unittest.cc
  keyex_unittest.cc
#  sign_unittest.cc
)

if(${CRYPTO} STREQUAL "boringssl")
  add_subdirectory(boringssl)
  target_link_libraries(vapid-crypto crypto)
else()
  message(FATAL_ERROR "Unsupported CRYPTO: " ${CRYPTO})
endif()

