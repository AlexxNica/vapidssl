# .../src/crypto/CMakeLists.txt
# Builds object files for crypto adapters.
# TODO(aarongreen): Add more versions for different crypto implementations.

# Tests are generic, as their correctness should not depend on the specific
# crypto implementation.
#add_gtest(aead_test)
#add_gtest(hash_test)
#add_gtest(keyx_test)
#add_gtest(sign_test)

################################################################################
### crypto-boringssl ###
# Linux version of the library that doesn't use threads.
# TODO(aarongreen): Enable this once we're ready to build samples under
# examples/.
add_library(
  crypto-boringssl

  OBJECT

#  boringssl/aead.c
#  boringssl/hash.c
#  boringssl/keyx.c
#  boringssl/sign.c
)

