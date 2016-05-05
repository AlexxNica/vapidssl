# .../src/CMakeLists.txt
# Builds core VapidSSL library, libvapid.a

add_subdirectory(arch)
#add_subdirectory(crypto)

################################################################################
### vapid-common ###
# Code common to release and test configurations.
add_library(
  vapid-internal

  OBJECT

#  asn1.c
#  buf.c
#  certificate.c
#  ciphersuite.c
#  config.c
  error.c
#  extension.c
#  handshake.c
#  message.c
#  multihash.c
#  prf.c
#  record.c
#  tls.c
)

################################################################################
### vapid ###
# Release version of the library
# TODO(aarongreen): Enable this once we're ready to build samples under
# examples/.  Add conditionals to select proper arch for the platform and
# threading options, and the proper crypto implementation.
#add_library(
#  vapid
#
#  $<TARGET_OBJECTS:arch>
#  $<TARGET_OBJECTS:crypto-boringssl>
#  $<TARGET_OBJECTS:vapid-internal>
#)
# TODO(aarongreen): Add conditionals to allow compiling against other crypto
# libs.
#target_link_libraries(vapid crypto)

################################################################################
### vapid-test ###
# Test version of the library; includes some mocks and fakes for the platform-
# specific and non-deterministic pieces.
# TODO(aarongreen): Add conditionals to allow compiling against other crypto
# libs.
add_library(
  vapid-test

  $<TARGET_OBJECTS:arch-test>
#  $<TARGET_OBJECTS:crypto-boringssl>
  $<TARGET_OBJECTS:vapid-internal>
)
# TODO(aarongreen): Add conditionals to allow compiling against other crypto
# libs.
target_link_libraries(vapid-test crypto)

#add_gtest(asn1_test)
#add_gtest(buf_test)
#add_gtest(certificate_test)
#add_gtest(ciphersuite_test)
#add_gtest(config_test)
add_gtest(error_test)
#add_gtest(extension_test)
#add_gtest(handshake_test)
#add_gtest(message_test)
#add_gtest(multihash_test)
#add_gtest(prf_test)
#add_gtest(record_test)
#add_gtest(tls_test)

# TODO(aarongreen): Replace the individual tests with this code once they're all
# implemented.
#file(GLOB_RECURSE UNITTESTS "${CMAKE_CURRENT_SOURCE_DIR}" "*_test.cc")
#foreach(UNITTEST ${UNITTESTS})
#  get_filename_component(TESTNAME ${UNITTEST} NAME_WE)
#  add_gtest(${TESTNAME} ${TESTNAME})
#endforeach()
