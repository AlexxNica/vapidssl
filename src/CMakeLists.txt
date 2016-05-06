# .../src/CMakeLists.txt
# Builds core VapidSSL library, libvapid.a
# TODO(aarongreen): Add more conditionals to allow compiling against other
# platforms, protocols, and crypto libraries.

add_subdirectory(base)
add_subdirectory(base/arch)
#add_subdirectory(common)
#add_subdirectory(crypto)
#add_subdirectory(tls1_2)
#add_subdirectory(x509v3)

add_library(
  vapid-core

  $<TARGET_OBJECTS:base>
#  $<TARGET_OBJECTS:common>
#  $<TARGET_OBJECTS:crypto-generic>
)

#add_library(
#  vapid
#
#  $<TARGET_OBJECTS:arch>
#)
#target_link_libraries(vapid crypto-specific)

add_executable(
  vapid_test

  test/unittest_main.cc
  $<TARGET_OBJECTS:arch-test-generic>
  $<TARGET_OBJECTS:arch-test-specific>
  $<TARGET_OBJECTS:base-unittests>
  #$<TARGET_OBJECTS:common-unittests>
  #$<TARGET_OBJECTS:crypto-unittests-generic>
)
target_link_libraries(vapid_test vapid-core gtest)
set_target_properties(vapid_test PROPERTIES COMPILE_FLAGS "${cxx_default} -g")
add_test(NAME vapid_test COMMAND vapid_test --base_dir=${PROJECT_SOURCE_DIR})
