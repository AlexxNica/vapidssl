# .../CMakeLists.txt
# CMake files for VapidSSL, see BUILDING.md for instructions.

cmake_minimum_required (VERSION 2.8.10)

project (VapidSSL NONE)

enable_language(C)
enable_language(CXX)
enable_testing()

set(ARCH "linux")
set(CRYPTO "boringssl")
option(THREADS "Build with threading support" OFF)

################################################################################
### BoringSSL ###
# TODO(aarongreen): Add conditionals to allow compiling against other crypto
# libs.

set(BORINGSSL_ROOT ${PROJECT_SOURCE_DIR}/third_party/boringssl)
set(LIBCRYPTO_BUILD_DIR ${BORINGSSL_ROOT}/build)
include_directories(${BORINGSSL_ROOT}/include)
add_library(crypto STATIC IMPORTED)
set_property(TARGET crypto PROPERTY IMPORTED_LOCATION ${LIBCRYPTO_BUILD_DIR}/crypto/libcrypto.a)

if(${THREAD})
  set(BORINGSSL_CMAKE_C_FLAGS "-DOPENSSL_SMALL")
else(${THREAD})
  set(BORINGSSL_CMAKE_C_FLAGS "-DOPENSSL_NO_THREADS -DOPENSSL_SMALL")
endif(${THREAD})

add_custom_target(rebuild-boringssl
  COMMAND rm -rf ${LIBCRYPTO_BUILD_DIR}
  COMMAND mkdir ${LIBCRYPTO_BUILD_DIR}
  COMMAND cd ${LIBCRYPTO_BUILD_DIR}
  COMMAND ${CMAKE_COMMAND} -GNinja ${BORINGSSL_ROOT} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_C_FLAGS="${BORINGSSL_CMAKE_C_FLAGS}"
  COMMAND ninja
  WORKING_DIRECTORY ${BORINGSSL_ROOT})

################################################################################
### Google Test ###

set(GOOGLETEST_ROOT ${PROJECT_SOURCE_DIR}/third_party/gtest/googletest)
set(LIBGTEST_BUILD_DIR ${GOOGLETEST_ROOT}/build)
include(${GOOGLETEST_ROOT}/cmake/internal_utils.cmake)
config_compiler_and_linker()
include_directories(${GOOGLETEST_ROOT}/include)
add_library(gtest STATIC IMPORTED)
set_property(TARGET gtest PROPERTY IMPORTED_LOCATION ${LIBGTEST_BUILD_DIR}/libgtest.a)
add_library(gtest_main STATIC IMPORTED)
set_property(TARGET gtest_main PROPERTY IMPORTED_LOCATION ${LIBGTEST_BUILD_DIR}/libgtest_main.a)

# Setting the 'gtest_disable_pthreads' options breaks more than a third of
# gtest's self-tests and our unit tests!
#if(${THREAD})
#  set(GTEST_OPTIONS "")
#else(${THREAD})
#  set(GTEST_OPTIONS "-Dgtest_disable_pthreads=ON")
#endif(${THREAD})

add_custom_target(rebuild-googletest
  COMMAND rm -rf ${LIBGTEST_BUILD_DIR}
  COMMAND mkdir ${LIBGTEST_BUILD_DIR}
  COMMAND cd ${LIBGTEST_BUILD_DIR}
  COMMAND ${CMAKE_COMMAND} -GNinja ${GOOGLETEST_ROOT} ${GTEST_OPTIONS}
  COMMAND ninja
  WORKING_DIRECTORY ${GOOGLETEST_ROOT})

################################################################################
### VapidSSL ###
# Builds core VapidSSL library, libvapid.a

set(C_CXX_FLAGS "-Wall -Werror -Wformat=2 -Wsign-compare -Wmissing-field-initializers -ggdb -fvisibility=hidden")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_CXX_FLAGS} -std=c11 -Wmissing-prototypes -Wshadow")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ${C_CXX_FLAGS} -Wshadow -fno-exceptions")

include_directories(.)

add_subdirectory(base)
#add_subdirectory(crypto)
#add_subdirectory(common)
#add_subdirectory(x509v3)
#add_subdirectory(tls1_2)

add_library(
  vapid-core

  $<TARGET_OBJECTS:base>
#  $<TARGET_OBJECTS:common>
#  $<TARGET_OBJECTS:x509v3>
#  $<TARGET_OBJECTS:tls1_2>
)

add_library(
  vapid

  $<TARGET_OBJECTS:arch>
)
#target_link_libraries(vapid vapid-core vapid-crypto)

add_executable(
  vapid_test

  test/unittest_main.cc
  $<TARGET_OBJECTS:base-test>
  $<TARGET_OBJECTS:arch-test-generic>
  $<TARGET_OBJECTS:arch-test-specific>

  $<TARGET_OBJECTS:base-unittests>
#  $<TARGET_OBJECTS:vapid-crypto-unittests-generic>
#  #$<TARGET_OBJECTS:vapid-crypto-unittests-specific>
#  $<TARGET_OBJECTS:common-unittests>
#  $<TARGET_OBJECTS:x509v3-unittests>
#  $<TARGET_OBJECTS:tls1_2-unittests>
)
# See parent CMakeList.txt for why gtest requires pthread.
target_link_libraries(vapid_test vapid-core gtest pthread)
#target_link_libraries(vapid_test vapid-core vapid-crypto-unittests gtest pthread)
set_target_properties(vapid_test PROPERTIES COMPILE_FLAGS "${cxx_default} -g")
add_test(NAME vapid_test COMMAND vapid_test --base_dir=${PROJECT_SOURCE_DIR})

# TODO(aarongreen: Enable stripping and/or and packing to reduce file sizes.
# Some ideas:
#  * http://codereview.stackexchange.com/questions/103972
#     strip -s -R .note.gnu.gold-version -R .comment -R .note \
#     -R .note.gnu.build-id -R .note.ABI-tag ${name})
#  * upx.sourceforge.net
#     upx --ultra-brute examples/client-small
#function(strip_and_pack name)
#  add_custom_command(TARGET ${name}
#    POST_BUILD
#    COMMAND strip -s -R .note.gnu.gold-version -R .comment -R .note -R .note.gnu.build-id -R .note.ABI-tag ${name})
#endfunction()

################################################################################
### VapidSSL Examples ###

#add_subdirectory(examples)
