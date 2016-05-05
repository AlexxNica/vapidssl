# .../CMakeLists.txt
# CMake files for VapidSSL, see BUILDING.md for instructions.

cmake_minimum_required (VERSION 2.8.10)

project (VapidSSL NONE)

enable_language(C)
enable_language(CXX)
enable_testing()

################################################################################
### BoringSSL ###
# TODO(aarongreen): Add conditionals to allow compiling against other crypto
# libs.

set(BORINGSSL_ROOT ${PROJECT_SOURCE_DIR}/third_party/boringssl)
set(LIBCRYPTO_BUILD_DIR ${BORINGSSL_ROOT}/build)
include_directories(${BORINGSSL_ROOT}/include)
add_library(crypto STATIC IMPORTED)
set_property(TARGET crypto PROPERTY IMPORTED_LOCATION ${LIBCRYPTO_BUILD_DIR}/crypto/libcrypto.a)
add_custom_target(rebuild-boringssl
  COMMAND rm -rf ${LIBCRYPTO_BUILD_DIR}
  COMMAND mkdir ${LIBCRYPTO_BUILD_DIR}
  COMMAND cd ${LIBCRYPTO_BUILD_DIR}
  COMMAND ${CMAKE_COMMAND} -GNinja ${BORINGSSL_ROOT} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_C_FLAGS="-DOPENSSL_NO_THREADS -DOPENSSL_SMALL"
  COMMAND ninja
  WORKING_DIRECTORY ${BORINGSSL_ROOT})

################################################################################
### Googletest ###

set(GOOGLETEST_ROOT ${PROJECT_SOURCE_DIR}/third_party/gtest/googletest)
set(LIBGTEST_BUILD_DIR ${GOOGLETEST_ROOT}/build)
include(${GOOGLETEST_ROOT}/cmake/internal_utils.cmake)
config_compiler_and_linker()
include_directories(${GOOGLETEST_ROOT}/include)
add_library(gtest STATIC IMPORTED)
set_property(TARGET gtest PROPERTY IMPORTED_LOCATION ${LIBGTEST_BUILD_DIR}/libgtest.a)
add_library(gtest_main STATIC IMPORTED)
set_property(TARGET gtest_main PROPERTY IMPORTED_LOCATION ${LIBGTEST_BUILD_DIR}/libgtest_main.a)
add_custom_target(rebuild-googletest
  COMMAND rm -rf ${LIBGTEST_BUILD_DIR}
  COMMAND mkdir ${LIBGTEST_BUILD_DIR}
  COMMAND cd ${LIBGTEST_BUILD_DIR}
  COMMAND ${CMAKE_COMMAND} -GNinja ${GOOGLETEST_ROOT}
  COMMAND ninja
  WORKING_DIRECTORY ${GOOGLETEST_ROOT})

# Replacement for cxx_executable in googletest's internal_utils.cmake
# That function did not link both gtest and gtest_main, assuming the top-level
# CMakeList would do it.  Since we're not using that, we need to tweak it here
function(add_gtest name)
  add_executable(${name} ${name}.cc)
  set_target_properties(${name} PROPERTIES COMPILE_FLAGS "${cxx_default} -g")
  target_link_libraries(${name} vapid-test crypto gtest_main gtest pthread)
  add_test(${name} ${name})
endfunction()

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

set(C_CXX_FLAGS "-Wall -Werror -Wformat=2 -Wsign-compare -Wmissing-field-initializers -ggdb -fvisibility=hidden")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_CXX_FLAGS} -std=c11 -Wmissing-prototypes -Wshadow")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x ${C_CXX_FLAGS} -Wmissing-declarations -Wshadow")

include_directories(include)
add_subdirectory(src)
#add_subdirectory(examples)
