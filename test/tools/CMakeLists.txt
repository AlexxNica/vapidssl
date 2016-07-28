# .../test/tools/CMakeLists.txt
# CMake files test data generation code

add_library(ssl STATIC IMPORTED)
set_property(TARGET ssl PROPERTY IMPORTED_LOCATION ${LIBCRYPTO_BUILD_DIR}/ssl/libssl.a)

add_executable(
  generate_prf_test_data

  ${CMAKE_SOURCE_DIR}/base/platform/test/random_fake.c
  ${CMAKE_SOURCE_DIR}/base/platform/thread_none.c
  ${CMAKE_SOURCE_DIR}/base/test/scoped_buf.cc

  generate_prf_test_data.cc

)
target_link_libraries(generate_prf_test_data vapid-test ssl)
set_target_properties(generate_prf_test_data PROPERTIES COMPILE_FLAGS "-g")
