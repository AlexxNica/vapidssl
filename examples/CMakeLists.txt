add_executable(
  client

  client.cc
  client_main.cc
  ${BORINGSSL_ROOT}/crypto/test/file_test.cc
)
target_link_libraries(client vapid)


