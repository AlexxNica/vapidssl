add_executable(client-small client.c)
target_link_libraries(client-small vapid crypto)
set_target_properties(client-small PROPERTIES COMPILE_FLAGS "-DNDEBUG")
strip_and_pack(client-small)

add_executable(client client.c)
target_link_libraries(client vapid crypto)
