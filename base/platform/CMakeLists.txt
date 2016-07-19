# .../src/base/platform/CMakeLists.txt
# Builds object files for platform specific routines.
# TODO(aarongreen): Add more versions for different platforms and threading
# options.

add_subdirectory(test)

if(${THREAD})
  message(FATAL_ERROR "Thread support is not yet implemented.")
endif(${THREAD})

if (APPLE OR ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  add_library(
    base-platform

    OBJECT

#    lock_none.c
    thread_none.c
#    io_posix.c
#    random_posix.c
    time_posix.c
  )

else()
  message(FATAL_ERROR "Unsupported OS: " ${CMAKE_SYSTEM})

endif()
