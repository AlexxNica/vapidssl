# .../base/platform/CMakeLists.txt
# Builds test object files for platform specific routines.

add_library(
  base-platform-test-generic

  OBJECT

  #../lock_none.c
  ../thread_none.c
  #io_mock.c
  platform_helper.cc
  random_fake.c
  #time_fake.c
)


if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  add_library(
    base-platform-test-specific

    OBJECT

    platform_helper_linux.cc
    platform_helper_posix.cc
  )

else()
  message(FATAL_ERROR "Unsupported OS: " ${CMAKE_SYSTEM})

endif()


