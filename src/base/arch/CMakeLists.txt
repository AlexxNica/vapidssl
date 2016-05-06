# .../src/base/arch/CMakeLists.txt
# Builds object files for platform specific routines.
# TODO(aarongreen): Add more versions for different platforms and threading
# options.

add_library(
  arch-test-generic

  OBJECT

#  io_mock.c
#  lock_none.c
  rand_fake.c
  thread_none.c

  arch_test_helper.cc
)

if(${ARCH} STREQUAL "linux")
  if(${THREAD})
    message(FATAL_ERROR "Thread support is not yet implemented.")

  else(${THREAD})
    #add_library(
    #  arch-linux-none
    #
    #  OBJECT
    #
    #  io_linux.c
    #  lock_none.c
    #  rand_linux.c
    #  thread_none.c
    #)

    add_library(
      arch-test-specific

      OBJECT

      arch_test_helper_linux.cc
    )
  endif(${THREAD})

else()
  message(FATAL_ERROR "Unsupported ARCH: " ${ARCH})

endif()
