# .../src/arch/CMakeLists.txt
# Builds object files for platform specific routines.
# TODO(aarongreen): Add more versions for different platforms and threading
# options.

################################################################################
### arch-linux-nothreads ###
# Linux version of the library that doesn't use threads.
# TODO(aarongreen): Enable this once we're ready to build samples under
# examples/.
#add_library(
#  arch-linux-nothreads
#
#  OBJECT
#
#  io_linux.c
#  lock_none.c
#  rand_linux.c
#  thread_none.c
#)

################################################################################
### arch-test ###
# Test version of the objects; includes some mocks and fakes for the platform-
# specific and non-deterministic pieces.
add_library(
  arch-test

  OBJECT

#  io_test.c
#  lock_none.c
#  rand_test.c
  thread_none.c
)
