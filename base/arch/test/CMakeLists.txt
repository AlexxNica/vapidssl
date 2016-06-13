# .../base/arch/test/CMakeLists.txt
# Builds test object files for platform specific routines.

add_library(
  arch-test-generic

  OBJECT

#  ../lock_none.c
  ../thread_none.c
#  io_mock.c
  random_fake.c
  arch_helper.cc
)
