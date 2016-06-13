# .../base/arch/linux/test/CMakeLists.txt
# Builds test helpers for Linux specific routines.

add_library(
  arch-test-specific

  OBJECT

  arch_helper_linux.cc
)
