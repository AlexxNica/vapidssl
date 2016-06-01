# .../base/arch/linux/CMakeLists.txt
# Builds object files for Linux specific routines.

add_subdirectory(test)

if(${THREAD})
  message(FATAL_ERROR "Thread support is not yet implemented.")

else(${THREAD})
  add_library(
    arch

    OBJECT

#    ../lock_none.c
    ../thread_none.c
#    io_linux.c
#    random_linux.c
  )

endif(${THREAD})
