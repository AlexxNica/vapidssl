# .../base/arch/CMakeLists.txt
# Builds object files for platform specific routines.

add_subdirectory(test)

if(${ARCH} STREQUAL "linux")
    add_subdirectory(linux)

else()
  message(FATAL_ERROR "Unsupported ARCH: " ${ARCH})

endif()
