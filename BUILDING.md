# Building VapidSSL

At this prerelease stage, VapidSSL only has documented build instructions for
64-bit Linux.  It will also target small embedded microcontrollers, and should
be usuable on 32-bit Linux and on Android platforms as well.

## Build Prerequisites

  * [CMake](https://cmake.org/download/) 2.8.8 or later is required.

  *  [Ninja](https://ninja-build.org/) is not required, but recommended, because
    it makes builds faster.

  * If you need to build Ninja from source, then a recent version of
    [Python](https://www.python.org/downloads/) is required (Python 2.7.5 works).

  * A C compiler is required. Recent versions of GCC (4.8+) and Clang should
    work..

## Building

Using Ninja (note the 'N' is capitalized in the cmake invocation):

    mkdir build
    cd build
    cmake -GNinja ..
    ninja

You usually don't need to run `cmake` again after changing `CMakeLists.txt`
files because the build scripts will detect changes to them and rebuild
themselves automatically.

The build system is not quite yet smart enough to properly figure out how to
automatically build the external libraries, due to limitations of older version
of `cmake` as well as some path assumptions of the BoringSSL build system.  As a
result, the libraries must be built manually at least once before building
VapidSSL. To (re)build the externl projects, set the relevant project roots in
the top-level `CMakeLists.txt` and use the `ninja` targets:

    ninja rebuild-boringssl
    ninja rebuild-googletest

Note that the default build flags in the top-level `CMakeLists.txt` are for
debugging—optimisation isn't yet possible.

See [CMake](https://cmake.org/cmake/help/v3.4/manual/cmake-variables.7.html) documentation for other variables which may be used to configure the build.

# Running tests

There is one sets of test currently: the C/C++ tests which are built by Ninja
and can be run from the build directory with `ctest`.
There's another one in the works:  the Go blackbox tests from BoringSSL, which
can be run by running [TBD: `go test client tls12 <path/to/shim>`]
