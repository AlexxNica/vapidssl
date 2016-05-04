# VapidSSL

VapidSSL is a TLS 1.2 client derived from BoringSSL, which itself is a fork of
OpenSSL that is designed to meet Google's needs.  VapidSSL is designed to work
securely on constrained platforms with low memory and storage capacities.

VapidSSL arose because BoringSSL was too large for the smallest class of
devices, and couldn't be made smaller without fundamentally changing the way it
worked and was organized.  At the same time, the existing embedded TLS libraries
suffered many of the same development problems that plagued OpenSSL and led to
the creation of BoringSSL in the first place. In general, if your environment
can run BoringSSL, it should prefer that library over this one.

## Cloning via Jiri

To recommended way to clone this repositories and its dependencies is using Jiri
(https://github.com/vanadium/go.jiri):

    jiri import -name=vapidssl manifest https://fuchsia.googlesource.com/vapidssl

Once this has been done, you can get the latest updates for both VapidSSL and
its dependencies with one command:

    jiri update

## Important information

Like its parent, BoringSSL, this project has no guarantees of API or ABI
stability. Programs and/or platforms ship their own copies of VapidSSL when they
use it and we update everything as needed when deciding to make API changes.
This allows us to mostly avoid compromises in the name of compatibility. It
works for us, but it may not work for you.

There are other files in this directory which might be helpful:

  * [BUILDING.md](/BUILDING.md): how to build VapidSSL.
  * [STYLE.md](/STYLE.md): rules and guidelines for coding style.
  * include/vapidssl: public headers with API documentation in comments.

