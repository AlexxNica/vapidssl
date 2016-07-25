# .../x509v3/CMakeLists.txt
# Builds object files for certificate parsing and validation.

add_library(
  x509v3

  OBJECT

#  asn1.c
#  certificate.c
  oid.c
)

add_library(
  x509v3-unittests

  OBJECT

#  asn1_unittest.cc
#  certificate_unittest.cc
  oid_unittest.cc
)
