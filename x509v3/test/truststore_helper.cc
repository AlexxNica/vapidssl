// Copyright 2016 The Fuchsia Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "x509v3/test/truststore_helper.h"

#include <stddef.h>
#include <stdint.h>

namespace vapidssl {

// TODO(aarongreen) Script the extraction of the DN bytes from a certificate.
// This is the subject (and issuer, since it's self-signed) DN field of
// "test/root.cert.pem".
const size_t TruststoreHelper::dn_len = 113;
const uint8_t TruststoreHelper::dn[TruststoreHelper::dn_len] = {
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
    0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a,
    0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x16,
    0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0d, 0x4d, 0x6f, 0x75,
    0x6e, 0x74, 0x61, 0x69, 0x6e, 0x20, 0x56, 0x69, 0x65, 0x77, 0x31, 0x10,
    0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x46, 0x75, 0x63,
    0x68, 0x73, 0x69, 0x61, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x08, 0x56, 0x61, 0x70, 0x69, 0x64, 0x53, 0x53, 0x4c, 0x31,
    0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x52, 0x6f,
    0x6f, 0x74, 0x20, 0x43, 0x41};

// TODO(aarongreen) Script the extraction of the key bytes from a certificate.
// This is the public key bytes of "test/root.cert.pem".
const size_t TruststoreHelper::key_len = 270;
const uint8_t TruststoreHelper::key[TruststoreHelper::key_len] = {
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb9, 0x4c, 0x64,
    0x4f, 0x89, 0x1d, 0x6e, 0xff, 0xa7, 0x7b, 0xb9, 0xfe, 0xef, 0x00, 0x37,
    0x88, 0x49, 0x51, 0x57, 0x80, 0x32, 0x6f, 0x24, 0xd0, 0xd8, 0xef, 0xee,
    0x22, 0x07, 0x1d, 0x34, 0x73, 0x7f, 0xd8, 0xe9, 0x2a, 0xdd, 0x0c, 0x79,
    0x0e, 0xfe, 0xd1, 0x64, 0x58, 0x3e, 0xe8, 0x22, 0x0c, 0xfe, 0x78, 0x5b,
    0xa4, 0x72, 0x37, 0x0a, 0x65, 0xd8, 0x26, 0x70, 0xec, 0x56, 0x62, 0x8a,
    0xfc, 0x7d, 0x6b, 0x4f, 0xfa, 0x51, 0x90, 0xfe, 0x40, 0x07, 0xaf, 0xca,
    0xec, 0xe6, 0xb6, 0x31, 0x62, 0x4a, 0x70, 0xcc, 0x8e, 0xbc, 0xd1, 0xe2,
    0xea, 0x52, 0x8c, 0x5d, 0x9a, 0xff, 0xf2, 0xc0, 0x1a, 0xb9, 0xc5, 0x9d,
    0x33, 0xca, 0x57, 0x2e, 0xec, 0x34, 0xd5, 0x4b, 0x1e, 0x97, 0x7f, 0x9d,
    0xf7, 0x9e, 0x61, 0x7e, 0x56, 0x6a, 0xe3, 0x3c, 0xb2, 0xb2, 0xc0, 0x74,
    0x33, 0xf4, 0x04, 0x19, 0xdd, 0x8a, 0x0a, 0xb2, 0xba, 0x48, 0xa0, 0x3f,
    0x26, 0xa7, 0x0f, 0x7d, 0x1a, 0x36, 0xcc, 0x3b, 0x25, 0xbc, 0x75, 0x37,
    0xed, 0xdf, 0xfa, 0xec, 0xd2, 0x26, 0x07, 0xe4, 0x93, 0xac, 0x11, 0xc7,
    0x93, 0xe7, 0x12, 0xad, 0xa2, 0x2a, 0x2b, 0x7b, 0x90, 0x88, 0x1c, 0x61,
    0xe5, 0xdc, 0x2b, 0x28, 0x05, 0x2a, 0x4f, 0x4b, 0xc8, 0x56, 0x34, 0xcc,
    0x1e, 0xc1, 0xb2, 0x7b, 0x5a, 0xcd, 0xa8, 0x1b, 0x35, 0x8e, 0x25, 0x8d,
    0xba, 0x3f, 0x6d, 0x0e, 0xc9, 0xd8, 0x08, 0xea, 0xc8, 0xcf, 0x4b, 0x2e,
    0xaa, 0x40, 0xbf, 0x70, 0x2d, 0xf2, 0xe4, 0x31, 0x5e, 0x41, 0x48, 0xc1,
    0x8f, 0xb7, 0xa9, 0xfc, 0xd7, 0x5b, 0x12, 0x76, 0x19, 0xf2, 0xb9, 0x53,
    0x93, 0x1d, 0xeb, 0x12, 0x94, 0xc4, 0x31, 0x39, 0x41, 0x19, 0x55, 0x6e,
    0xa0, 0x5b, 0x69, 0xe6, 0x81, 0xeb, 0xd9, 0x80, 0x0b, 0x5f, 0xe2, 0x4e,
    0x53, 0x02, 0x03, 0x01, 0x00, 0x01};

}  // namespace vapidssl
