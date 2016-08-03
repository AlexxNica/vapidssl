#! /usr/bin/ruby

# Copyright 2016 The Fuchsia Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "base64"

# This file does *EXTREMELY* minimal parsing of a directory of self-signed
# PEM-formatted X.509v3 certificates in order to extract sample signed data,
# public keys, and signatures for use in src/crypto/sign_test.cc

# It also produces the DN, but leaves it commented out.  This can be used  with
# TLS_CONFIG_trust_signer to trust a certificate.

# We only care about identifying a small subset of ASN.1 tags
ASN1_SEQUENCE = 0x30
ASN1_BITSTRING = 0x03
ASN1_INTEGER = 0x02

# Rather than parse out the string fine detail, we simply match the whole
# algorithm idenifier to the appropriate test data file.
ALG_IDS = {
  "06092a864886f70d0101040500" => "rsa_with_md5_tests.txt",
  "06092a864886f70d0101050500" => "rsa_with_sha1_tests.txt",
  "06092a864886f70d01010b0500" => "rsa_with_sha256_tests.txt",
  "06092a864886f70d01010c0500" => "rsa_with_sha384_tests.txt",
  "06082a8648ce3d040303" => "ecdsa_with_sha384_tests.txt",
}

# Open a PEM file, ignore the leading and trailing lines, and base-64 decode the
# rest into an array of bytes
def get_pem_bytes(path)
  bytes = Array.new
  File.open(path, "r") do |f|
    f.each_line do |line|
      if !line.match(/-----/)
        bytes.concat(Base64.decode64(line).unpack('C*'))
      end
    end
  end
  return bytes
rescue => e
  puts "[-] I/O error: #{e.to_s}"
  return nil
end

# Read off the type and length of the ASN.1/DER structure.  Verify the type is
# what we expected. Report and return the length.
def parse_asn1(bytes, type, name, discarded)
  len = 0
  discarded = Array.new if discarded.nil?
  discarded << bytes.shift
  if discarded.last != type
    puts "[-]  Expected '0x#{type.to_s(16)}' for #{name}."
    puts "[-]  Found '0x#{discarded.last.to_s(16)}'."
    raise "Wrong type #{type} != #{t}"
  elsif bytes.first < 0x80
    discarded << bytes.shift
    len = discarded.last
  else
    discarded << bytes.shift
    (discarded.last & 0x0f).times do |i|
      len <<= 8
      discarded << bytes.shift
      len += discarded.last
    end
  end
  puts "[+] Length of #{name}: #{len.to_s}"
  return len
end

# Same as parse_asn1, but use the length it returns to remove and return the
# associated ASN.1/DER data from the array
def get_asn1(bytes, type, name)
  return bytes.shift(parse_asn1(bytes, type, name, nil))
end

# Given the bytes from a PEM file, parse through a self-signed X.509v3
# certificate and extract the signed data, public key, and signature.  Return
# either the test data file these should be written to, or nil on error.
def parse_pem_bytes(bytes, data, key, sig, dn)
  return nil if bytes.nil?
  # Parse the relevant fields of the DER-encoded structure
  parse_asn1(bytes, ASN1_SEQUENCE, "top-level", nil)
  tbs = bytes.shift(parse_asn1(bytes, ASN1_SEQUENCE, "TBS certificate", data))
  data.concat(tbs)
  if tbs.shift(5) != [0xa0, 0x03, 0x02, 0x01, 0x02]
    puts "[-] Did not find explicit version tag for X.509v3"
    return nil
  end
  get_asn1(tbs, ASN1_INTEGER, "serial")
  inner_alg_id = get_asn1(tbs, ASN1_SEQUENCE, "algorithm identifier")
  get_asn1(tbs, ASN1_SEQUENCE, "issuer DN")
  get_asn1(tbs, ASN1_SEQUENCE, "validity")
  dn.replace(get_asn1(tbs, ASN1_SEQUENCE, "subject DN"))
  spki = get_asn1(tbs, ASN1_SEQUENCE, "subject public key info")
  get_asn1(spki, ASN1_SEQUENCE, "algorithm identifier")
  key.replace(get_asn1(spki, ASN1_BITSTRING, "subject public key"))

  outer_alg_id = get_asn1(bytes, ASN1_SEQUENCE, "algorithm identifier")
  sig.replace(get_asn1(bytes, ASN1_BITSTRING, "signature"))
  # Do some minimal checks
  if inner_alg_id != outer_alg_id
    puts "[-] Algorithm ID mismatch"
    return nil
  elsif key.shift != 0
    puts "[-] Public key is not a multiple of 8 bits"
    return nil
  elsif sig.shift != 0
    puts "[-] Signature is not a multiple of 8 bits"
    return nil
  elsif bytes.length != 0
    puts "[-] #{bytes.length} not consumed"
    return nil
  end
  return ALG_IDS[hexify(inner_alg_id)]
rescue => e
  puts "[-] Parse error: #{e.to_s}"
  return nil
end

def hexify(bytes)
  return bytes.pack('C*').unpack('H*')[0]
end

# Main routine: Take self-signed certificates in <cert-dir> and use them to
# generate test data files in <test-dir>
if ARGV.length != 2
  puts "[-] usage: #{$0} <cert-dir> <test-dir>"
  exit 1
end
cert_dir = ARGV[0]
test_dir = ARGV[1]

# Get a list of the PEM files in <cert-dir>
pem_files ||= []
Dir.chdir(cert_dir) do
  pem_files = Dir["*.pem"]
end

# Process each PEM file and append its results to the appropriate test data file
tool = File.expand_path($0).gsub(/.*\/test\//, 'test/')
date = Time.now.strftime("%m/%d/%Y")
data_files = Hash.new
pem_files.each do |pem|
  data_file = ""
  data = Array.new
  key = Array.new
  sig = Array.new
  dn = Array.new
  Dir.chdir(cert_dir) do
    puts "Now parsing '#{pem}'..."
    data_file = parse_pem_bytes(get_pem_bytes(pem), data, key, sig, dn)
    puts "Parse of '#{pem}' complete."
    puts
  end
  next if data_file.nil?
  Dir.chdir(test_dir) do
    # Truncate any existing test data files and add an informative header
    if data_files[data_file].nil?
      File.open(data_file, 'w') do |f|
        f.puts "# This file was auto-generated by #{tool} on #{date}"
        f.puts
      end
      data_files[data_file] = 1
    end
    # Append the data
    File.open(data_file, 'a') do |f|
      f.puts "# #{pem}"
      f.puts "DN: " + hexify(dn)
      f.puts "DATA: " + hexify(data)
      f.puts "KEY: " + hexify(key)
      f.puts "SIG: " + hexify(sig)
      f.puts
    end
  end
end
