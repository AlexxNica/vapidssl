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

#include "examples/client.h"

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "public/config.h"
#include "public/error.h"
#include "public/tls.h"
#include "third_party/boringssl/crypto/test/file_test.h"

namespace vapidssl {

// Public methods

Client::Client()
    : total_(0),
      config_(nullptr),
      issuers_(),
      hostname_(""),
      service_(""),
      path_(""),
      socket_(-1),
      tls_(nullptr),
      sni_("") {
  size_t len = TLS_ERROR_size();
  err_buf_.reset(new (std::nothrow) std::vector<uint8_t>(len));
  if (!err_buf_.get()) {
    PrintError("Client", "out of memory");
    abort();
  } else if (!TLS_ERROR_init(&(*err_buf_)[0], len)) {
    PError("TLS_ERROR_init");
    abort();
  }
  total_ += len;
}

Client::~Client() = default;

bool Client::ParseArgs(int argc, char **argv) {
  int i = 1;
  while (i < argc) {
    if (strncmp(argv[i], "-n=", 3) == 0) {
      sni_ = &argv[i][3];
    } else if (argv[i][0] == '-') {
      PrintError("ParseArgs", "unrecognized option");
      PrintError("ParseArgs", argv[i]);
      return false;
    } else {
      break;
    }
    ++i;
  }
  if (i + 2 > argc) {
    fprintf(stderr, "Usage: %s [-n=name] <host>[:port][/path] <certdata>\n",
            argv[0]);
    return false;
  }
  std::string url(argv[i]);
  size_t port_off = url.find(':');
  size_t path_off = url.find('/');
  if (port_off != std::string::npos && path_off != std::string::npos) {
    hostname_ = url.substr(0, port_off);
    service_ = url.substr(port_off + 1, path_off - port_off - 1);
    path_ = url.substr(path_off);

  } else if (port_off != std::string::npos) {
    hostname_ = url.substr(0, port_off);
    service_ = url.substr(port_off + 1);
    path_ = "/";

    hostname_ = url.substr(0, path_off);
    service_ = "https";

  } else if (path_off != std::string::npos) {
    hostname_ = url.substr(0, path_off);
    service_ = "https";
    path_ = url.substr(path_off);

  } else {
    hostname_ = url;
    service_ = "https";
    path_ = "/";
  }

  if (sni_.length() == 0) {
    sni_ = hostname_;
  }
  ++i;
  return ReadIssuers(argv[i]) && Configure();
}

bool Client::Connect() {
  return TcpConnect() && TlsConnect();
}

bool Client::WGet() {
  std::string s = "GET ";
  std::vector<uint8_t> request(s.begin(), s.end());
  std::copy(path_.begin(), path_.end(), std::back_inserter(request));
  s = " HTTP/1.1\r\nHost: ";
  std::copy(s.begin(), s.end(), std::back_inserter(request));
  std::copy(hostname_.begin(), hostname_.end(), std::back_inserter(request));
  s = "\r\nConnection: close\r\n\r\n";
  std::copy(s.begin(), s.end(), std::back_inserter(request));
  if (!Write(request)) {
    return false;
  }
  ScopedByteVector response = Read(0x10000);
  if (response->size() == 0) {
    PrintError("Read", "no data returned");
    return false;
  }
  std::copy(response->begin(), response->end(),
            std::ostream_iterator<uint8_t>(std::cout, ""));
  std::cout << std::endl;
  std::cout << std::endl;
  std::cout << "Success!  Received " << response->size() << " bytes from ";
  std::cout << hostname_ << std::endl;
  return true;
}

void Client::PrintTotal() {
  size_t config_len = TLS_CONFIG_size(issuers_.size());
  size_t buffers_len = 16384 * 2;
  size_t conn_len = total_ - config_len - buffers_len;
  std::cout << std::endl;
  std::cout << "--------------------------------" << std::endl;
  std::cout << std::endl;
  std::cout << "Total memory used: " << total_ << std::endl;
  std::cout << "    Configuration: " << config_len << std::endl;
  std::cout << "       Connection: " << conn_len << std::endl;
  std::cout << "      I/O buffers: " << buffers_len << std::endl;
  std::cout << std::endl;
}
// Private Methods

void Client::PrintError(const std::string &where, const std::string &what) {
  fprintf(stderr, "[-] ERROR: %s: %s\n", where.c_str(), what.c_str());
}

void Client::PError(const std::string &func) {
  tls_error_source_t source;
  int reason = 0;
  const char *file = nullptr;
  int line = 0;
  std::ostringstream oss;
  if (TLS_ERROR_get(&source, &reason, &file, &line) && file) {
    oss << "<" << source << ":" << reason << "> at " << file << ":" << line;
  } else {
    oss << "(unspecified)";
  }
  PrintError(func, oss.str());
}

bool Client::ReadIssuers(const std::string &datafile) {
  ::FileTest issuers(datafile.c_str());
  if (!issuers.is_open()) {
    PrintError("AddIssuer", "unable to open file");
    PrintError("AddIssuer", datafile);
    return false;
  }
  enum ::FileTest::ReadResult result = ::FileTest::kReadEOF;
  std::vector<uint8_t> ignored;
  for (result = issuers.ReadNext(); result == ::FileTest::kReadSuccess;
       result = issuers.ReadNext()) {
    ScopedByteVector dn(new (std::nothrow) std::vector<uint8_t>());
    ScopedByteVector key(new (std::nothrow) std::vector<uint8_t>());
    if (!dn.get() || !key.get()) {
      PrintError("ReadIssuers", "out of memory");
      return false;
    }
    if (!issuers.GetBytes(dn.get(), "DN") ||
        !issuers.GetBytes(key.get(), "KEY") ||
        !issuers.GetBytes(&ignored, "DATA") ||
        !issuers.GetBytes(&ignored, "SIG")) {
      break;
    }
    std::pair<ScopedByteVector, ScopedByteVector> p(std::move(dn),
                                                    std::move(key));
    issuers_.push_back(std::move(p));
  }
  if (result != ::FileTest::kReadEOF) {
    PrintError("AddIssuer", "read failure");
    PrintError("AddIssuer", datafile);
    return false;
  }
  return true;
}

bool Client::Configure() {
  size_t len = TLS_CONFIG_size(issuers_.size());
  config_buf_.reset(new (std::nothrow) std::vector<uint8_t>(len));
  if (!config_buf_.get()) {
    PrintError("Configure", "out of memory");
    return false;
  } else if (!TLS_CONFIG_init(&(*config_buf_)[0], len, issuers_.size(),
                              &config_)) {
    PError("TLS_CONFIG_init");
    return false;
  }

  for (const auto &issuer : issuers_) {
    std::vector<uint8_t> *dn = issuer.first.get();
    std::vector<uint8_t> *key = issuer.second.get();
    if (!TLS_CONFIG_trust_signer(config_, &(*dn)[0], dn->size(), &(*key)[0],
                                 key->size())) {
      PError("TLS_CONFIG_trust_signer");
      return false;
    }
  }
  total_ += len;
  return true;
}

bool Client::TcpConnect() {
  // Set up hints: TCP/IPv4 or TCP/IPv6
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  // Get the address info.
  struct addrinfo *res = nullptr;
  int result = getaddrinfo(hostname_.c_str(), service_.c_str(), &hints, &res);
  if (result != 0) {
    PrintError("getaddrinfo", gai_strerror(result));
    return false;
  }
  // Try to connect.
  struct addrinfo *ai = res;
  while (ai) {
    socket_ = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (socket_ < 0) {
      perror("socket");
    } else if (connect(socket_, ai->ai_addr, ai->ai_addrlen) < 0) {
      perror("connect");
      close(socket_);
    } else {
      break;
    }
    ai = ai->ai_next;
  }
  // No more addresses to try.
  if (!ai) {
    PrintError("TcpConnect", "failed to connect");
    return false;
  }
  // Cleanup.
  freeaddrinfo(res);
  return true;
}

bool Client::TlsConnect() {
  // Create the connection object.
  size_t len = TLS_size(config_);
  tls_buf_.reset(new (std::nothrow) std::vector<uint8_t>(len));
  if (!tls_buf_.get()) {
    PrintError("TlsConnect", "out of memory");
    return false;
  } else if (!TLS_init(config_, &(*tls_buf_)[0], len, socket_, sni_.c_str(),
                       &tls_)) {
    PError("TLS_init");
    return false;
  }
  total_ += len;
  // Perform the handshake.
  len = TLS_connect_size(config_);
  ScopedByteVector connect_buf_(new (std::nothrow) std::vector<uint8_t>(len));
  if (!connect_buf_.get()) {
    PrintError("TlsConnect", "out of memory");
    return false;
  } else if (!TLS_connect(tls_, &(*connect_buf_)[0], len)) {
    PError("TLS_connect");
    return false;
  }
  return true;
}

Client::ScopedByteVector Client::Read(size_t max) {
  ScopedByteVector response(new std::vector<uint8_t>(max));
  if (!response.get()) {
    PrintError("Read", "out of memory");
    return response;
  }
  if (tls_) {
    size_t len = 0;
    if (!TLS_read(tls_, &(*response)[0], &len, max)) {
      PError("TLS_read");
    }
    response->resize(len);
  } else if (!tls_) {
    ssize_t len = recv(socket_, &(*response)[0], max, 0);
    if (len < 0) {
      perror("recv");
    }
    response->resize(len);
  }
  return response;
}

bool Client::Write(const std::vector<uint8_t> &request) {
  if (request.size() == 0) {
    PrintError("Write", "no data to send");
    return false;
  }
  ssize_t len = request.size();
  if (tls_ && !TLS_write(tls_, &request[0], len)) {
    PError("TLS_write");
    return false;
  } else if (!tls_ && send(socket_, &request[0], len, 0) < 0) {
    perror("send");
    return false;
  }
  return true;
}

}  // namespace vapidssl
