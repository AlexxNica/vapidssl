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

#ifndef VAPIDSSL_EXAMPLES_CLIENT_H
#define VAPIDSSL_EXAMPLES_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "public/config.h"
#include "public/error.h"
#include "public/tls.h"

namespace vapidssl {

// Client is a very simple HTTPS client that can be used to issue HTTP GET
// requests over TLS 1.2.
class Client {
 public:
  Client();
  virtual ~Client();
  Client &operator=(const Client &) = delete;
  Client(const Client &) = delete;

  // ParseArgs parses the command line arguments, |argc| and |argv|.  The
  // correct usage is:
  //  client [-n sni] host[:port][/path]
  virtual bool ParseArgs(int argc, char **argv);

  // Connect performs the TCP and TLS handshakes.
  virtual bool Connect();

  // WGet issues an HTTP GET request.
  virtual bool WGet();

  // PrintTotal reports some memory usage numbers.
  virtual void PrintTotal();

 private:
  using ScopedByteVector = std::unique_ptr<std::vector<uint8_t> >;

  // PrintError is a helper function to report errors.
  void PrintError(const std::string &where, const std::string &what);

  // PError wraps |perror|.
  void PError(const std::string &func);

  // Configure builds the necessary configuration object.
  bool Configure();

  // ReadIssuers parses the output of test/tools/generate_sign_data.rb for use
  // as a truststore.
  bool ReadIssuers(const std::string &datafile);

  // TcpConnect does the TCP handshake.
  bool TcpConnect();

  // TcpConnect does the TLS handshake.
  bool TlsConnect();

  // Read receives a response from the server up to |max| bytes long and returns
  // it.
  ScopedByteVector Read(size_t max);

  // Write sends a |request| to the server.
  bool Write(const std::vector<uint8_t> &request);

  // total_ tracks the memory used.
  size_t total_;
  // err_buf_ is the memory allocated for the call to TLS_ERR_init.
  ScopedByteVector err_buf_;
  // config_buf_ is the memory allocated for the call to TLS_CONFIG_init.
  ScopedByteVector config_buf_;
  // config_ is the library configuration.
  TLS_CONFIG *config_;
  // issuers_ is the truststore.
  std::vector<std::pair<ScopedByteVector, ScopedByteVector> > issuers_;
  // hostname_ indicates what IP address to connect to.
  std::string hostname_;
  // service indicates what TCP port to use.
  std::string service_;
  // path_ is used to build the HTTP GET request.
  std::string path_;
  // socket_ is the OS's socket file descriptor.
  int socket_;
  // tls_buf_ is the memory allocated for the call to TLS_init.
  ScopedByteVector tls_buf_;
  // tls_ is the TLS connection object.
  TLS *tls_;
  // sni_ is the server name indication to request in the TLS handshake.
  std::string sni_;
};

}  // namespace vapidssl

#endif  // VAPIDSSL_EXAMPLES_CLIENT_H
