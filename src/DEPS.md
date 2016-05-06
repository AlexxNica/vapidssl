# Modules and dependencies

The source tree for VapidSSL is broken into several modules as listed below:
  * base: Utility functions and cross-cutting behaviors.
  * arch: Adapter code for platform-specific functionality.
  * common: Protocol-agnostic code for processing packets and streams.
  * crypto: Adapter code for specific crypto library implementations.
  * tls1_2: Code for implementing TLS 1.2 per RFC 5246.
  * x509v3: Code for processing certificates per RFC 5280.

The dependency graph is depicted below.  It is important that this graph is
respected; it is essential that no cycles are allowed in the dependency graph.
The only allowed exception is between `base` and `arch`.  `arch` is a submodule
of `base`; thus both are treated as a single node in the graph.

    +---- tls1_2 ---+
    |     |         v
    |     |    x509v3
    |     |         |
    |     common <--+
    |     |    |
    |     |    +----+
    |     |         v
    |     |    crypto
    |     v         |
    +-> base/arch <-+
