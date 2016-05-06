# VapidSSL Style Guide

VapidSSL usually follows [BoringSSL's style guide]
(https://boringssl.googlesource.com/boringssl/+/HEAD/STYLE.md) which in turn
references the [Google C++ style guide]
(https://google.github.io/styleguide/cppguide.html). The rest of this document
describes differences and clarifications on top of the base guide.


## Language

Use enums and constants instead of `#define`s wherever possible, including for
sets of flags. `#defines` should only be used when a value is needed for a
fixed size array or for macros.  Macros should be limited to those involving
type manipulation, static initialization, or built-in macros where not using a
macro would lead to error-prone code duplication.


## Formatting

All files use Google's clang-format style, with the exception that, like
BoringSSL, single-statement blocks are not allowed. All conditions and loops
must use braces.  In contrast to BoringSSL, VapidSSL extends this rule to short
functions as well, requiring them to break across multiple lines.


## Naming

All externally visible symbols are prefixed by either 'TLS_', 'tls_', or 'kTls'
as appropriate to avoid naming collisions with library consumers.

VapidSSL mimics the function naming rules that BoringSSL (almost) always uses:
  * Public API calls are declared in vapid.h and start with the uppercase name
    of the corresponding source file, i.e. TLS_ERROR_get() is implemented in
    error.c. An exception is tls.c, where the 'TLS' prefixes are not duplicated,
    i.e. `TLS_connect()`is used instead of `TLS_TLS_connect()`.
  * Library routines are declared in an internal header and begin with the
    lowercase name of the corresponding source file, i.e. `buffer_wrap()` is
    declared in internal/buffer.h and implemented in buffer.c
  * Private functions are forward declared near the beginning of a source file,
    defined near the end, and begin with the lowercase name of that source file,
    i.e. `message_send()` has a forward declaration and definition in message.c

Struct names include the name of file that defines them and have a *_st suffix.
The "main" structure defined by a file may simply be the file name and suffix
with no additional naming in between. These "main" structures are typedef'd with
the uppercase filename, for example `typedef struct message_st MESSAGE` for the
structure defined in message.h.

Enums and aliases for primitives have a *_t suffix and are typedef’d to
themselves, e.g. `enum direction_t direction_t` or `typedef uint32_t uint24_t`.
Values of an enum all start with a shared prefix, e.g. `kTlsErrUnknownCA` and
`kTlsErrRecordOverflow` are both values of `tls_error_alert_t`.  The prefixes
are not required to be unique, but separate enums that use the same prefix must
be declared in the same file.

Function pointers are discouraged except for continuation-style code to handle
non-blocking I/O. These function pointers are typedef'd with a file prefix and a
*_f suffix, for example:
`typedef result_t (*handshake_io_f)(HANDSHAKE* handshake, TLS* tls)`.

As a difference from BoringSSL, functions named `<TYPE>_new` do not allocate any
memory, but rather take memory as an argument to instantiate new structures of
type `struct <type>_st`.  Similarly, `buf_malloc` and `buf_free` use existing
memory rather than allocating or freeing memory dynamically.


## Return values

The majority of functions return a `result_t`, which is an an enumeration of
`kSuccess` and `kFailure`.

If a function cannot fail and has no outputs or has a single output, it can
return `void` or that value, respectively.  Many library routines only have
failures that would require a coding error.  These routines can `assert` those
failure modes and then behave as if they can not fail.

As with BoringSSL, if a function outputs a pointer to an object on success and
there are no other outputs, return the pointer directly and `NULL` on error.


## Documentation

The BoringSSL rules about documentation apply, but to library routines as well
as API calls.  All non-static symbols must have a documentation comment in their
header file. The style is based on that of Go. The first sentence begins with
the symbol name, optionally prefixed with "A" or "An". Apart from the
initial mention of symbol, references to other symbols or parameter
names should be surrounded by |pipes|.

Documentation should be concise but completely describe the exposed
behavior of the function. Pay special note to success/failure behaviors
and caller obligations on object lifetimes. If this sacrifices
conciseness, consider simplifying the function's behavior. Explicitly mention
any surprising edge cases or deviations from common return value patterns.
Document static structures where declared, and static functions with their
forward declarations.
