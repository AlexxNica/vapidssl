#include <stdio.h>
#include <time.h>
#include <vector>

#include "base/buf.h"
#include "base/platform/random.h"
#include "base/test/scoped_buf.h"
#include "third_party/boringssl/include/openssl/ssl.h"
#include "third_party/boringssl/ssl/internal.h"

namespace vapidssl {

namespace {

std::vector<uint32_t> kHashes = {SSL_HANDSHAKE_MAC_SHA256,
                                 SSL_HANDSHAKE_MAC_SHA384};
std::vector<size_t> kSecretLengths = {48, 63, 99};
const size_t kSeedLength = 64;
std::vector<size_t> kSeedSplits = {0, 1, 16, 32, 63};
std::vector<size_t> kOutputLengths = {1, 31, 32, 33, 47, 48, 49, 255, 1024};
std::vector<const char *> kLabels = {"", "test label",
                                     "another, longer test label",
                                     "({[An_E^en_L()nger_%and-Th0r0ughlY."
                                     "puncu8ted\\$tr!ng>+h@+//goes\ton&on*#"};
}

void PrintfHexBuf(const char *tag, BUF *buf) {
  printf("%s : ", tag);
  buf_reset(buf, 0);
  buf_produce(buf, buf_size(buf), NULL);
  uint32_t value = 0;
  while (buf_ready(buf) != 0) {
    buf_get_val(buf, 1, &value);
    printf("%02x", value);
  }
  printf("\n");
}

void ProducePrfData(uint32_t hash) {
  // Set up memory
  ScopedBuf secret;
  uint8_t *secret_raw = nullptr;
  for (const char *label : kLabels) {
    size_t label_len = strlen(label);
    ScopedBuf seeds;
    BUF seed1 = buf_init();
    uint8_t *seed1_raw = nullptr;
    size_t seed1_len = 0;
    BUF seed2 = buf_init();
    uint8_t *seed2_raw = nullptr;
    ScopedBuf output;
    uint8_t *output_raw = nullptr;
    // Build a fake SSL struct
    SSL ssl;
    SSL3_STATE s3;
    SSL_CIPHER cipher;
    memset(&ssl, 0, sizeof(SSL));
    memset(&s3, 0, sizeof(SSL3_STATE));
    memset(&cipher, 0, sizeof(SSL_CIPHER));
    ssl.s3 = &s3;
    s3.tmp.new_cipher = &cipher;
    cipher.algorithm_prf = hash;
    // Iterate over different secret lengths
    for (size_t secret_len : kSecretLengths) {
      secret.Reset(secret_len);
      random_buf(secret.Get());
      buf_consume(secret.Get(), secret_len, &secret_raw);
      // Iterate over different ways to split the seed
      seeds.Reset(kSeedLength);
      buf_malloc(seeds.Get(), kSeedLength, &seed1);
      random_buf(&seed1);
      for (size_t seed2_len : kSeedSplits) {
        seed1_len = kSeedLength;
        seed2_raw = nullptr;
        assert(seed2_len < kSeedLength);
        if (seed2_len != 0) {
          seed1_len -= seed2_len;
          buf_split(&seed1, seed1_len, &seed2);
          buf_consume(&seed2, seed2_len, &seed2_raw);
        }
        buf_consume(&seed1, seed1_len, &seed1_raw);
        // Iterate over different length of outputs
        for (size_t output_len : kOutputLengths) {
          output.Reset(output_len);
          buf_produce(output.Get(), output_len, &output_raw);
          if (!TLSv1_enc_data.prf(&ssl, output_raw, output_len, secret_raw,
                                  secret_len, label, label_len, seed1_raw,
                                  seed1_len, seed2_raw, seed2_len)) {
            abort();
          }
          printf("\n");
          printf("# %lu byte secret generating %lu bytes of output.\n",
                 secret.Len(), output.Len());
          PrintfHexBuf("SECRET", secret.Get());
          printf("LABEL: %s\n", label);
          PrintfHexBuf("SEED1", &seed1);
          PrintfHexBuf("SEED2", &seed2);
          PrintfHexBuf("OUTPUT", output.Get());
        }
        if (seed2_raw) {
          buf_merge(&seed2, &seed1);
        }
        buf_reset(&seed1, 0);
        buf_produce(&seed1, kSeedLength, NULL);
      }
      buf_free(&seed1);
    }
  }
}

}  // namespace vapidssl

int main(int argc, char **argv) {
  uint32_t hash = 0;
  if (argc != 2) {
    printf("error:  No hash algorithm specified.\n");
    printf("usage: %s <hash>\n", argv[0]);
    exit(1);
  } else if (strcmp(argv[1], "sha256") == 0) {
    hash = SSL_HANDSHAKE_MAC_SHA256;
  } else if (strcmp(argv[1], "sha384") == 0) {
    hash = SSL_HANDSHAKE_MAC_SHA384;
  } else {
    printf("error:  Unrecognized hash '%s'.\n", argv[1]);
    printf("        Supported hashes are:\n");
    printf("                sha256\n");
    printf("                sha384\n");
    exit(1);
  }
  // Init errors
  vapidssl::ScopedBuf err_buf(TLS_ERROR_size());
  if (!TLS_ERROR_init(err_buf.Raw(), err_buf.Len())) {
    abort();
  }
  // Print header
  time_t t;
  time(&t);
  struct tm *l = localtime(&t);
  char today[9];
  strftime(today, 9, "%x", l);
  printf("# This file was generated by %s on %s using %s.\n", __FILE__, today,
         argv[1]);
  // Generate the data
  vapidssl::ProducePrfData(hash);
  return 0;
}
