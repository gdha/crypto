/*
Single-line container format for AES/RSA:

  <b64(part1)>.<b64(part2)>.<b64(part3)>\n

- rsa-enc reads the recipient's PUBLIC key from a file and emits:
    b64(cipher).b64(encryptedKey).b64(iv)
- rsa-dec reads the recipient's PRIVATE key from a file and decrypts
- aes-enc reads the AES key+iv from a file and emits:
    b64(cipher).b64(iv)
  (the key itself is NOT embedded in the output)
- aes-dec reads the AES key+iv from the same file and decrypts

Usage:
  rsa-enc <pubkey.pem>  – reads plaintext from stdin, writes ciphertext to stdout
  rsa-dec <privkey.pem> – reads ciphertext from stdin, writes plaintext to stdout
  aes-enc <keyfile>     – reads plaintext from stdin, writes ciphertext to stdout
  aes-dec <keyfile>     – reads ciphertext from stdin, writes plaintext to stdout

AES keyfile format: raw bytes – first 32 bytes are the key, next 16 are the IV.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/pem.h>
#include <openssl/rand.h>

#include "crypto.h"
#include "base64.h"

/* MAX_INPUT_BYTES caps unbounded stdin growth (256 MiB) */
#define MAX_INPUT_BYTES (256 * 1024 * 1024)

/* Mark die() as noreturn so the compiler knows it never returns.
   This prevents false-positive CWE-457 warnings from -fanalyzer. */
static void die(const char *msg) __attribute__((noreturn));
static void die(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(1);
}

static unsigned char *read_all_stdin(size_t *out_len) {
  size_t cap = 8192, len = 0;
  unsigned char *buf = (unsigned char *)malloc(cap);
  if (!buf) die("OOM");

  for (;;) {
    size_t n = fread(buf + len, 1, cap - len, stdin);
    len += n;

    if (n == 0) {
      if (ferror(stdin)) die("Failed reading stdin");
      break;
    }

    if (len > MAX_INPUT_BYTES) die("Input exceeds maximum allowed size (256 MiB)");

    if (len == cap) {
      if (cap > MAX_INPUT_BYTES / 2) die("Input exceeds maximum allowed size (256 MiB)");
      cap *= 2;
      unsigned char *nb = (unsigned char *)realloc(buf, cap);
      if (!nb) die("OOM");
      buf = nb;
    }
  }

  *out_len = len;
  return buf;
}

static char *read_all_stdin_text(size_t *out_len) {
  size_t n = 0;
  unsigned char *raw = read_all_stdin(&n);
  /* read_all_stdin either returns a valid pointer or calls die() (noreturn).
     The explicit NULL check below silences -fanalyzer's CWE-457 false positive
     since the analyzer does not fully model noreturn through all call paths. */
  if (!raw) die("OOM");

  while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r' || raw[n - 1] == ' ' || raw[n - 1] == '\t'))
    n--;

  char *s = (char *)malloc(n + 1);
  if (!s) die("OOM");
  /* GCC -fanalyzer issues a false-positive CWE-457 here because it cannot
     fully model that read_all_stdin() either returns a valid pointer or
     terminates the process.  The explicit NULL check above confirms 'raw'
     is non-NULL before this point. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-use-of-uninitialized-value"
  memcpy(s, raw, n);
#pragma GCC diagnostic pop
  s[n] = '\0';

  free(raw);
  *out_len = n;
  return s;
}

static void write_all_stdout(const unsigned char *buf, size_t len) {
  if (len == 0) return;
  if (fwrite(buf, 1, len, stdout) != len) die("Failed writing stdout");
}

static void usage(const char *argv0) {
  fprintf(stderr,
    "Usage:\n"
    "  %s rsa-enc <pubkey.pem>   encrypt stdin with RSA public key\n"
    "  %s rsa-dec <privkey.pem>  decrypt stdin with RSA private key\n"
    "  %s aes-enc <keyfile>      encrypt stdin with AES key file\n"
    "  %s aes-dec <keyfile>      decrypt stdin with AES key file\n"
    "  %s aes-keygen <keyfile>   generate a new AES-256 key+iv and write to keyfile\n"
    "  %s --version              print version and exit\n"
    "\n"
    "AES keyfile: 48 raw bytes (32-byte key || 16-byte IV).\n"
    "Container format (single line): b64(part1).b64(part2).b64(part3)\\n\n",
    argv0, argv0, argv0, argv0, argv0, argv0);
  exit(2);
}

/* ── helpers ────────────────────────────────────────────────────────────── */

static int split_3_parts(char *s, char **p1, char **p2, char **p3) {
  char *a = s;
  char *dot1 = strchr(a, '.');
  if (!dot1) return 0;
  *dot1 = '\0';

  char *b = dot1 + 1;
  char *dot2 = strchr(b, '.');
  if (!dot2) return 0;
  *dot2 = '\0';

  char *c = dot2 + 1;
  if (*c == '\0') return 0;

  *p1 = a; *p2 = b; *p3 = c;
  return 1;
}

static int split_2_parts(char *s, char **p1, char **p2) {
  char *a = s;
  char *dot1 = strchr(a, '.');
  if (!dot1) return 0;
  *dot1 = '\0';

  char *b = dot1 + 1;
  if (*b == '\0') return 0;

  *p1 = a; *p2 = b;
  return 1;
}

static void emit_container_line_3(const char *b1, const char *b2, const char *b3) {
  fputs(b1, stdout); fputc('.', stdout);
  fputs(b2, stdout); fputc('.', stdout);
  fputs(b3, stdout); fputc('\n', stdout);
}

static void emit_container_line_2(const char *b1, const char *b2) {
  fputs(b1, stdout); fputc('.', stdout);
  fputs(b2, stdout); fputc('\n', stdout);
}

/* Load an EVP_PKEY public key from a PEM file. */
static EVP_PKEY *load_public_key(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) { fprintf(stderr, "Cannot open public key file: %s\n", path); exit(1); }
  EVP_PKEY *k = PEM_read_PUBKEY(f, NULL, NULL, NULL);
  fclose(f);
  if (!k) { fprintf(stderr, "Failed to read public key from: %s\n", path); exit(1); }
  return k;
}

/* Load an EVP_PKEY private key from a PEM file. */
static EVP_PKEY *load_private_key(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) { fprintf(stderr, "Cannot open private key file: %s\n", path); exit(1); }
  EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
  fclose(f);
  if (!k) { fprintf(stderr, "Failed to read private key from: %s\n", path); exit(1); }
  return k;
}

/* AES keyfile: 48 bytes — 32-byte key || 16-byte IV */
#define AES_KEYFILE_SIZE (32 + 16)

static void load_aes_keyfile(const char *path, unsigned char key[32], unsigned char iv[16]) {
  FILE *f = fopen(path, "rb");
  if (!f) { fprintf(stderr, "Cannot open AES key file: %s\n", path); exit(1); }
  unsigned char buf[AES_KEYFILE_SIZE];
  if (fread(buf, 1, AES_KEYFILE_SIZE, f) != AES_KEYFILE_SIZE) {
    fclose(f);
    die("AES key file too short (need 48 bytes: 32-byte key + 16-byte IV)");
  }
  fclose(f);
  memcpy(key, buf, 32);
  memcpy(iv,  buf + 32, 16);
  /* wipe stack copy */
  OPENSSL_cleanse(buf, AES_KEYFILE_SIZE);
}

/* ── modes ──────────────────────────────────────────────────────────────── */

static void do_rsa_enc(const char *pubkey_path) {
  /* Load recipient's public key — the matching private key stays with the
     recipient and is never transmitted. */
  EVP_PKEY *pub = load_public_key(pubkey_path);

  size_t in_len = 0;
  unsigned char *in = read_all_stdin(&in_len);
  if (in_len > (size_t)INT_MAX) die("Input too large for RSA seal");

  Crypto crypto;
  if (crypto_init(&crypto, /*pseudo_client=*/0) != 0) die("Failed to initialize crypto");

  /* Point the crypto context at the loaded public key (no private key needed
     for sealing). EVP_SealInit only uses the public component. */
  EVP_PKEY_free(crypto.remotePublicKey);
  crypto.remotePublicKey = pub;

  unsigned char *cipher = NULL; size_t cipher_len = 0;
  unsigned char *ek = NULL;     size_t ek_len = 0;
  unsigned char *iv = NULL;     size_t iv_len = 0;

  if (crypto_rsa_seal(&crypto, in, in_len, &cipher, &cipher_len, &ek, &ek_len, &iv, &iv_len) != 0)
    die("Encryption failed");

  char *b64_cipher = base64Encode(cipher, cipher_len);
  char *b64_ek     = base64Encode(ek, ek_len);
  char *b64_iv     = base64Encode(iv, iv_len);

  emit_container_line_3(b64_cipher, b64_ek, b64_iv);

  OPENSSL_cleanse(in, in_len);
  free(in); free(cipher); free(ek); free(iv);
  free(b64_cipher); free(b64_ek); free(b64_iv);
  crypto_cleanup(&crypto);
}

static void do_rsa_dec(const char *privkey_path) {
  EVP_PKEY *priv = load_private_key(privkey_path);

  size_t line_len = 0;
  char *line = read_all_stdin_text(&line_len);

  char *p1 = NULL, *p2 = NULL, *p3 = NULL;
  if (!split_3_parts(line, &p1, &p2, &p3)) die("Invalid input container line");

  unsigned char *cipher = NULL, *ek = NULL, *iv = NULL;
  int cipher_len_i = base64Decode(p1, strlen(p1), &cipher);
  int ek_len_i     = base64Decode(p2, strlen(p2), &ek);
  int iv_len_i     = base64Decode(p3, strlen(p3), &iv);
  if (cipher_len_i < 0 || ek_len_i < 0 || iv_len_i < 0) die("Base64 decode failed");
  if (cipher_len_i > INT_MAX || ek_len_i > INT_MAX || iv_len_i > INT_MAX)
    die("Decoded field too large");

  Crypto crypto;
  if (crypto_init(&crypto, /*pseudo_client=*/0) != 0) die("Failed to initialize crypto");

  /* Replace the local keypair with the loaded private key so crypto_rsa_open
     uses it for unsealing. */
  EVP_PKEY_free(crypto.localKeypair);
  crypto.localKeypair = priv;

  unsigned char *plain = NULL; size_t plain_len = 0;
  if (crypto_rsa_open(&crypto,
                      cipher, (size_t)cipher_len_i,
                      ek,     (size_t)ek_len_i,
                      iv,     (size_t)iv_len_i,
                      &plain, &plain_len) != 0) {
    die("Decryption failed");
  }

  write_all_stdout(plain, plain_len);

  OPENSSL_cleanse(plain, plain_len);
  free(line); free(cipher); free(ek); free(iv); free(plain);
  crypto_cleanup(&crypto);
}

static void do_aes_enc(const char *keyfile_path) {
  unsigned char key[32], iv[16];
  load_aes_keyfile(keyfile_path, key, iv);

  size_t in_len = 0;
  unsigned char *in = read_all_stdin(&in_len);
  if (in_len > (size_t)INT_MAX) die("Input too large for AES encrypt");

  Crypto crypto;
  if (crypto_init(&crypto, /*pseudo_client=*/0) != 0) die("Failed to initialize crypto");

  /* Overwrite the randomly generated key/iv with the ones from the key file. */
  memcpy(crypto.aesKey, key, 32);
  memcpy(crypto.aesIv,  iv,  16);
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(iv,  sizeof(iv));

  unsigned char *cipher = NULL; size_t cipher_len = 0;
  if (crypto_aes_encrypt(&crypto, in, in_len, &cipher, &cipher_len) != 0)
    die("Encryption failed");

  /* Emit only cipher.iv — the key is NOT included in the output. */
  char *b64_cipher = base64Encode(cipher, cipher_len);
  char *b64_iv     = base64Encode(crypto.aesIv, crypto.aesIvLength);

  emit_container_line_2(b64_cipher, b64_iv);

  OPENSSL_cleanse(in, in_len);
  free(in); free(cipher); free(b64_cipher); free(b64_iv);
  crypto_cleanup(&crypto);
}

static void do_aes_dec(const char *keyfile_path) {
  unsigned char key[32], iv[16];
  load_aes_keyfile(keyfile_path, key, iv);

  size_t line_len = 0;
  char *line = read_all_stdin_text(&line_len);

  char *p1 = NULL, *p2 = NULL;
  if (!split_2_parts(line, &p1, &p2)) die("Invalid input container line");

  unsigned char *cipher = NULL, *dec_iv = NULL;
  int cipher_len_i = base64Decode(p1, strlen(p1), &cipher);
  int iv_len_i     = base64Decode(p2, strlen(p2), &dec_iv);
  if (cipher_len_i < 0 || iv_len_i < 0) die("Base64 decode failed");
  if (cipher_len_i > INT_MAX || iv_len_i > INT_MAX) die("Decoded field too large");

  Crypto crypto;
  if (crypto_init(&crypto, /*pseudo_client=*/0) != 0) die("Failed to initialize crypto");

  if ((size_t)iv_len_i != crypto.aesIvLength)
    die("IV in container has wrong length");

  memcpy(crypto.aesKey, key, 32);
  memcpy(crypto.aesIv,  dec_iv, (size_t)iv_len_i);
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(iv,  sizeof(iv));

  unsigned char *plain = NULL; size_t plain_len = 0;
  if (crypto_aes_decrypt(&crypto, cipher, (size_t)cipher_len_i, &plain, &plain_len) != 0)
    die("Decryption failed");

  write_all_stdout(plain, plain_len);

  OPENSSL_cleanse(plain, plain_len);
  free(line); free(cipher); free(dec_iv); free(plain);
  crypto_cleanup(&crypto);
}

static void do_aes_keygen(const char *keyfile_path) {
  unsigned char buf[AES_KEYFILE_SIZE];
  if (RAND_bytes(buf, AES_KEYFILE_SIZE) != 1)
    die("Failed to generate random key material");

  FILE *f = fopen(keyfile_path, "wb");
  if (!f) { fprintf(stderr, "Cannot create key file: %s\n", keyfile_path); exit(1); }
  if (fwrite(buf, 1, AES_KEYFILE_SIZE, f) != AES_KEYFILE_SIZE) {
    fclose(f);
    die("Failed to write key file");
  }
  fclose(f);
  OPENSSL_cleanse(buf, AES_KEYFILE_SIZE);
  fprintf(stderr, "AES key written to %s\n", keyfile_path);
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    printf("crypto %s\n", CRYPTO_VERSION);
    return 0;
  }
  if (argc != 3) usage(argv[0]);
  const char *mode    = argv[1];
  const char *keyfile = argv[2];

  if      (strcmp(mode, "rsa-enc")    == 0) do_rsa_enc(keyfile);
  else if (strcmp(mode, "rsa-dec")    == 0) do_rsa_dec(keyfile);
  else if (strcmp(mode, "aes-enc")    == 0) do_aes_enc(keyfile);
  else if (strcmp(mode, "aes-dec")    == 0) do_aes_dec(keyfile);
  else if (strcmp(mode, "aes-keygen") == 0) do_aes_keygen(keyfile);
  else usage(argv[0]);

  return 0;
}
