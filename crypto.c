/*
Single-line container format for AES/RSA:

  <b64(cipher)>.<b64(key_or_encryptedKey)>.<b64(iv)>\n

- rsa-enc emits: b64(cipher).b64(encryptedKey).b64(iv)
- rsa-dec expects that single line
- aes-enc emits: b64(cipher).b64(aesKey).b64(aesIv)
- aes-dec expects that single line

This makes `... | aes-enc | aes-dec` work across processes with no env vars.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "base64.h"

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

    if (len == cap) {
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

  while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r' || raw[n - 1] == ' ' || raw[n - 1] == '\t'))
    n--;

  char *s = (char *)malloc(n + 1);
  if (!s) die("OOM");
  memcpy(s, raw, n);
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
          "Usage: %s <rsa-enc|rsa-dec|aes-enc|aes-dec>\n"
          "Reads from stdin, writes to stdout.\n"
          "\n"
          "Container format (single line): b64(part1).b64(part2).b64(part3)\\n\n",
          argv0);
  exit(2);
}

static int split_3_parts(char *s, char **p1, char **p2, char **p3) {
  /* In-place split on '.' into exactly 3 parts */
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

  *p1 = a;
  *p2 = b;
  *p3 = c;
  return 1;
}

static void emit_container_line(const char *b64_1, const char *b64_2, const char *b64_3) {
  fputs(b64_1, stdout);
  fputc('.', stdout);
  fputs(b64_2, stdout);
  fputc('.', stdout);
  fputs(b64_3, stdout);
  fputc('\n', stdout);
}

int main(int argc, char **argv) {
  if (argc != 2) usage(argv[0]);
  const char *mode = argv[1];

  Crypto crypto;
  if (crypto_init(&crypto, /*pseudo_client=*/1) != 0) die("Failed to initialize crypto");

  if (strcmp(mode, "aes-enc") == 0) {
    size_t in_len = 0;
    unsigned char *in = read_all_stdin(&in_len);

    unsigned char *cipher = NULL;
    size_t cipher_len = 0;
    if (crypto_aes_encrypt(&crypto, in, in_len, &cipher, &cipher_len) != 0) die("Encryption failed");

    const unsigned char *aesKey = NULL;
    size_t aesKeyLen = 0;
    crypto_get_aes_key(&crypto, &aesKey, &aesKeyLen);

    const unsigned char *aesIv = NULL;
    size_t aesIvLen = 0;
    crypto_get_aes_iv(&crypto, &aesIv, &aesIvLen);

    char *b64_cipher = base64Encode(cipher, cipher_len);
    char *b64_key    = base64Encode(aesKey, aesKeyLen);
    char *b64_iv     = base64Encode(aesIv, aesIvLen);

    emit_container_line(b64_cipher, b64_key, b64_iv);

    free(in);
    free(cipher);
    free(b64_cipher);
    free(b64_key);
    free(b64_iv);
  } else if (strcmp(mode, "aes-dec") == 0) {
    size_t line_len = 0;
    char *line = read_all_stdin_text(&line_len);

    char *p1 = NULL, *p2 = NULL, *p3 = NULL;
    if (!split_3_parts(line, &p1, &p2, &p3)) die("Invalid input container line");

    unsigned char *cipher = NULL, *key = NULL, *iv = NULL;
    int cipher_len_i = base64Decode(p1, strlen(p1), &cipher);
    int key_len_i    = base64Decode(p2, strlen(p2), &key);
    int iv_len_i     = base64Decode(p3, strlen(p3), &iv);
    if (cipher_len_i < 0 || key_len_i < 0 || iv_len_i < 0) die("Base64 decode failed");

    if ((size_t)key_len_i != crypto.aesKeyLength || (size_t)iv_len_i != crypto.aesIvLength) {
      die("Embedded AES key/iv have wrong length");
    }

    memcpy(crypto.aesKey, key, (size_t)key_len_i);
    memcpy(crypto.aesIv,  iv,  (size_t)iv_len_i);

    unsigned char *plain = NULL;
    size_t plain_len = 0;
    if (crypto_aes_decrypt(&crypto, cipher, (size_t)cipher_len_i, &plain, &plain_len) != 0) die("Decryption failed");

    write_all_stdout(plain, plain_len);

    free(line);
    free(cipher);
    free(key);
    free(iv);
    free(plain);
  } else if (strcmp(mode, "rsa-enc") == 0) {
    size_t in_len = 0;
    unsigned char *in = read_all_stdin(&in_len);

    unsigned char *cipher = NULL;
    size_t cipher_len = 0;
    unsigned char *ek = NULL;
    size_t ek_len = 0;
    unsigned char *iv = NULL;
    size_t iv_len = 0;

    if (crypto_rsa_seal(&crypto, in, in_len, &cipher, &cipher_len, &ek, &ek_len, &iv, &iv_len) != 0) die("Encryption failed");

    char *b64_cipher = base64Encode(cipher, cipher_len);
    char *b64_ek     = base64Encode(ek, ek_len);
    char *b64_iv     = base64Encode(iv, iv_len);

    emit_container_line(b64_cipher, b64_ek, b64_iv);

    free(in);
    free(cipher);
    free(ek);
    free(iv);
    free(b64_cipher);
    free(b64_ek);
    free(b64_iv);
  } else if (strcmp(mode, "rsa-dec") == 0) {
    size_t line_len = 0;
    char *line = read_all_stdin_text(&line_len);

    char *p1 = NULL, *p2 = NULL, *p3 = NULL;
    if (!split_3_parts(line, &p1, &p2, &p3)) die("Invalid input container line");

    unsigned char *cipher = NULL, *ek = NULL, *iv = NULL;
    int cipher_len_i = base64Decode(p1, strlen(p1), &cipher);
    int ek_len_i     = base64Decode(p2, strlen(p2), &ek);
    int iv_len_i     = base64Decode(p3, strlen(p3), &iv);
    if (cipher_len_i < 0 || ek_len_i < 0 || iv_len_i < 0) die("Base64 decode failed");

    unsigned char *plain = NULL;
    size_t plain_len = 0;
    if (crypto_rsa_open(&crypto,
                        cipher, (size_t)cipher_len_i,
                        ek, (size_t)ek_len_i,
                        iv, (size_t)iv_len_i,
                        &plain, &plain_len) != 0) {
      die("Decryption failed");
    }

    write_all_stdout(plain, plain_len);

    free(line);
    free(cipher);
    free(ek);
    free(iv);
    free(plain);
  } else {
    usage(argv[0]);
  }

  crypto_cleanup(&crypto);
  return 0;
}
