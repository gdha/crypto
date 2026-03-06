#ifndef CRYPTO_C_H
#define CRYPTO_C_H

#include <stddef.h>
#include <stdio.h>

#include <openssl/evp.h>

#define RSA_KEYLEN 2048
#define AES_ROUNDS 6

#define SUCCESS 0
#define FAILURE -1

#define KEY_SERVER_PRI 0
#define KEY_SERVER_PUB 1
#define KEY_CLIENT_PUB 2
#define KEY_AES        3
#define KEY_AES_IV     4

typedef struct Crypto {
  EVP_PKEY *localKeypair;
  EVP_PKEY *remotePublicKey;

  EVP_CIPHER_CTX *rsaEncryptContext;
  EVP_CIPHER_CTX *aesEncryptContext;

  EVP_CIPHER_CTX *rsaDecryptContext;
  EVP_CIPHER_CTX *aesDecryptContext;

  unsigned char *aesKey;
  unsigned char *aesIv;

  size_t aesKeyLength;
  size_t aesIvLength;

  int pseudo_client; /* mirrors PSEUDO_CLIENT behavior in C++ code */
} Crypto;

int crypto_init(Crypto *c, int pseudo_client);
void crypto_cleanup(Crypto *c);

int crypto_rsa_seal(
  Crypto *c,
  const unsigned char *message, size_t messageLength,
  unsigned char **encryptedMessage, size_t *encryptedMessageLength,
  unsigned char **encryptedKey, size_t *encryptedKeyLength,
  unsigned char **iv, size_t *ivLength);

int crypto_rsa_open(
  Crypto *c,
  const unsigned char *encryptedMessage, size_t encryptedMessageLength,
  const unsigned char *encryptedKey, size_t encryptedKeyLength,
  const unsigned char *iv, size_t ivLength,
  unsigned char **decryptedMessage, size_t *decryptedMessageLength);

int crypto_aes_encrypt(
  Crypto *c,
  const unsigned char *message, size_t messageLength,
  unsigned char **encryptedMessage, size_t *encryptedMessageLength);

int crypto_aes_decrypt(
  Crypto *c,
  const unsigned char *encryptedMessage, size_t encryptedMessageLength,
  unsigned char **decryptedMessage, size_t *decryptedMessageLength);

void crypto_get_aes_key(Crypto *c, const unsigned char **aesKey, size_t *aesKeyLength);
void crypto_get_aes_iv(Crypto *c, const unsigned char **aesIv, size_t *aesIvLength);

int crypto_write_key_to_file(Crypto *c, FILE *file, int key);

#endif