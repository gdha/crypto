#include "crypto.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static int generate_rsa_keypair(EVP_PKEY **keypair) {
  int ok = 0;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx) return FAILURE;

  if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0) goto done;
  if (EVP_PKEY_keygen(ctx, keypair) <= 0) goto done;

  ok = 1;
done:
  EVP_PKEY_CTX_free(ctx);
  return ok ? SUCCESS : FAILURE;
}

static int generate_aes_key_iv(Crypto *c) {
  c->aesKey = (unsigned char *)malloc(c->aesKeyLength);
  c->aesIv  = (unsigned char *)malloc(c->aesIvLength);
  if (!c->aesKey || !c->aesIv) return FAILURE;

  if (RAND_bytes(c->aesKey, (int)c->aesKeyLength) != 1) return FAILURE;
  if (RAND_bytes(c->aesIv,  (int)c->aesIvLength)  != 1) return FAILURE;

  return SUCCESS;
}

int crypto_init(Crypto *c, int pseudo_client) {
  memset(c, 0, sizeof(*c));
  c->pseudo_client = pseudo_client ? 1 : 0;

  c->rsaEncryptContext = EVP_CIPHER_CTX_new();
  c->aesEncryptContext = EVP_CIPHER_CTX_new();
  c->rsaDecryptContext = EVP_CIPHER_CTX_new();
  c->aesDecryptContext = EVP_CIPHER_CTX_new();
  if (!c->rsaEncryptContext || !c->aesEncryptContext || !c->rsaDecryptContext || !c->aesDecryptContext) {
    return FAILURE;
  }

  /* Establish AES key/iv lengths like the original */
  if (EVP_CipherInit_ex(c->aesEncryptContext, EVP_aes_256_cbc(), NULL, NULL, NULL, 1) != 1) {
    return FAILURE;
  }
  c->aesKeyLength = (size_t)EVP_CIPHER_CTX_key_length(c->aesEncryptContext);
  c->aesIvLength  = (size_t)EVP_CIPHER_CTX_iv_length(c->aesEncryptContext);

  if (generate_rsa_keypair(&c->localKeypair) != SUCCESS) return FAILURE;

  if (c->pseudo_client) {
    /* original code generates a remote keypair for demo purposes */
    if (generate_rsa_keypair(&c->remotePublicKey) != SUCCESS) return FAILURE;
  } else {
    c->remotePublicKey = NULL;
  }

  if (generate_aes_key_iv(c) != SUCCESS) return FAILURE;

  return SUCCESS;
}

void crypto_cleanup(Crypto *c) {
  if (!c) return;

  EVP_PKEY_free(c->localKeypair);
  EVP_PKEY_free(c->remotePublicKey);

  EVP_CIPHER_CTX_free(c->rsaEncryptContext);
  EVP_CIPHER_CTX_free(c->aesEncryptContext);
  EVP_CIPHER_CTX_free(c->rsaDecryptContext);
  EVP_CIPHER_CTX_free(c->aesDecryptContext);

  free(c->aesKey);
  free(c->aesIv);

  memset(c, 0, sizeof(*c));
}

int crypto_rsa_seal(
  Crypto *c,
  const unsigned char *message, size_t messageLength,
  unsigned char **encryptedMessage, size_t *encryptedMessageLength,
  unsigned char **encryptedKey, size_t *encryptedKeyLength,
  unsigned char **iv, size_t *ivLength
) {
  size_t out_len = 0;
  int block_len = 0;

  *encryptedKey = (unsigned char *)malloc((size_t)EVP_PKEY_size(c->remotePublicKey));
  *iv = (unsigned char *)malloc(EVP_MAX_IV_LENGTH);
  if (!*encryptedKey || !*iv) return FAILURE;

  *ivLength = EVP_MAX_IV_LENGTH;

  *encryptedMessage = (unsigned char *)malloc(messageLength + EVP_MAX_IV_LENGTH);
  if (!*encryptedMessage) return FAILURE;

  if (EVP_SealInit(c->rsaEncryptContext, EVP_aes_256_cbc(),
                   encryptedKey, (int *)encryptedKeyLength,
                   *iv, &c->remotePublicKey, 1) != 1) {
    return FAILURE;
  }

  if (EVP_SealUpdate(c->rsaEncryptContext,
                     *encryptedMessage + out_len, &block_len,
                     message, (int)messageLength) != 1) {
    return FAILURE;
  }
  out_len += (size_t)block_len;

  if (EVP_SealFinal(c->rsaEncryptContext,
                    *encryptedMessage + out_len, &block_len) != 1) {
    return FAILURE;
  }
  out_len += (size_t)block_len;

  *encryptedMessageLength = out_len;
  return SUCCESS;
}

int crypto_rsa_open(
  Crypto *c,
  const unsigned char *encryptedMessage, size_t encryptedMessageLength,
  const unsigned char *encryptedKey, size_t encryptedKeyLength,
  const unsigned char *iv, size_t ivLength,
  unsigned char **decryptedMessage, size_t *decryptedMessageLength
) {
  (void)ivLength; /* OpenSSL uses cipher’s IV length; keep for API symmetry */
  size_t out_len = 0;
  int block_len = 0;

  *decryptedMessage = (unsigned char *)malloc(encryptedMessageLength + ivLength);
  if (!*decryptedMessage) return FAILURE;

  EVP_PKEY *key = c->pseudo_client ? c->remotePublicKey : c->localKeypair;

  if (EVP_OpenInit(c->rsaDecryptContext, EVP_aes_256_cbc(),
                   encryptedKey, (int)encryptedKeyLength, iv, key) != 1) {
    return FAILURE;
  }

  if (EVP_OpenUpdate(c->rsaDecryptContext,
                     *decryptedMessage + out_len, &block_len,
                     encryptedMessage, (int)encryptedMessageLength) != 1) {
    return FAILURE;
  }
  out_len += (size_t)block_len;

  if (EVP_OpenFinal(c->rsaDecryptContext,
                    *decryptedMessage + out_len, &block_len) != 1) {
    return FAILURE;
  }
  out_len += (size_t)block_len;

  *decryptedMessageLength = out_len;
  return SUCCESS;
}

int crypto_aes_encrypt(
  Crypto *c,
  const unsigned char *message, size_t messageLength,
  unsigned char **encryptedMessage, size_t *encryptedMessageLength
) {
  int block_len = 0;
  int out_len = 0;

  *encryptedMessage = (unsigned char *)malloc(messageLength + AES_BLOCK_SIZE);
  if (!*encryptedMessage) return FAILURE;

  if (EVP_EncryptInit_ex(c->aesEncryptContext, EVP_aes_256_cbc(), NULL, c->aesKey, c->aesIv) != 1) return FAILURE;

  if (EVP_EncryptUpdate(c->aesEncryptContext, *encryptedMessage, &block_len, message, (int)messageLength) != 1) return FAILURE;
  out_len = block_len;

  if (EVP_EncryptFinal_ex(c->aesEncryptContext, *encryptedMessage + out_len, &block_len) != 1) return FAILURE;
  out_len += block_len;

  *encryptedMessageLength = (size_t)out_len;
  return SUCCESS;
}

int crypto_aes_decrypt(
  Crypto *c,
  const unsigned char *encryptedMessage, size_t encryptedMessageLength,
  unsigned char **decryptedMessage, size_t *decryptedMessageLength
) {
  int block_len = 0;
  int out_len = 0;

  *decryptedMessage = (unsigned char *)malloc(encryptedMessageLength + 1);
  if (!*decryptedMessage) return FAILURE;

  if (EVP_DecryptInit_ex(c->aesDecryptContext, EVP_aes_256_cbc(), NULL, c->aesKey, c->aesIv) != 1) return FAILURE;

  if (EVP_DecryptUpdate(c->aesDecryptContext, *decryptedMessage, &block_len, encryptedMessage, (int)encryptedMessageLength) != 1) return FAILURE;
  out_len = block_len;

  if (EVP_DecryptFinal_ex(c->aesDecryptContext, *decryptedMessage + out_len, &block_len) != 1) return FAILURE;
  out_len += block_len;

  (*decryptedMessage)[out_len] = '\0';
  *decryptedMessageLength = (size_t)out_len;
  return SUCCESS;
}

void crypto_get_aes_key(Crypto *c, const unsigned char **aesKey, size_t *aesKeyLength) {
  *aesKey = c->aesKey;
  *aesKeyLength = c->aesKeyLength;
}

void crypto_get_aes_iv(Crypto *c, const unsigned char **aesIv, size_t *aesIvLength) {
  *aesIv = c->aesIv;
  *aesIvLength = c->aesIvLength;
}

int crypto_write_key_to_file(Crypto *c, FILE *file, int key) {
  switch (key) {
    case KEY_SERVER_PRI:
      return PEM_write_PrivateKey(file, c->localKeypair, NULL, NULL, 0, 0, NULL) ? SUCCESS : FAILURE;
    case KEY_SERVER_PUB:
      return PEM_write_PUBKEY(file, c->localKeypair) ? SUCCESS : FAILURE;
    case KEY_CLIENT_PUB:
      return PEM_write_PUBKEY(file, c->remotePublicKey) ? SUCCESS : FAILURE;
    case KEY_AES:
      return (fwrite(c->aesKey, 1, c->aesKeyLength, file) == c->aesKeyLength) ? SUCCESS : FAILURE;
    case KEY_AES_IV:
      return (fwrite(c->aesIv, 1, c->aesIvLength, file) == c->aesIvLength) ? SUCCESS : FAILURE;
    default:
      return FAILURE;
  }
}
