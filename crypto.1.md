# crypto(1) -- Tool to encrypt or decrypt standard input using OpenSSL (RSA seal/open or AES-256-CBC)


## SYNOPSIS

    crypto rsa-enc <pubkey.pem>   < plaintext > container.txt
    crypto rsa-dec <privkey.pem>  < container.txt > plaintext

    crypto aes-keygen <keyfile>
    crypto aes-enc <keyfile>      < plaintext > container.txt
    crypto aes-dec <keyfile>      < container.txt > plaintext

## DESCRIPTION

**crypto** is a small CLI tool that reads all data from standard input and writes the result to standard output.

It supports:

- **RSA hybrid encryption** via OpenSSL `EVP_Seal*` / `EVP_Open*` (`rsa-enc` / `rsa-dec`)
- **AES-256-CBC** symmetric encryption via OpenSSL `EVP_Encrypt*` / `EVP_Decrypt*` (`aes-enc` / `aes-dec`)

Every mode requires a key file argument. Keys are never embedded in the output container. The tool is designed for piping and scripting — it prints no interactive prompts and no labels on output.

## MODES

### rsa-enc \<pubkey.pem\>

Reads plaintext bytes from `stdin`, encrypts using RSA hybrid "seal" (RSA-encrypted session key + AES-256-CBC data encryption), and writes a single-line container to `stdout`.

The recipient's **public key** PEM file is required. The corresponding private key never leaves the recipient's side and is never transmitted.

### rsa-dec \<privkey.pem\>

Reads a single-line RSA container from `stdin`, decrypts it using the given **private key** PEM file, and writes plaintext bytes to `stdout`.

### aes-keygen keyfile

Generates 48 cryptographically random bytes (32-byte AES-256 key + 16-byte IV) and writes them to `keyfile`. Use this to create a key file before running `aes-enc` or `aes-dec`. Prints a confirmation message to `stderr`.

### aes-enc keyfile

Reads plaintext bytes from `stdin`, encrypts using AES-256-CBC with the key and IV loaded from `keyfile`, and writes a single-line container to `stdout`.

The key is **not** included in the container output. Both the sender and receiver must possess the same key file.

### aes-dec keyfile

Reads a single-line AES container from `stdin`, loads the key from `keyfile`, and writes plaintext bytes to `stdout`.

## KEY FILE FORMAT

### RSA keys

Standard PEM format, compatible with OpenSSL:

    # Generate a 2048-bit RSA key pair
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
    openssl pkey -in private.pem -pubout -out public.pem

### AES key file

A binary file of exactly **48 bytes**: the first 32 bytes are the AES-256 key, the next 16 bytes are the AES-CBC IV. Use `aes-keygen` to create one.

## CONTAINER FORMAT

All `*-enc` modes output a **single line** to `stdout`:

**RSA container** (`rsa-enc`):

    b64(ciphertext).b64(encryptedSessionKey).b64(IV)

**AES container** (`aes-enc`):

    b64(ciphertext).b64(IV)

Each `b64(...)` is Base64-encoded without newlines. The AES key is **not** present in the container.

## EXAMPLES

### Generate an RSA key pair and perform a round-trip

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
    openssl pkey -in private.pem -pubout -out public.pem

    printf "hello\n" | ./crypto rsa-enc public.pem | ./crypto rsa-dec private.pem

### Generate an AES key file and perform a round-trip

    ./crypto aes-keygen my.key
    printf "test" | ./crypto aes-enc my.key | ./crypto aes-dec my.key

### Encrypt a file and decrypt it

    ./crypto aes-keygen my.key
    ./crypto aes-enc my.key < input.bin > out.container
    ./crypto aes-dec my.key < out.container > input.bin.recovered

## EXIT STATUS

- **0** on success
- **1** on errors (missing/invalid key file, invalid container, crypto failure, I/O failure)
- **2** on usage error (wrong number of arguments or unknown mode)

## SECURITY NOTES

- RSA containers do **not** embed any key material. Confidentiality relies entirely on keeping the private key file secret.
- AES containers do **not** embed the key. The key file must be kept secret and shared securely out-of-band with the decrypting party.
- Input is limited to 256 MiB to prevent unbounded memory growth.
- Key material is wiped from memory using `OPENSSL_cleanse` before being freed.

## SEE ALSO

**openssl(1)**, **openssl-genpkey(1)**, **openssl-pkey(1)**, OpenSSL EVP documentation

## AUTHOR

Original from the `shanet/Crypto-Example` repository.

Updated by Gratien Dhaese
