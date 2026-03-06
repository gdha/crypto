# crypto(1) -- Tool to encrypt or decrypt standard input using OpenSSL (RSA seal/open or AES-256-CBC)


## SYNOPSIS

    crypto rsa-enc   < plaintext > container.txt
    crypto rsa-dec   < container.txt > plaintext
    
    crypto aes-enc   < plaintext > container.txt
    crypto aes-dec   < container.txt > plaintext

## DESCRIPTION

**crypto** is a small CLI tool that reads all data from standard input and writes the result to standard output.

It supports:

- **RSA hybrid encryption** via OpenSSL `EVP_Seal*` / `EVP_Open*` (`rsa-enc` / `rsa-dec`)
- **AES-256-CBC** symmetric encryption via OpenSSL `EVP_Encrypt*` / `EVP_Decrypt*` (`aes-enc` / `aes-dec`)

The tool is designed for piping and scripting. It prints no interactive prompts and no "Decrypted message:" labels.

## MODES

### rsa-enc

Reads plaintext bytes from `stdin`, encrypts using RSA hybrid "seal" (RSA-encrypted session key + AES-256-CBC data encryption), and writes a single-line container to `stdout`.

### rsa-dec

Reads a single-line container from `stdin`, decrypts it using RSA hybrid "open", and writes plaintext bytes to `stdout`.

### aes-enc

Reads plaintext bytes from `stdin`, encrypts using AES-256-CBC with a randomly generated key and IV, and writes a single-line container (including key+IV) to `stdout`.

### aes-dec

Reads a single-line container from `stdin`, extracts the AES key+IV from the container, decrypts, and writes plaintext bytes to `stdout`.

## CONTAINER FORMAT

All `*-enc` modes output a **single line** in the following format:

    b64(part1).b64(part2).b64(part3)

Where:

For **RSA**:

  - `part1` = ciphertext
  - `part2` = encrypted session key (from `EVP_SealInit`)
  - `part3` = IV
  - `part4` = privateKey

For **AES**:

  - `part1` = ciphertext
  - `part2` = raw AES key (32 bytes for AES-256)
  - `part3` = raw AES IV (16 bytes for AES-256-CBC)

Each `b64(...)` is Base64 without newlines.

## EXAMPLES

### AES round-trip

    printf "test" | ./crypto aes-enc | ./crypto aes-dec

### RSA round-trip

    printf "hello\n" | ./crypto rsa-enc | ./crypto rsa-dec

### Save encrypted output to a file

    cat input.bin | ./crypto aes-enc > out.container
    cat out.container | ./crypto aes-dec > input.bin.recovered

## EXIT STATUS

- **0** on success
- **1** on errors (invalid input, crypto failure, I/O failure)
- **2** on usage error (wrong arguments)

## NOTES

- The **AES container includes the key and IV**, so it is suitable only as a format demonstration. Anyone with the container can decrypt it.
- `aes-dec` and `rsa-dec` expect the full container on `stdin` (one line).
- Base64 decoding errors or malformed containers will cause the program to print an error to `stderr` and exit non-zero.

## SEE ALSO

**openssl(1)**, OpenSSL EVP documentation

## AUTHOR

Original is from the `shanet/Crypto-Example` repository.

Updated by Gratien Dhaese
