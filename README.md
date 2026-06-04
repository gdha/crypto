# crypto

[![C Build and Test](https://github.com/gdha/crypto/actions/workflows/c-build.yml/badge.svg)](https://github.com/gdha/crypto/actions/workflows/c-build.yml)

A small CLI tool that demonstrates OpenSSL EVP APIs for encryption and decryption. It reads data from standard input and writes the result to standard output, making it suitable for shell pipelines and scripting.

Keys are **never embedded in the output container** — every mode requires a key file argument.

## Features

- **RSA hybrid encryption** via OpenSSL `EVP_Seal*` / `EVP_Open*` (`rsa-enc` / `rsa-dec`) — uses a PEM public key to encrypt, PEM private key to decrypt
- **AES-256-CBC** symmetric encryption via OpenSSL `EVP_Encrypt*` / `EVP_Decrypt*` (`aes-enc` / `aes-dec`) — uses a binary key file; key is never included in the output
- `aes-keygen` subcommand to generate a secure random AES key file
- Input capped at 256 MiB to prevent unbounded memory growth
- Key material wiped from memory with `OPENSSL_cleanse` after use
- Designed for piping: no interactive prompts, no labels on output

## Requirements

- **gcc** – C compiler (C11 standard)
- **make** – Build system
- **OpenSSL 3.x** – `libssl-dev` (Debian/Ubuntu) or `openssl-devel` (RPM-based)
- **ronn** – For generating the man page (`gem install ronn`)

## Building

```bash
make
```

This compiles the `crypto` binary and generates the man page.

## Usage

```
crypto rsa-enc <pubkey.pem>   encrypt stdin with RSA public key
crypto rsa-dec <privkey.pem>  decrypt stdin with RSA private key

crypto aes-keygen <keyfile>   generate a new AES-256 key+iv file
crypto aes-enc <keyfile>      encrypt stdin with AES key file
crypto aes-dec <keyfile>      decrypt stdin with AES key file
```

### Modes

| Mode | Description |
|------|-------------|
| `rsa-enc <pubkey.pem>` | Encrypt stdin using RSA hybrid seal. The recipient's public key PEM is required. Writes a single-line container to stdout. |
| `rsa-dec <privkey.pem>` | Decrypt a single-line RSA container from stdin using the private key PEM. |
| `aes-keygen <keyfile>` | Generate 48 random bytes (32-byte key + 16-byte IV) and write to `keyfile`. |
| `aes-enc <keyfile>` | Encrypt stdin using AES-256-CBC. Key loaded from `keyfile`; key is **not** in the output. |
| `aes-dec <keyfile>` | Decrypt a single-line AES container from stdin. Key loaded from `keyfile`. |

## Key Setup

### RSA

Generate a key pair with OpenSSL:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

Keep `private.pem` secret. Share `public.pem` with anyone who needs to encrypt data for you.

### AES

Generate a key file:

```bash
./crypto aes-keygen my.key
```

This writes 48 random bytes to `my.key` (32-byte AES-256 key + 16-byte IV). Keep this file secret and share it out-of-band with anyone who needs to decrypt.

## Examples

```bash
# RSA round-trip
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
printf "hello\n" | ./crypto rsa-enc public.pem | ./crypto rsa-dec private.pem

# AES round-trip
./crypto aes-keygen my.key
printf "test" | ./crypto aes-enc my.key | ./crypto aes-dec my.key

# Encrypt a file
./crypto aes-enc my.key < input.bin > out.container
./crypto aes-dec my.key < out.container > input.bin.recovered
```

## Container Format

All `*-enc` modes output a **single line** with Base64-encoded parts separated by dots.

**RSA container:**

```
b64(ciphertext).b64(encryptedSessionKey).b64(IV)
```

**AES container:**

```
b64(ciphertext).b64(IV)
```

Each `b64(...)` is Base64-encoded without newlines. Neither container includes the key.

## Exit Status

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Cryptographic, I/O, or key file error |
| `2` | Usage error (wrong arguments or unknown mode) |

## Security Notes

- RSA containers contain no key material. Confidentiality depends on keeping `private.pem` secret.
- AES containers contain only the IV, not the key. The key file must be kept secret and shared securely out-of-band.
- Input is limited to 256 MiB.
- Key material is wiped with `OPENSSL_cleanse` before being freed.

## Testing

```bash
make test
```

Runs a basic AES and RSA round-trip smoke test.

## Installation

```bash
make install
# or with a custom prefix:
make install PREFIX=/usr/local DESTDIR=/path/to/root
```

Installs the `crypto` binary to `$(PREFIX)/bin` and the man page to `$(PREFIX)/share/man/man1`.

## Packaging

```bash
make dist   # Create source tarball
make rpm    # Build RPM package
make deb    # Build DEB package
```

## License

[GNU General Public License v3 (GPLv3)](LICENSE)

## Author

Original from the [`shanet/Crypto-Example`](https://github.com/shanet/Crypto-Example) repository.  
Updated and maintained by [Gratien Dhaese](https://github.com/gdha).
