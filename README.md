# crypto

[![C Build and Test](https://github.com/gdha/crypto/actions/workflows/c-build.yml/badge.svg)](https://github.com/gdha/crypto/actions/workflows/c-build.yml)

A small CLI tool that demonstrates OpenSSL EVP APIs for encryption and decryption. It reads data from standard input and writes the result to standard output, making it suitable for shell pipelines and scripting.

## Features

- **RSA hybrid encryption** via OpenSSL `EVP_Seal*` / `EVP_Open*` (`rsa-enc` / `rsa-dec`)
- **AES-256-CBC** symmetric encryption via OpenSSL `EVP_Encrypt*` / `EVP_Decrypt*` (`aes-enc` / `aes-dec`) — **Note:** the AES container embeds the key and IV, so it is for demonstration purposes only
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
crypto rsa-enc   < plaintext > container.txt
crypto rsa-dec   < container.txt > plaintext

crypto aes-enc   < plaintext > container.txt
crypto aes-dec   < container.txt > plaintext
```

### Modes

| Mode | Description |
|------|-------------|
| `rsa-enc` | Encrypt stdin using RSA hybrid seal (RSA-encrypted session key + AES-256-CBC). Writes a single-line container to stdout. |
| `rsa-dec` | Decrypt a single-line RSA container from stdin. Writes plaintext to stdout. |
| `aes-enc` | Encrypt stdin using AES-256-CBC with a randomly generated key and IV. Writes a single-line container (including key and IV) to stdout. |
| `aes-dec` | Decrypt a single-line AES container from stdin (key and IV are embedded). Writes plaintext to stdout. |

## Examples

```bash
# AES round-trip
printf "test" | ./crypto aes-enc | ./crypto aes-dec

# RSA round-trip
printf "hello\n" | ./crypto rsa-enc | ./crypto rsa-dec

# Save encrypted output to a file
cat input.bin | ./crypto aes-enc > out.container
cat out.container | ./crypto aes-dec > input.bin.recovered
```

## Container Format

All `*-enc` modes output a **single line** with Base64-encoded parts separated by dots.

**AES container:**

```
b64(ciphertext).b64(key).b64(IV)
```

**RSA container:**

```
b64(ciphertext).b64(encryptedSessionKey).b64(IV).b64(privateKey)
```

Each `b64(...)` is Base64-encoded without newlines.

## Exit Status

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Cryptographic or I/O error |
| `2` | Usage error (wrong arguments) |

## Notes

- The **AES container includes the key and IV** in plaintext (Base64-encoded), so it is suitable only as a format demonstration. Anyone with the container can decrypt it.
- `aes-dec` and `rsa-dec` expect the full container on stdin (one line).
- Base64 decoding errors or malformed containers will cause the program to print an error to stderr and exit with a non-zero status.

## Testing

```bash
make test
```

Runs a basic AES round-trip: `printf "test" | ./crypto aes-enc | ./crypto aes-dec`.

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