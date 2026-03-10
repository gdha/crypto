gcc -std=c11 -Wall -Wextra -O2 \
  crypto.c crypto-func.c base64.c \
  -o crypto \
  -lssl -lcrypto

# To build a static and stripped binary (OpenSSL statically linked,
# glibc dynamically linked to avoid linker warnings about dlopen/getaddrinfo):
# gcc -std=c11 -Wall -Wextra -O2 \
#   crypto.c crypto-func.c base64.c \
#   -Wl,-s \
#   -o crypto \
#   -Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic -ldl
