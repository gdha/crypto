gcc -std=c11 -Wall -Wextra -O2 \
  crypto.c crypto-func.c base64.c \
  -o crypto \
  -lssl -lcrypto
