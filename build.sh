gcc -std=c11 -Wall -Wextra -O2 \
  crypto.c crypto-func.c base64.c \
  -o crypto \
  -lssl -lcrypto

# To build a static and stripped binary:
# gcc -std=c11 -Wall -Wextra -O2 \
#   crypto.c crypto-func.c base64.c \
#   -static -Wl,-s \
#   -o crypto \
#   -lssl -lcrypto
