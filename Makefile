CC ?= gcc
CFLAGS ?= -Wall -Wextra -pedantic -std=c11
OPENSSL_LIBS ?= -lcrypto
SRC = src/crypto_utils.c src/transmission.c

.PHONY: all clean

all: client server

client: $(SRC) src/client.c
	$(CC) $(CFLAGS) $^ -o $@ $(OPENSSL_LIBS)

server: $(SRC) src/server.c
	$(CC) $(CFLAGS) $^ -o $@ $(OPENSSL_LIBS)

clean:
	$(RM) client server

