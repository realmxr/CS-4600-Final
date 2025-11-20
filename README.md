# CS 4600 Final Project – Secure File Transfer Demo

This repository contains two standalone C programs that implement the sender (“client”) and receiver (“server”) roles required by the final project specification. They use the OpenSSL crypto library to meet all requirements:

- Each side owns an RSA key pair (default 3072 bits, configurable ≥ 2048).
- Messages are encrypted with AES‑256‑CBC before transmission.
- The AES session key is wrapped with the receiver’s RSA public key using OAEP padding.
- An HMAC‑SHA256 tag (keyed with the AES session key) covers the IV and ciphertext for integrity and authenticity.
- All data that would cross the network is stored in a local `Transmitted_Data` file so sockets are not required.

## Building

Prerequisites: a C11 compiler, OpenSSL headers/libs (e.g., `libcrypto`), and `make`.

```
make
```

This produces two binaries: `client` (sender) and `server` (receiver).

## Usage

Both binaries expose two subcommands.

### Key generation

```
client --gen-keys client_private.pem client_public.pem [bits]
server --gen-keys server_private.pem server_public.pem [bits]
```

The optional `bits` argument defaults to 3072. Run once per party, then exchange the public key files.

### Sending a message

```
client --send plaintext.txt server_public.pem Transmitted_Data.bin
```

Steps performed:

1. Reads `plaintext.txt`.
2. Generates a random 32‑byte AES key and 16‑byte IV.
3. Encrypts the plaintext with AES‑256‑CBC.
4. Builds an HMAC‑SHA256 over IV||ciphertext using the AES key.
5. Wraps the AES key with the server’s RSA public key (OAEP).
6. Stores everything inside `Transmitted_Data.bin` (magic, version, then length‑prefixed blocks for the encrypted AES key, IV, ciphertext, and MAC).

### Receiving a message

```
server --receive Transmitted_Data.bin server_private.pem decrypted.txt
```

Steps performed:

1. Validates the file header and structure.
2. Uses the receiver’s RSA private key to recover the AES key.
3. Recomputes HMAC‑SHA256 over IV||ciphertext and compares it (constant time).
4. Decrypts the ciphertext with AES‑256‑CBC.
5. Writes the original plaintext to `decrypted.txt`.

If any step fails (wrong file, tampering, or wrong key) the program aborts with an error message.

## File format reference

`Transmitted_Data.bin` layout:

```
Offset  Size  Description
0       4     ASCII "TRNS"
4       1     Version byte (currently 0x01)
5       4     Big‑endian length of encrypted AES key (L1)
9       L1    RSA‑encrypted AES key (OAEP)
…       4     Big‑endian length of IV (L2, expected 16)
…       L2    AES IV
…       4     Big‑endian length of ciphertext (L3)
…       L3    AES‑256‑CBC ciphertext
…       4     Big‑endian length of HMAC tag (L4, expected 32)
…       L4    HMAC‑SHA256 tag
```

Parsing and serialization helpers live in `src/transmission.c`.

## Extending or testing

- Replace AES/HMAC parameters or add additional metadata by changing `TransmissionPackage` usage.
- Use different files to simulate multiple messages—each `client --send` call overwrites the output path you choose.
- Run `make clean` to remove the binaries.

The project avoids socket code per the instructions but can be adapted to real networking by sending the same serialized payload over a socket instead of writing it to disk.

