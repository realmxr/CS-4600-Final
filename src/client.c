#include "crypto_utils.h"
#include "transmission.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_RSA_BITS 3072

static void print_usage(void) {
    printf("Secure Sender (client) utility\n");
    printf("Usage:\n");
    printf("  client --gen-keys <private.pem> <public.pem> [bits]\n");
    printf("  client --send <plaintext.txt> <receiver_public.pem> <transmitted.bin>\n");
}

static int handle_generate_keys(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Missing arguments for --gen-keys\n");
        print_usage();
        return 1;
    }

    const char *priv = argv[2];
    const char *pub = argv[3];
    int bits = (argc >= 5) ? atoi(argv[4]) : DEFAULT_RSA_BITS;
    if (bits < 2048) {
        fprintf(stderr, "RSA key size must be at least 2048 bits\n");
        return 1;
    }

    if (!generate_rsa_keypair(priv, pub, bits)) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    printf("Generated RSA key pair (%d bits):\n", bits);
    printf("  Private key: %s\n", priv);
    printf("  Public key : %s\n", pub);
    return 0;
}

static int handle_send(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Missing arguments for --send\n");
        print_usage();
        return 1;
    }

    const char *plaintext_path = argv[2];
    const char *receiver_pub_path = argv[3];
    const char *output_path = argv[4];

    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;
    unsigned char *mac = NULL;
    unsigned int mac_len = 0;
    unsigned char *mac_input = NULL;
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    EVP_PKEY *receiver_key = NULL;
    unsigned char *encrypted_key = NULL;
    size_t encrypted_key_len = 0;
    size_t mac_input_len = 0;
    int exit_code = 1;

    if (RAND_bytes(aes_key, AES_KEY_SIZE) != 1 || RAND_bytes(iv, AES_IV_SIZE) != 1) {
        handle_openssl_error("Failed to generate random AES material");
        goto cleanup;
    }

    if (!read_whole_file(plaintext_path, &plaintext, &plaintext_len)) {
        fprintf(stderr, "Failed to read plaintext file\n");
        goto cleanup;
    }

    if (!aes256_cbc_encrypt(plaintext, (int)plaintext_len, aes_key, iv, &ciphertext, &ciphertext_len)) {
        fprintf(stderr, "AES encryption failed\n");
        goto cleanup;
    }

    mac_input_len = AES_IV_SIZE + (size_t)ciphertext_len;
    mac_input = (unsigned char *)malloc(mac_input_len);
    if (!mac_input) {
        perror("Failed to allocate MAC input buffer");
        goto cleanup;
    }
    memcpy(mac_input, iv, AES_IV_SIZE);
    memcpy(mac_input + AES_IV_SIZE, ciphertext, (size_t)ciphertext_len);

    if (!compute_hmac_sha256(aes_key, AES_KEY_SIZE, mac_input, mac_input_len, &mac, &mac_len)) {
        fprintf(stderr, "Failed to compute HMAC\n");
        goto cleanup;
    }

    receiver_key = load_public_key(receiver_pub_path);
    if (!receiver_key) {
        fprintf(stderr, "Unable to load receiver public key\n");
        goto cleanup;
    }

    if (!rsa_public_encrypt(receiver_key, aes_key, AES_KEY_SIZE, &encrypted_key, &encrypted_key_len)) {
        fprintf(stderr, "RSA encryption of AES key failed\n");
        goto cleanup;
    }

    TransmissionPackage pkg = {
        .encrypted_key = encrypted_key,
        .encrypted_key_len = encrypted_key_len,
        .iv = iv,
        .iv_len = AES_IV_SIZE,
        .ciphertext = ciphertext,
        .ciphertext_len = (size_t)ciphertext_len,
        .mac = mac,
        .mac_len = mac_len};

    if (!write_transmission_package(output_path, &pkg)) {
        fprintf(stderr, "Failed to write transmission file\n");
        goto cleanup;
    }

    printf("Message encrypted and written to %s\n", output_path);
    exit_code = 0;

cleanup:
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        free(plaintext);
    }
    if (ciphertext) {
        OPENSSL_cleanse(ciphertext, (size_t)ciphertext_len);
        free(ciphertext);
    }
    if (mac_input) {
        OPENSSL_cleanse(mac_input, mac_input_len);
        free(mac_input);
    }
    if (mac) {
        OPENSSL_cleanse(mac, mac_len);
        free(mac);
    }
    if (receiver_key) {
        EVP_PKEY_free(receiver_key);
    }
    if (encrypted_key) {
        OPENSSL_cleanse(encrypted_key, encrypted_key_len);
        free(encrypted_key);
    }
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    return exit_code;
}

int main(int argc, char **argv) {
    OPENSSL_init_crypto(0, NULL);
    ERR_load_crypto_strings();

    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "--gen-keys") == 0) {
        return handle_generate_keys(argc, argv);
    }

    if (strcmp(argv[1], "--send") == 0) {
        return handle_send(argc, argv);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    print_usage();
    return 1;
}

