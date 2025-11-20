#include "crypto_utils.h"
#include "transmission.h"

#include <openssl/crypto.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_RSA_BITS 3072

static void print_usage(void) {
    printf("Secure Receiver (server) utility\n");
    printf("Usage:\n");
    printf("  server --gen-keys <private.pem> <public.pem> [bits]\n");
    printf("  server --receive <transmitted.bin> <receiver_private.pem> <plaintext_out.txt>\n");
}

static int secure_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
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

static int handle_receive(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Missing arguments for --receive\n");
        print_usage();
        return 1;
    }

    const char *transmission_path = argv[2];
    const char *priv_key_path = argv[3];
    const char *output_plain_path = argv[4];

    TransmissionPackage pkg;
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char *mac_input = NULL;
    size_t mac_input_len = 0;
    unsigned char *computed_mac = NULL;
    unsigned int computed_mac_len = 0;
    unsigned char *plaintext = NULL;
    int plaintext_len = 0;
    EVP_PKEY *receiver_key = NULL;
    unsigned char *decrypted_key = NULL;
    size_t decrypted_key_len = 0;
    int exit_code = 1;

    if (!read_transmission_package(transmission_path, &pkg)) {
        fprintf(stderr, "Unable to read transmission file\n");
        return 1;
    }

    if (pkg.iv_len != AES_IV_SIZE) {
        fprintf(stderr, "Invalid IV length in transmission file\n");
        goto cleanup;
    }

    receiver_key = load_private_key(priv_key_path);
    if (!receiver_key) {
        fprintf(stderr, "Unable to load private key\n");
        goto cleanup;
    }

    if (!rsa_private_decrypt(receiver_key,
                             pkg.encrypted_key,
                             pkg.encrypted_key_len,
                             &decrypted_key,
                             &decrypted_key_len)) {
        fprintf(stderr, "Failed to decrypt AES key\n");
        goto cleanup;
    }

    if (decrypted_key_len != AES_KEY_SIZE) {
        fprintf(stderr, "Unexpected AES key length\n");
        goto cleanup;
    }
    memcpy(aes_key, decrypted_key, AES_KEY_SIZE);

    mac_input_len = pkg.iv_len + pkg.ciphertext_len;
    mac_input = (unsigned char *)malloc(mac_input_len);
    if (!mac_input) {
        perror("Failed to allocate MAC input buffer");
        goto cleanup;
    }
    memcpy(mac_input, pkg.iv, pkg.iv_len);
    memcpy(mac_input + pkg.iv_len, pkg.ciphertext, pkg.ciphertext_len);

    if (!compute_hmac_sha256(aes_key, AES_KEY_SIZE, mac_input, mac_input_len, &computed_mac, &computed_mac_len)) {
        fprintf(stderr, "Failed to compute HMAC\n");
        goto cleanup;
    }

    if (computed_mac_len != pkg.mac_len || !secure_compare(pkg.mac, computed_mac, pkg.mac_len)) {
        fprintf(stderr, "MAC verification failed\n");
        goto cleanup;
    }

    if (!aes256_cbc_decrypt(pkg.ciphertext, (int)pkg.ciphertext_len, aes_key, pkg.iv, &plaintext, &plaintext_len)) {
        fprintf(stderr, "AES decryption failed\n");
        goto cleanup;
    }

    if (!write_whole_file(output_plain_path, plaintext, (size_t)plaintext_len)) {
        fprintf(stderr, "Failed to write plaintext output\n");
        goto cleanup;
    }

    printf("Message authenticated and written to %s\n", output_plain_path);
    exit_code = 0;

cleanup:
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    if (mac_input) {
        OPENSSL_cleanse(mac_input, mac_input_len);
        free(mac_input);
    }
    if (computed_mac) {
        OPENSSL_cleanse(computed_mac, computed_mac_len);
        free(computed_mac);
    }
    if (plaintext) {
        OPENSSL_cleanse(plaintext, (size_t)plaintext_len);
        free(plaintext);
    }
    if (receiver_key) {
        EVP_PKEY_free(receiver_key);
    }
    if (decrypted_key) {
        OPENSSL_cleanse(decrypted_key, decrypted_key_len);
        free(decrypted_key);
    }
    free_transmission_package(&pkg);
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

    if (strcmp(argv[1], "--receive") == 0) {
        return handle_receive(argc, argv);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    print_usage();
    return 1;
}

