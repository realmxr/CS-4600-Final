/*
 * client.c
 * CLI sender that generates keys and encrypts messages for delivery.
 */

#include "crypto_utils.h"
#include "transmission.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Industry standard RSA key size.
#define DEFAULT_RSA_BITS 2048

// Print CLI help/usage banner.
static void print_usage(void) {
    printf("Secure Sender (client) utility\n");
    printf("Usage:\n");
    printf("  client --gen-keys <private.pem> <public.pem>\n");
    printf("  client --send <plaintext.txt> <receiver_public.pem> <sender_private.pem>\n");
}

// Handle `--gen-keys` CLI command.
static int handle_generate_keys(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Expected exactly two paths for --gen-keys\n");
        print_usage();
        return 1;
    }

    const char *priv = argv[2];
    const char *pub = argv[3];
    const int bits = DEFAULT_RSA_BITS; // Utilize default RSA key size

    if (!generate_rsa_keypair(priv, pub, bits)) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    printf("Generated RSA key pair (%d bits):\n", bits);
    printf("  Private key: %s\n", priv);
    printf("  Public key : %s\n", pub);
    return 0;
}

// Handle `--send` CLI command.
static int handle_send(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "Expected plaintext path, receiver public key, and sender private key for --send\n");
        print_usage();
        return 1;
    }

    const char *plaintext_path = argv[2];
    const char *receiver_pub_path = argv[3];
    const char *sender_priv_path = argv[4];
    const char *output_path = "ciphertext.bin";

    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;
    unsigned char *mac = NULL;
    unsigned int mac_len = 0;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    unsigned char *mac_input = NULL;
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[AES_IV_SIZE];
    EVP_PKEY *receiver_key = NULL;
    EVP_PKEY *sender_key = NULL;
    unsigned char *encrypted_key = NULL;
    size_t encrypted_key_len = 0;
    size_t mac_input_len = 0;
    int exit_code = 1;

    // Fresh AES key + IV per message to ensure forward secrecy.
    if (RAND_bytes(aes_key, AES_KEY_SIZE) != 1 || RAND_bytes(iv, AES_IV_SIZE) != 1) {
        handle_openssl_error("Failed to generate random AES material");
        goto cleanup;
    }

    if (!read_whole_file(plaintext_path, &plaintext, &plaintext_len)) {
        fprintf(stderr, "Failed to read plaintext file\n");
        goto cleanup;
    }

    // Encrypt the plaintext
    if (!aes256_cbc_encrypt(plaintext, (int)plaintext_len, aes_key, iv, &ciphertext, &ciphertext_len)) {
        fprintf(stderr, "AES encryption failed\n");
        goto cleanup;
    }

    // HMAC covers IV || ciphertext to protect both values.
    mac_input_len = AES_IV_SIZE + (size_t)ciphertext_len;
    mac_input = (unsigned char *)malloc(mac_input_len);
    if (!mac_input) {
        perror("Failed to allocate MAC input buffer");
        goto cleanup;
    }
    memcpy(mac_input, iv, AES_IV_SIZE);
    memcpy(mac_input + AES_IV_SIZE, ciphertext, (size_t)ciphertext_len);

    // Compute the HMAC
    if (!compute_hmac_sha256(aes_key, AES_KEY_SIZE, mac_input, mac_input_len, &mac, &mac_len)) {
        fprintf(stderr, "Failed to compute HMAC\n");
        goto cleanup;
    }

    // Load the receiver public key
    receiver_key = load_public_key(receiver_pub_path);
    if (!receiver_key) {
        fprintf(stderr, "Unable to load receiver public key\n");
        goto cleanup;
    }

    // Load the sender private key
    sender_key = load_private_key(sender_priv_path);
    if (!sender_key) {
        fprintf(stderr, "Unable to load sender private key\n");
        goto cleanup;
    }

    // Wrap the symmetric key with the receiver's RSA key.
    if (!rsa_public_encrypt(receiver_key, aes_key, AES_KEY_SIZE, &encrypted_key, &encrypted_key_len)) {
        fprintf(stderr, "RSA encryption of AES key failed\n");
        goto cleanup;
    }

    // Sign the MAC
    if (!rsa_sign(sender_key, mac, mac_len, &signature, &signature_len)) {
        fprintf(stderr, "Failed to sign MAC\n");
        goto cleanup;
    }

    // Persist everything in a single transport-friendly blob.
    TransmissionPackage pkg = {
        .encrypted_key = encrypted_key,
        .encrypted_key_len = encrypted_key_len,
        .iv = iv,
        .iv_len = AES_IV_SIZE,
        .ciphertext = ciphertext,
        .ciphertext_len = (size_t)ciphertext_len,
        .mac = mac,
        .mac_len = mac_len,
        .signature = signature,
        .signature_len = signature_len};

    // Write the package to the file
    if (!write_transmission_package(output_path, &pkg)) {
        fprintf(stderr, "Failed to write transmission file\n");
        goto cleanup;
    }

    printf("Message encrypted and written to %s\n", output_path);
    exit_code = 0;

cleanup:
    if (plaintext) {
        free(plaintext);
    }
    if (ciphertext) {
        free(ciphertext);
    }
    if (mac_input) {
        free(mac_input);
    }
    if (mac) {
        free(mac);
    }
    if (receiver_key) {
        EVP_PKEY_free(receiver_key);
    }
    if (sender_key) {
        EVP_PKEY_free(sender_key);
    }
    if (encrypted_key) {
        free(encrypted_key);
    }
    if (signature) {
        free(signature);
    }
    return exit_code;
}

// Entry point for the CLI sender tool.
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

