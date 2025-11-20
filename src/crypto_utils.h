#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <openssl/evp.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

int generate_rsa_keypair(const char *priv_path, const char *pub_path, int bits);

EVP_PKEY *load_public_key(const char *path);
EVP_PKEY *load_private_key(const char *path);

int rsa_public_encrypt(EVP_PKEY *public_key,
                       const unsigned char *plaintext,
                       size_t plaintext_len,
                       unsigned char **ciphertext,
                       size_t *ciphertext_len);

int rsa_private_decrypt(EVP_PKEY *private_key,
                        const unsigned char *ciphertext,
                        size_t ciphertext_len,
                        unsigned char **plaintext,
                        size_t *plaintext_len);

int read_whole_file(const char *path, unsigned char **buffer, size_t *len);
int write_whole_file(const char *path, const unsigned char *data, size_t len);

int aes256_cbc_encrypt(const unsigned char *plaintext, int plaintext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char **ciphertext, int *ciphertext_len);

int aes256_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char **plaintext, int *plaintext_len);

int compute_hmac_sha256(const unsigned char *key, size_t key_len,
                        const unsigned char *data, size_t data_len,
                        unsigned char **mac, unsigned int *mac_len);

void handle_openssl_error(const char *msg);

#endif

