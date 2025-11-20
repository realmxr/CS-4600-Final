#include "crypto_utils.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_openssl_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
}

int generate_rsa_keypair(const char *priv_path, const char *pub_path, int bits) {
    int success = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *priv = NULL;
    FILE *pub = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        handle_openssl_error("Failed to create keygen context");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        handle_openssl_error("RSA key generation failed");
        goto cleanup;
    }

    priv = fopen(priv_path, "wb");
    if (!priv) {
        perror("Unable to open private key file for writing");
        goto cleanup;
    }

    if (PEM_write_PrivateKey(priv, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        handle_openssl_error("Failed to write private key");
        goto cleanup;
    }

    pub = fopen(pub_path, "wb");
    if (!pub) {
        perror("Unable to open public key file for writing");
        goto cleanup;
    }

    if (PEM_write_PUBKEY(pub, pkey) != 1) {
        handle_openssl_error("Failed to write public key");
        goto cleanup;
    }

    success = 1;

cleanup:
    if (priv) {
        fclose(priv);
    }
    if (pub) {
        fclose(pub);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    return success;
}

static EVP_PKEY *load_key(const char *path, int is_private) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("Unable to open key file");
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (is_private) {
        pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    }

    fclose(fp);

    if (!pkey) {
        handle_openssl_error("Failed to read key");
    }

    return pkey;
}

EVP_PKEY *load_public_key(const char *path) {
    return load_key(path, 0);
}

EVP_PKEY *load_private_key(const char *path) {
    return load_key(path, 1);
}

int read_whole_file(const char *path, unsigned char **buffer, size_t *len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("Unable to open file");
        return 0;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("Failed to seek file");
        fclose(fp);
        return 0;
    }

    long size = ftell(fp);
    if (size < 0) {
        perror("Failed to determine file size");
        fclose(fp);
        return 0;
    }
    rewind(fp);

    unsigned char *data = (unsigned char *)malloc((size_t)size);
    if (!data) {
        perror("Failed to allocate buffer");
        fclose(fp);
        return 0;
    }

    size_t read_len = fread(data, 1, (size_t)size, fp);
    fclose(fp);

    if (read_len != (size_t)size) {
        perror("Failed to read file");
        free(data);
        return 0;
    }

    *buffer = data;
    *len = (size_t)size;
    return 1;
}

int write_whole_file(const char *path, const unsigned char *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("Unable to open file for writing");
        return 0;
    }

    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);

    if (written != len) {
        perror("Failed to write file");
        return 0;
    }

    return 1;
}

int aes256_cbc_encrypt(const unsigned char *plaintext, int plaintext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char **ciphertext, int *ciphertext_len) {
    int success = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *out = NULL;
    int len = 0;
    int total_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_error("Failed to create cipher context");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_openssl_error("EncryptInit failed");
        goto cleanup;
    }

    out = (unsigned char *)malloc((size_t)plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (!out) {
        perror("Failed to allocate ciphertext buffer");
        goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, out, &len, plaintext, plaintext_len) != 1) {
        handle_openssl_error("EncryptUpdate failed");
        goto cleanup;
    }
    total_len = len;

    if (EVP_EncryptFinal_ex(ctx, out + total_len, &len) != 1) {
        handle_openssl_error("EncryptFinal failed");
        goto cleanup;
    }
    total_len += len;

    *ciphertext = out;
    *ciphertext_len = total_len;
    out = NULL;
    success = 1;

cleanup:
    if (!success && out) {
        OPENSSL_cleanse(out, (size_t)plaintext_len + EVP_MAX_BLOCK_LENGTH);
        free(out);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return success;
}

int aes256_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                       const unsigned char *key, const unsigned char *iv,
                       unsigned char **plaintext, int *plaintext_len) {
    int success = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *out = NULL;
    int len = 0;
    int total_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_error("Failed to create cipher context");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_openssl_error("DecryptInit failed");
        goto cleanup;
    }

    out = (unsigned char *)malloc(ciphertext_len);
    if (!out) {
        perror("Failed to allocate plaintext buffer");
        goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, out, &len, ciphertext, ciphertext_len) != 1) {
        handle_openssl_error("DecryptUpdate failed");
        goto cleanup;
    }
    total_len = len;

    if (EVP_DecryptFinal_ex(ctx, out + total_len, &len) != 1) {
        handle_openssl_error("DecryptFinal failed");
        goto cleanup;
    }
    total_len += len;

    *plaintext = out;
    *plaintext_len = total_len;
    out = NULL;
    success = 1;

cleanup:
    if (!success && out) {
        OPENSSL_cleanse(out, (size_t)ciphertext_len);
        free(out);
    }
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return success;
}

int compute_hmac_sha256(const unsigned char *key, size_t key_len,
                        const unsigned char *data, size_t data_len,
                        unsigned char **mac, unsigned int *mac_len) {
    unsigned char *buffer = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
    if (!buffer) {
        perror("Failed to allocate MAC buffer");
        return 0;
    }

    if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, buffer, mac_len)) {
        handle_openssl_error("Failed to compute HMAC");
        free(buffer);
        return 0;
    }

    *mac = buffer;
    return 1;
}

static int rsa_transform(EVP_PKEY *pkey,
                         const unsigned char *input,
                         size_t input_len,
                         unsigned char **output,
                         size_t *output_len,
                         int encrypt) {
    if (!pkey || !output || !output_len) {
        return 0;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        handle_openssl_error("Failed to create EVP_PKEY_CTX");
        return 0;
    }

    int ok = 0;
    if ((encrypt ? EVP_PKEY_encrypt_init(ctx) : EVP_PKEY_decrypt_init(ctx)) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handle_openssl_error("Failed to initialize RSA transform");
        goto cleanup;
    }

    size_t len = 0;
    if ((encrypt ? EVP_PKEY_encrypt(ctx, NULL, &len, input, input_len)
                 : EVP_PKEY_decrypt(ctx, NULL, &len, input, input_len)) <= 0) {
        handle_openssl_error("Failed to size RSA transform");
        goto cleanup;
    }

    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) {
        perror("Failed to allocate RSA buffer");
        goto cleanup;
    }

    if ((encrypt ? EVP_PKEY_encrypt(ctx, buf, &len, input, input_len)
                 : EVP_PKEY_decrypt(ctx, buf, &len, input, input_len)) <= 0) {
        handle_openssl_error("RSA transform failed");
        OPENSSL_cleanse(buf, len);
        free(buf);
        goto cleanup;
    }

    *output = buf;
    *output_len = len;
    ok = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

int rsa_public_encrypt(EVP_PKEY *public_key,
                       const unsigned char *plaintext,
                       size_t plaintext_len,
                       unsigned char **ciphertext,
                       size_t *ciphertext_len) {
    return rsa_transform(public_key, plaintext, plaintext_len, ciphertext, ciphertext_len, 1);
}

int rsa_private_decrypt(EVP_PKEY *private_key,
                        const unsigned char *ciphertext,
                        size_t ciphertext_len,
                        unsigned char **plaintext,
                        size_t *plaintext_len) {
    return rsa_transform(private_key, ciphertext, ciphertext_len, plaintext, plaintext_len, 0);
}

