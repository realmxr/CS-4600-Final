#include "transmission.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRANSMISSION_MAGIC "TRNS"
#define TRANSMISSION_VERSION 1

static int write_u32_be(FILE *fp, uint32_t value) {
    unsigned char buffer[4];
    buffer[0] = (unsigned char)((value >> 24) & 0xFF);
    buffer[1] = (unsigned char)((value >> 16) & 0xFF);
    buffer[2] = (unsigned char)((value >> 8) & 0xFF);
    buffer[3] = (unsigned char)(value & 0xFF);
    return fwrite(buffer, 1, sizeof(buffer), fp) == sizeof(buffer);
}

static int read_u32_be(FILE *fp, uint32_t *value) {
    unsigned char buffer[4];
    if (fread(buffer, 1, sizeof(buffer), fp) != sizeof(buffer)) {
        return 0;
    }

    *value = ((uint32_t)buffer[0] << 24) |
             ((uint32_t)buffer[1] << 16) |
             ((uint32_t)buffer[2] << 8) |
             (uint32_t)buffer[3];
    return 1;
}

static int write_block(FILE *fp, const unsigned char *data, size_t len) {
    if (!write_u32_be(fp, (uint32_t)len)) {
        return 0;
    }
    if (fwrite(data, 1, len, fp) != len) {
        return 0;
    }
    return 1;
}

static unsigned char *read_block(FILE *fp, size_t *len) {
    uint32_t size = 0;
    if (!read_u32_be(fp, &size)) {
        return NULL;
    }
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (!buffer) {
        perror("Failed to allocate buffer");
        return NULL;
    }
    if (fread(buffer, 1, size, fp) != size) {
        perror("Failed to read block");
        free(buffer);
        return NULL;
    }
    *len = size;
    return buffer;
}

int write_transmission_package(const char *path, const TransmissionPackage *pkg) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("Unable to open transmission file for writing");
        return 0;
    }

    int success = 0;
    if (fwrite(TRANSMISSION_MAGIC, 1, 4, fp) != 4) {
        perror("Failed to write magic");
        goto cleanup;
    }

    unsigned char version = TRANSMISSION_VERSION;
    if (fwrite(&version, 1, 1, fp) != 1) {
        perror("Failed to write version");
        goto cleanup;
    }

    if (!write_block(fp, pkg->encrypted_key, pkg->encrypted_key_len) ||
        !write_block(fp, pkg->iv, pkg->iv_len) ||
        !write_block(fp, pkg->ciphertext, pkg->ciphertext_len) ||
        !write_block(fp, pkg->mac, pkg->mac_len)) {
        perror("Failed to write transmission package");
        goto cleanup;
    }

    success = 1;

cleanup:
    fclose(fp);
    return success;
}

int read_transmission_package(const char *path, TransmissionPackage *pkg) {
    memset(pkg, 0, sizeof(*pkg));

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("Unable to open transmission file");
        return 0;
    }

    unsigned char magic[4];
    if (fread(magic, 1, sizeof(magic), fp) != sizeof(magic) ||
        memcmp(magic, TRANSMISSION_MAGIC, sizeof(magic)) != 0) {
        fprintf(stderr, "Invalid transmission file magic value\n");
        fclose(fp);
        return 0;
    }

    unsigned char version = 0;
    if (fread(&version, 1, 1, fp) != 1) {
        fprintf(stderr, "Failed to read transmission version\n");
        fclose(fp);
        return 0;
    }

    if (version != TRANSMISSION_VERSION) {
        fprintf(stderr, "Unsupported transmission file version: %u\n", version);
        fclose(fp);
        return 0;
    }

    pkg->encrypted_key = read_block(fp, &pkg->encrypted_key_len);
    pkg->iv = read_block(fp, &pkg->iv_len);
    pkg->ciphertext = read_block(fp, &pkg->ciphertext_len);
    pkg->mac = read_block(fp, &pkg->mac_len);

    fclose(fp);

    if (!pkg->encrypted_key || !pkg->iv || !pkg->ciphertext || !pkg->mac) {
        free_transmission_package(pkg);
        return 0;
    }

    return 1;
}

void free_transmission_package(TransmissionPackage *pkg) {
    if (!pkg) {
        return;
    }
    free(pkg->encrypted_key);
    free(pkg->iv);
    free(pkg->ciphertext);
    free(pkg->mac);
    memset(pkg, 0, sizeof(*pkg));
}

