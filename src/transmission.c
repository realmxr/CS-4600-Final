/*
 * transmission.c
 * Binary serialization helpers for packaging encrypted payload data.
 */

#include "transmission.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Emit a big-endian uint32 into the file.
static int write_u32_be(FILE *fp, uint32_t value) {
    unsigned char buffer[4];
    buffer[0] = (unsigned char)((value >> 24) & 0xFF);
    buffer[1] = (unsigned char)((value >> 16) & 0xFF);
    buffer[2] = (unsigned char)((value >> 8) & 0xFF);
    buffer[3] = (unsigned char)(value & 0xFF);
    return fwrite(buffer, 1, sizeof(buffer), fp) == sizeof(buffer);
}

// Read a big-endian uint32 from the file.
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

// Write a length-prefixed binary blob (len || data).
static int write_block(FILE *fp, const unsigned char *data, size_t len) {
    if (!write_u32_be(fp, (uint32_t)len)) {
        return 0;
    }
    if (fwrite(data, 1, len, fp) != len) {
        return 0;
    }
    return 1;
}

// Read a length-prefixed blob into a freshly malloc'd buffer.
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

// Serialize a package to disk with simple TLV framing.
int write_transmission_package(const char *path, const TransmissionPackage *pkg) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        perror("Unable to open transmission file for writing");
        return 0;
    }

    int success = 0;

    if (!write_block(fp, pkg->encrypted_key, pkg->encrypted_key_len) ||
        !write_block(fp, pkg->iv, pkg->iv_len) ||
        !write_block(fp, pkg->ciphertext, pkg->ciphertext_len) ||
        !write_block(fp, pkg->mac, pkg->mac_len) ||
        !write_block(fp, pkg->signature, pkg->signature_len)) {
        perror("Failed to write transmission package");
        goto cleanup;
    }

    success = 1;

cleanup:
    fclose(fp);
    return success;
}

// Ingest a serialized package from disk, allocating buffers per field.
int read_transmission_package(const char *path, TransmissionPackage *pkg) {
    memset(pkg, 0, sizeof(*pkg));

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("Unable to open transmission file");
        return 0;
    }

    pkg->encrypted_key = read_block(fp, &pkg->encrypted_key_len);
    pkg->iv = read_block(fp, &pkg->iv_len);
    pkg->ciphertext = read_block(fp, &pkg->ciphertext_len);
    pkg->mac = read_block(fp, &pkg->mac_len);
    pkg->signature = read_block(fp, &pkg->signature_len);

    fclose(fp);

    if (!pkg->encrypted_key || !pkg->iv || !pkg->ciphertext || !pkg->mac || !pkg->signature) {
        free_transmission_package(pkg);
        return 0;
    }

    return 1;
}

// Release heap buffers referenced in the package struct.
void free_transmission_package(TransmissionPackage *pkg) {
    if (!pkg) {
        return;
    }
    free(pkg->encrypted_key);
    free(pkg->iv);
    free(pkg->ciphertext);
    free(pkg->mac);
    free(pkg->signature);
    memset(pkg, 0, sizeof(*pkg));
}

