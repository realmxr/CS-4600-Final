#ifndef TRANSMISSION_H
#define TRANSMISSION_H

#include <stddef.h>

typedef struct {
    unsigned char *encrypted_key;
    size_t encrypted_key_len;
    unsigned char *iv;
    size_t iv_len;
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *mac;
    size_t mac_len;
} TransmissionPackage;

int write_transmission_package(const char *path, const TransmissionPackage *pkg);
int read_transmission_package(const char *path, TransmissionPackage *pkg);
void free_transmission_package(TransmissionPackage *pkg);

#endif

