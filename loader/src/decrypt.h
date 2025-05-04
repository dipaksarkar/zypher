/**
 * Decryption functions for Zypher PHP Extension
 */
#ifndef ZYPHER_DECRYPT_H
#define ZYPHER_DECRYPT_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "php.h"
#include "src/php_loader.h"

/* Read and decrypt file content */
char *decrypt_file_content(const char *encoded_content, size_t encoded_length,
                           const char *master_key, const char *filename, size_t *out_length);

/* Utility function to read file contents */
char *read_file_contents(const char *filename, size_t *size);

/* Verify integrity of decrypted content */
int verify_content_integrity(const char *content, size_t content_len, const char *checksum);

#endif /* ZYPHER_DECRYPT_H */