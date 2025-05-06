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

/* Define constants for decryption */
#define IV_LENGTH 16
#define BYTE_ROTATION_OFFSET 7

typedef struct _zypher_file_metadata
{
    int format_version;           /* Format version of the encoded file */
    int format_type;              /* Type of encoded content (source or opcode) */
    uint32_t timestamp;           /* Timestamp when file was encoded */
    unsigned char content_iv[16]; /* IV for content encryption */
    unsigned char key_iv[16];     /* IV for key encryption */
    char *file_key;               /* Decrypted file encryption key */
    char *orig_filename;          /* Original filename used for key derivation */
    char checksum[33];            /* MD5 checksum for integrity checking */
} zypher_file_metadata;

/* Read and decrypt file content */
char *decrypt_file_content(const char *encoded_content, size_t encoded_length,
                           const char *master_key, const char *filename,
                           size_t *out_length, zypher_file_metadata *metadata);

/* Utility function to read file contents */
char *read_file_contents(const char *filename, size_t *size);

/* Verify integrity of decrypted content */
int verify_content_integrity(const char *content, size_t content_len, const char *checksum);

/* Process and load opcodes from serialized data */
zend_op_array *process_opcodes(char *opcode_data, size_t data_len, zend_string *filename);

/* Get metadata from encoded content */
int extract_file_metadata(const char *encoded_content, size_t encoded_length,
                          zypher_file_metadata *metadata);

#endif /* ZYPHER_DECRYPT_H */