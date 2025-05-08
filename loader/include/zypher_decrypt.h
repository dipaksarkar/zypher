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
#include "../../include/zypher_loader.h"

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

/* Deobfuscate opcode data using namespace hint */
int deobfuscate_opcode_data(char *data, size_t data_len, const char *namespace_hint);

#endif /* ZYPHER_DECRYPT_H */