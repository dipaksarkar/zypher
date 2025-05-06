/**
 * Utility functions for Zypher PHP Extension
 */
#ifndef ZYPHER_UTILS_H
#define ZYPHER_UTILS_H

#include "php.h"
#include "../../include/zypher_loader.h"

/* Memory allocation with error checking */
void *zypher_malloc(size_t size);
void *zypher_calloc(size_t nmemb, size_t size);
void *zypher_realloc(void *ptr, size_t size);
void zypher_free(void *ptr);

/* String functions */
char *zypher_strdup(const char *str);
char *zypher_strndup(const char *str, size_t n);

/* Base64 functions */
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);

/* Debug and logging functions */
void zypher_log_message(const char *format, ...);
void zypher_hex_dump(const unsigned char *data, size_t len);

/* PHP exported function */
PHP_FUNCTION(zypher_decode_string);

/* File and path utilities */
char *get_file_extension(const char *filename);
char *get_file_contents(const char *filename, size_t *length);

/* Hex string utilities */
char *bytes_to_hex(const unsigned char *data, size_t len);
unsigned char *hex_to_bytes(const char *hex, size_t *len);

#endif /* ZYPHER_UTILS_H */