/**
 * Zypher Encoder Header
 * Definitions for the PHP Source Code Encoder
 */
#ifndef ZYPHER_ENCODER_H
#define ZYPHER_ENCODER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h> /* For basename() function */

/* Include PHP necessary headers */
#include "php.h"
#include "php_ini.h"
#include "ext/standard/base64.h"
#include "ext/standard/md5.h"
#include "ext/standard/php_var.h"
#include "Zend/zend_compile.h"
#include "Zend/zend_execute.h"
#include "Zend/zend_vm.h"
#include "Zend/zend_operators.h"

/* Include OpenSSL for encryption */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

/* Include common definitions */
#include "zypher_common.h"

/* If the master key header exists, include it */
#ifdef HAVE_ZYPHER_MASTER_KEY_H
#include "../build/zypher_master_key.h"
#endif

/* Encoder specific definitions */
#define ZYPHER_ENCODER_VERSION ZYPHER_VERSION
#define ZYPHER_BANNER "Zypher PHP Encoder " ZYPHER_VERSION " (C) Zypher Team"

/* Encoder options */
typedef struct _zypher_encoder_options
{
    char *input_file;     /* Input PHP file to encode */
    char *output_file;    /* Output file for encoded result */
    int obfuscate;        /* Enable additional obfuscation */
    int expire_timestamp; /* Expiration timestamp (0=none) */
    char *domain_lock;    /* Domain to lock to (NULL=none) */
    int debug;            /* Enable debug output */
    int iteration_count;  /* Key derivation iteration count */
    int allow_debugging;  /* Allow debugging of encoded files */
} zypher_encoder_options;

/* Structure to hold encoding context */
typedef struct _zypher_encoding_context
{
    const char *master_key;       /* Master encryption key */
    unsigned char content_iv[16]; /* IV for content encryption */
    unsigned char key_iv[16];     /* IV for key encryption */
    char *file_key;               /* File-specific key */
    char checksum[33];            /* Content checksum */
    uint32_t flags;               /* Encoding flags */
    uint32_t timestamp;           /* Encoding timestamp */
} zypher_encoding_context;

/* Function prototypes */

/* Initialize encoder and libraries */
int zypher_encoder_init(void);

/* Cleanup encoder resources */
void zypher_encoder_shutdown(void);

/* Parse command-line options */
int parse_options(int argc, char **argv, zypher_encoder_options *options);

/* Show command-line help */
void show_help(void);

/* Read file contents */
char *read_file(const char *filename, size_t *size);

/* Write data to file */
int write_file(const char *filename, const char *data, size_t size);

/* Encode PHP file */
int encode_php_file(zypher_encoder_options *options);

/* Compile PHP source to opcodes */
zval *compile_php_to_opcodes(const char *source, size_t source_len, const char *filename);

/* Serialize opcodes to binary format */
char *serialize_opcodes(zval *opcodes, size_t *serialized_len);

/* Encrypt serialized opcodes */
char *encrypt_opcodes(char *serialized, size_t serialized_len,
                      zypher_encoding_context *ctx, const char *filename,
                      size_t *encrypted_len);

/* Generate file-specific encryption key */
char *generate_file_key(const char *master_key, const char *filename, int iterations);

/* Calculate content checksum */
void calculate_checksum(const char *content, size_t length, char *output);

/* Prepare final encoded file with PHP stub */
char *prepare_encoded_file(const char *encrypted_data, size_t encrypted_len,
                           size_t *output_len);

/* Error handling utilities */
void print_error(const char *format, ...);
void print_debug(const char *format, ...);

#endif /* ZYPHER_ENCODER_H */