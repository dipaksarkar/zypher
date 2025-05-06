/**
 * Zypher PHP Encoder - Core encoding functionality
 * Main coordinator for the encoding process
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

/* OpenSSL includes */
#include <openssl/rand.h>

/* Common headers */
#include "../include/zypher_encoder.h"
#include "../include/zypher_common.h"
#include "../build/zypher_master_key.h"

/* External debug function */
extern void print_debug(const char *format, ...);
extern void print_error(const char *format, ...);

/* Function prototypes from other modules */
extern char *read_file_contents(const char *filename, size_t *size);
extern char *run_command(const char *command, size_t *output_size);
extern char *base64_encode(const unsigned char *input, size_t length);
extern int create_stub_file(const char *filename, const char *encoded_content, size_t content_len,
                            const zypher_encoder_options *options);
extern int compile_php_to_opcodes(const char *source_code, const char *filename, char **output, size_t *output_len);
extern void calculate_content_checksum(const char *content, size_t length, char *output);
extern char *encrypt_content(const char *content, size_t content_len, const char *key,
                             unsigned char *iv, size_t *out_len);
extern char *derive_encryption_key(const char *master_key, const char *filename, int iterations);

/* Global encoder context */
typedef struct _zypher_encoder_ctx
{
    char master_key[65]; /* Hex string of the master key */
    int initialized;
} zypher_encoder_ctx;

/* Encoder context */
static zypher_encoder_ctx g_ctx;

/* Initialize the encoder */
int zypher_encoder_init()
{
    /* Convert master key to hex string */
    memset(&g_ctx, 0, sizeof(g_ctx));

    /* Check if master key is available */
#ifndef ZYPHER_MASTER_KEY
    print_error("Master key not defined. Please run make first to generate it.");
    return 0;
#endif

    /* Copy hex string master key */
    strncpy(g_ctx.master_key, ZYPHER_MASTER_KEY, sizeof(g_ctx.master_key) - 1);
    g_ctx.initialized = 1;

    /* Check if PHP is available */
    char *php_version = run_command("php -v | head -n1", NULL);
    if (!php_version)
    {
        print_error("PHP not found or not executable");
        return 0;
    }

    print_debug("Using %s", php_version);
    free(php_version);

    return 1;
}

/* Shutdown the encoder */
void zypher_encoder_shutdown()
{
    /* Nothing special to clean up at this point */
}

/* Main encoding function */
int encode_php_file(const zypher_encoder_options *options)
{
    int success = 0;
    char *file_content = NULL;
    size_t file_size;

    /* Stage 1: Read the PHP file */
    printf("Reading PHP file: %s\n", options->input_file);
    file_content = read_file_contents(options->input_file, &file_size);
    if (!file_content)
    {
        return 0;
    }

    /* Stage 2: Compile the PHP code to opcodes using PHP CLI */
    printf("Compiling PHP code to opcodes...\n");
    size_t serialized_len;
    char *serialized = NULL;
    if (compile_php_to_opcodes(file_content, options->input_file, &serialized, &serialized_len) != ZYPHER_SUCCESS)
    {
        print_error("Failed to compile PHP code");
        free(file_content);
        return 0;
    }
    free(file_content); /* No longer needed */

    /* First 32 bytes should be the MD5 checksum, rest is serialized opcodes */
    char checksum[33];
    memcpy(checksum, serialized, 32);
    checksum[32] = '\0';

    if (options->debug)
    {
        print_debug("Checksum: %s", checksum);
    }

    /* Stage 4: Derive encryption key for this file */
    printf("Generating file-specific encryption key...\n");
    char *encryption_key = derive_encryption_key(g_ctx.master_key, options->input_file,
                                                 options->iteration_count);
    if (!encryption_key)
    {
        print_error("Failed to derive encryption key");
        free(serialized);
        return 0;
    }

    /* Generate random IV */
    unsigned char content_iv[16];
    unsigned char key_iv[16];
    if (!RAND_bytes(content_iv, sizeof(content_iv)) || !RAND_bytes(key_iv, sizeof(key_iv)))
    {
        print_error("Failed to generate random IV");
        free(encryption_key);
        free(serialized);
        return 0;
    }

    /* Encrypt the serialized opcodes */
    printf("Encrypting opcodes with AES-256-CBC...\n");
    size_t encrypted_len = 0;
    char *encrypted_data = encrypt_content(serialized, serialized_len,
                                           encryption_key, content_iv, &encrypted_len);
    if (!encrypted_data)
    {
        print_error("Failed to encrypt opcodes");
        free(encryption_key);
        free(serialized);
        return 0;
    }

    /* We no longer need the serialized data */
    free(serialized);

    /* Build metadata packet:
     * - Format version (1 byte)
     * - Format type (1 byte) - opcode format
     * - Timestamp (4 bytes)
     * - Content IV (16 bytes)
     * - Key IV (16 bytes)
     * - File key (encrypted) - length + data
     * - Original filename - length + data
     */
    unsigned char *metadata = malloc(1024); /* Start with a reasonable buffer */
    size_t metadata_len = 0;

    /* Add format version and type */
    metadata[metadata_len++] = ZYPHER_FORMAT_VERSION;
    metadata[metadata_len++] = ZYPHER_FORMAT_OPCODE;

    /* Add timestamp (big endian) */
    uint32_t timestamp = time(NULL);
    metadata[metadata_len++] = (timestamp >> 24) & 0xFF;
    metadata[metadata_len++] = (timestamp >> 16) & 0xFF;
    metadata[metadata_len++] = (timestamp >> 8) & 0xFF;
    metadata[metadata_len++] = timestamp & 0xFF;

    /* Add content IV */
    memcpy(metadata + metadata_len, content_iv, 16);
    metadata_len += 16;

    /* Add key IV */
    memcpy(metadata + metadata_len, key_iv, 16);
    metadata_len += 16;

    /* Encrypt the file key with the master key */
    unsigned char *encrypted_key = malloc(100); /* More than enough for the key */
    size_t encrypted_key_len = 0;
    char *encrypted_file_key = encrypt_content(encryption_key, strlen(encryption_key),
                                               g_ctx.master_key, key_iv, &encrypted_key_len);
    if (!encrypted_file_key)
    {
        print_error("Failed to encrypt file key");
        free(encrypted_key);
        free(metadata);
        free(encryption_key);
        free(encrypted_data);
        return 0;
    }

    /* Add encrypted key length and data */
    metadata[metadata_len++] = (encrypted_key_len >> 24) & 0xFF;
    metadata[metadata_len++] = (encrypted_key_len >> 16) & 0xFF;
    metadata[metadata_len++] = (encrypted_key_len >> 8) & 0xFF;
    metadata[metadata_len++] = encrypted_key_len & 0xFF;
    memcpy(metadata + metadata_len, encrypted_file_key, encrypted_key_len);
    metadata_len += encrypted_key_len;

    /* Add original filename length and data */
    const char *filename = options->input_file;
    size_t filename_len = strlen(filename);
    if (filename_len > 255)
    {
        filename_len = 255; /* Truncate if too long */
    }
    metadata[metadata_len++] = filename_len;
    memcpy(metadata + metadata_len, filename, filename_len);
    metadata_len += filename_len;

    /* Add license information if provided */
    if (options->domain_lock)
    {
        size_t domain_len = strlen(options->domain_lock);
        if (domain_len > 255)
        {
            domain_len = 255;
        }
        metadata[metadata_len++] = domain_len;
        memcpy(metadata + metadata_len, options->domain_lock, domain_len);
        metadata_len += domain_len;
    }
    else
    {
        metadata[metadata_len++] = 0; /* No domain */
    }

    /* Add expiry timestamp if provided */
    metadata[metadata_len++] = (options->expire_timestamp >> 24) & 0xFF;
    metadata[metadata_len++] = (options->expire_timestamp >> 16) & 0xFF;
    metadata[metadata_len++] = (options->expire_timestamp >> 8) & 0xFF;
    metadata[metadata_len++] = options->expire_timestamp & 0xFF;

    /* Now combine metadata and encrypted data */
    size_t total_size = metadata_len + encrypted_len;
    unsigned char *combined = malloc(total_size);
    memcpy(combined, metadata, metadata_len);
    memcpy(combined + metadata_len, encrypted_data, encrypted_len);
    free(encrypted_data);
    free(metadata);

    /* Apply byte rotation obfuscation if enabled */
    if (options->obfuscate)
    {
        printf("Applying byte rotation obfuscation...\n");
        for (size_t i = 0; i < total_size; i++)
        {
            combined[i] = (combined[i] + BYTE_ROTATION_OFFSET) & 0xFF;
        }
    }

    /* Base64 encode the final result */
    printf("Base64 encoding final output...\n");
    char *b64_result = base64_encode(combined, total_size);
    if (!b64_result)
    {
        print_error("Failed to base64 encode output");
        free(combined);
        free(encrypted_file_key);
        free(encryption_key);
        return 0;
    }

    /* Create the stub PHP file with the encoded data */
    printf("Creating encoded PHP file: %s\n", options->output_file);
    success = create_stub_file(options->output_file, b64_result, strlen(b64_result), options);

    /* Cleanup */
    free(b64_result);
    free(combined);
    free(encrypted_file_key);
    free(encryption_key);

    return success;
}