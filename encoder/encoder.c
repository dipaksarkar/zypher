/*
  +----------------------------------------------------------------------+
  | Zypher PHP Encoder                                                    |
  +----------------------------------------------------------------------+
  | Copyright (c) 2023-2025 Zypher Team                                  |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Zypher Team <info@zypher.com>                                |
  +----------------------------------------------------------------------+
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <libgen.h>

/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* Common headers */
#include "../include/zypher_encoder.h"
#include "../include/zypher_common.h"
#include "../build/zypher_master_key.h"

/* Forward declarations */
extern void print_debug(const char *format, ...);
extern void print_error(const char *format, ...);
extern int compile_php_to_opcodes(const char *source_code, const char *filename, char **output, size_t *output_len);
extern char *clean_php_source(const char *source_code);
extern char *php_serialize_data(const char *contents, const char *filename);
extern char *derive_encryption_key(const char *master_key, const char *filename, int iterations);
extern char *encrypt_content(const char *content, size_t content_len, const char *key, unsigned char *iv, size_t *out_len);
extern char *read_file_contents(const char *filename, size_t *size);
extern void byte_rotate(unsigned char *data, size_t len, int offset);
extern char *base64_encode(const unsigned char *input, size_t length);
extern void calculate_content_checksum(const char *content, size_t length, char *output);
extern int create_stub_file(const char *filename, const char *encoded_content, size_t content_len, const zypher_encoder_options *options);

/* PHP embedding variables */
#ifdef HAVE_EMBED
#include <sapi/embed/php_embed.h>
#endif

/* Initialize encoder and required libraries */
int zypher_encoder_init()
{
    print_debug("Initializing encoder");

    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Seed the random number generator */
    if (!RAND_poll())
    {
        print_error("Failed to seed OpenSSL PRNG");
        return ZYPHER_FAILURE;
    }

#ifdef HAVE_EMBED
    /* Initialize PHP embedding if available */
    php_embed_init(0, NULL);
    print_debug("PHP embedding initialized");
#endif

    print_debug("Encoder initialized successfully");
    return ZYPHER_SUCCESS;
}

/* Shutdown encoder and free resources */
void zypher_encoder_shutdown()
{
    print_debug("Shutting down encoder");

    /* Clean up OpenSSL */
    EVP_cleanup();
    ERR_free_strings();

#ifdef HAVE_EMBED
    /* Shutdown PHP embedding if available */
    php_embed_shutdown();
    print_debug("PHP embedding shutdown");
#endif
}

/* Main encoding function */
int encode_php_file(const zypher_encoder_options *options)
{
    char *source_code = NULL;
    char *cleaned_source = NULL;
    char *opcodes = NULL;
    char *serialized = NULL;
    char *encryption_key = NULL;
    char *encrypted = NULL;
    char *encoded_content = NULL;
    unsigned char iv[IV_LENGTH] = {0};
    size_t source_len = 0;
    size_t opcodes_len = 0;
    size_t encrypted_len = 0;
    int result = ZYPHER_FAILURE;
    char checksum[33] = {0}; /* MD5 hex digest (32 chars + null) */
    char *input_copy = NULL;
    char *filename_only = NULL;
    char debug_filename[4096] = {0};

    /* Base path for debug files */
    char debug_base[4096] = {0};

    if (!options || !options->input_file || !options->output_file)
    {
        print_error("Invalid options passed to encoder");
        return ZYPHER_FAILURE;
    }

    /* Generate base filename for debug outputs */
    if (options->debug)
    {
        strncpy(debug_base, options->input_file, sizeof(debug_base) - 1);
        debug_base[sizeof(debug_base) - 1] = '\0'; /* Ensure null-termination */
    }

    /* Extract just the filename portion for key derivation */
    input_copy = strdup(options->input_file);
    if (!input_copy)
    {
        print_error("Failed to allocate memory for filename");
        return ZYPHER_FAILURE;
    }
    filename_only = basename(input_copy);
    print_debug("Using base filename '%s' for key derivation", filename_only);

    /* Read source code from file */
    source_code = read_file_contents(options->input_file, &source_len);
    if (!source_code)
    {
        print_error("Failed to read source code from %s", options->input_file);
        free(input_copy); /* Free the copy, not the basename result */
        return ZYPHER_FAILURE;
    }

    print_debug("Read %zu bytes from %s", source_len, options->input_file);

    /* Clean source code (remove comments and whitespace) */
    cleaned_source = clean_php_source(source_code);
    if (!cleaned_source)
    {
        print_error("Failed to clean source code");
        free(source_code);
        free(input_copy);
        return ZYPHER_FAILURE;
    }

    print_debug("Source code cleaned");

    /* Save cleaned source in debug mode */
    if (options->debug)
    {
        snprintf(debug_filename, sizeof(debug_filename), "%s.cleaned", debug_base);
        FILE *debug_file = fopen(debug_filename, "wb");
        if (debug_file)
        {
            if (fwrite(cleaned_source, 1, strlen(cleaned_source), debug_file) == strlen(cleaned_source))
            {
                print_debug("Cleaned source saved to %s", debug_filename);
            }
            fclose(debug_file);
        }
    }

    /* Step 1: Compile PHP into opcodes */
    if (compile_php_to_opcodes(cleaned_source, options->input_file, &opcodes, &opcodes_len) != ZYPHER_SUCCESS)
    {
        print_error("Failed to compile PHP to opcodes");
        free(source_code);
        free(cleaned_source);
        free(input_copy);
        return ZYPHER_FAILURE;
    }

    print_debug("Source code compiled to opcodes");

    /* Save raw opcodes in debug mode */
    if (options->debug)
    {
        snprintf(debug_filename, sizeof(debug_filename), "%s.opcodes", debug_base);
        FILE *debug_file = fopen(debug_filename, "wb");
        if (debug_file)
        {
            if (fwrite(opcodes, 1, opcodes_len, debug_file) == opcodes_len)
            {
                print_debug("Raw opcodes saved to %s (%zu bytes)", debug_filename, opcodes_len);
            }
            fclose(debug_file);
        }
    }

    /* Step 2: Serialize PHP opcodes with metadata */
    serialized = php_serialize_data(opcodes, options->input_file);
    if (!serialized)
    {
        print_error("Failed to serialize opcodes");
        free(source_code);
        free(cleaned_source);
        free(opcodes);
        free(input_copy);
        return ZYPHER_FAILURE;
    }

    print_debug("Opcodes serialized successfully");

    /* Save serialized opcodes in debug mode */
    if (options->debug)
    {
        snprintf(debug_filename, sizeof(debug_filename), "%s.serialized", debug_base);
        FILE *debug_file = fopen(debug_filename, "wb");
        if (debug_file)
        {
            if (fwrite(serialized, 1, strlen(serialized), debug_file) == strlen(serialized))
            {
                print_debug("Serialized opcodes saved to %s (%zu bytes)", debug_filename, strlen(serialized));
            }
            fclose(debug_file);
        }
    }

    /* Step 3: Calculate MD5 checksum of the serialized data */
    calculate_content_checksum(serialized, strlen(serialized), checksum);
    print_debug("Content checksum: %s", checksum);

    /* Step 4: Generate IV for encryption */
    if (RAND_bytes(iv, IV_LENGTH) != 1)
    {
        print_error("Failed to generate random IV");
        free(source_code);
        free(cleaned_source);
        free(opcodes);
        free(serialized);
        free(input_copy);
        return ZYPHER_FAILURE;
    }

    /* Step 5: Derive encryption key from master key and filename */
    encryption_key = derive_encryption_key(ZYPHER_MASTER_KEY, filename_only, options->iteration_count);
    if (!encryption_key)
    {
        print_error("Failed to derive encryption key");
        free(source_code);
        free(cleaned_source);
        free(opcodes);
        free(serialized);
        free(input_copy);
        return ZYPHER_FAILURE;
    }

    print_debug("Encryption key derived successfully");

    /* Log encryption info in debug mode instead of saving to file */
    if (options->debug)
    {
        char iv_hex[IV_LENGTH * 2 + 1] = {0};
        char key_preview[17] = {0}; /* 8 bytes = 16 hex chars + null */

        /* Format IV as hex string */
        for (int i = 0; i < IV_LENGTH; i++)
        {
            sprintf(&iv_hex[i * 2], "%02x", iv[i]);
        }

        /* Format first 8 bytes of the key as hex string */
        for (int i = 0; i < 8 && i < KEY_LENGTH; i++)
        {
            sprintf(&key_preview[i * 2], "%02x", (unsigned char)encryption_key[i]);
        }

        print_debug("Encryption Info:");
        print_debug("  IV: %s", iv_hex);
        print_debug("  Key-Derivation: PBKDF2-HMAC-SHA256");
        print_debug("  Iterations: %d", options->iteration_count);
        print_debug("  Salt: %s", filename_only);
        print_debug("  Derived Key (first 8 bytes): %s... (remaining bytes omitted for security)", key_preview);
    }

    /* Step 6: Encrypt the serialized data */
    encrypted = encrypt_content(serialized, strlen(serialized), encryption_key, iv, &encrypted_len);
    if (!encrypted)
    {
        print_error("Failed to encrypt content");
        free(source_code);
        free(cleaned_source);
        free(opcodes);
        free(serialized);
        free(encryption_key);
        free(input_copy);
        return ZYPHER_FAILURE;
    }

    print_debug("Content encrypted successfully (%zu bytes)", encrypted_len);

    /* Step 7: If obfuscation is enabled, rotate bytes */
    if (options->obfuscate)
    {
        print_debug("Applying byte rotation obfuscation");
        byte_rotate((unsigned char *)encrypted, encrypted_len, BYTE_ROTATION_OFFSET);

        /* Save obfuscated data in debug mode */
        if (options->debug)
        {
            snprintf(debug_filename, sizeof(debug_filename), "%s.obfuscated", debug_base);
            FILE *debug_file = fopen(debug_filename, "wb");
            if (debug_file)
            {
                if (fwrite(encrypted, 1, encrypted_len, debug_file) == encrypted_len)
                {
                    print_debug("Obfuscated data saved to %s", debug_filename);
                }
                fclose(debug_file);
            }
        }
    }

    /* Step 8: Base64 encode the encrypted content */
    encoded_content = base64_encode((unsigned char *)encrypted, encrypted_len);
    if (!encoded_content)
    {
        print_error("Failed to base64 encode encrypted content");
        free(source_code);
        free(cleaned_source);
        free(opcodes);
        free(serialized);
        free(encryption_key);
        free(encrypted);
        free(input_copy);
        return ZYPHER_FAILURE;
    }

    print_debug("Content encoded with base64");

    /* Save base64 encoded data in debug mode */
    if (options->debug)
    {
        snprintf(debug_filename, sizeof(debug_filename), "%s.base64", debug_base);
        FILE *debug_file = fopen(debug_filename, "wb");
        if (debug_file)
        {
            if (fwrite(encoded_content, 1, strlen(encoded_content), debug_file) == strlen(encoded_content))
            {
                print_debug("Base64 encoded data saved to %s", debug_filename);
            }
            fclose(debug_file);
        }
    }

    /* Step 9: Create output file with proper stub */
    result = create_stub_file(options->output_file, encoded_content, strlen(encoded_content), options);

    /* Log final structure information in debug mode instead of saving to file */
    if (options->debug && result == ZYPHER_SUCCESS)
    {
        print_debug("Final structure breakdown:");
        print_debug("  1. PHP Stub + ?> closing tag");
        print_debug("  2. Signature: %s", ZYPHER_SIGNATURE);
        print_debug("  3. Encoded payload: [BASE64 DATA LENGTH: %zu bytes]", strlen(encoded_content));
        print_debug("");
        print_debug("Total file size: ~%zu bytes",
                    strlen("<?php ... ?>\n") + SIGNATURE_LENGTH + strlen(encoded_content));
    }

    /* Clean up */
    free(source_code);
    free(cleaned_source);
    free(opcodes);
    free(serialized);
    free(encryption_key);
    free(encrypted);
    free(encoded_content);
    free(input_copy); /* Free the copy, not the basename result */

    return result;
}