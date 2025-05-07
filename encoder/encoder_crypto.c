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
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>

/* Common headers */
#include "../include/zypher_encoder.h"
#include "../include/zypher_common.h"
#include "../build/zypher_master_key.h"

/* Forward declarations */
extern void print_debug(const char *format, ...);
extern void print_error(const char *format, ...);

/* Calculate MD5 checksum of content */
void calculate_content_checksum(const char *content, size_t length, char *output)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    /* Use EVP interface instead of deprecated direct MD5 functions */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        print_error("Failed to create MD5 context");
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, content, length) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1)
    {

        print_error("MD5 calculation failed");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    /* Convert to hex string */
    for (unsigned int i = 0; i < digest_len; i++)
    {
        sprintf(&output[i * 2], "%02x", digest[i]);
    }
    output[digest_len * 2] = '\0';

    /* Clean up */
    EVP_MD_CTX_free(mdctx);
}

/* Derive encryption key from master key and file-specific data */
char *derive_encryption_key(const char *master_key, const char *filename, int iterations)
{
    if (!master_key || !filename || iterations < 1000)
    {
        print_error("Invalid parameters for key derivation");
        return NULL;
    }

    unsigned char *key = (unsigned char *)malloc(KEY_LENGTH + 1);
    if (!key)
    {
        print_error("Failed to allocate memory for encryption key");
        return NULL;
    }

    /* Use PBKDF2 with HMAC-SHA256 to derive the key */
    const char *salt = filename; /* Use filename as salt */

    if (PKCS5_PBKDF2_HMAC(master_key, strlen(master_key),
                          (const unsigned char *)salt, strlen(salt),
                          iterations, EVP_sha256(),
                          KEY_LENGTH, key) != 1)
    {
        print_error("PBKDF2 key derivation failed");
        free(key);
        return NULL;
    }

    key[KEY_LENGTH] = '\0'; /* Null terminate for safe string handling */
    return (char *)key;
}

/* Apply byte rotation obfuscation */
void byte_rotate(unsigned char *data, size_t len, int offset)
{
    for (size_t i = 0; i < len; i++)
    {
        data[i] = (data[i] + offset) & 0xFF;
    }
}

/* Encrypt content using AES-256-CBC */
char *encrypt_content(const char *content, size_t content_len, const char *key,
                      unsigned char *iv, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char *out_buf;
    int outlen, templen;
    char *result = NULL;

    if (!content || content_len == 0 || !key || !iv || !out_len)
    {
        print_error("Invalid parameters for encryption");
        return NULL;
    }

    /* Allocate buffer for encrypted data - need to account for block padding */
    out_buf = (unsigned char *)malloc(content_len + AES_BLOCK_SIZE);
    if (!out_buf)
    {
        print_error("Failed to allocate memory for encryption");
        return NULL;
    }

    /* Create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        print_error("Failed to create cipher context");
        free(out_buf);
        return NULL;
    }

    /* Initialize encryption operation with AES-256-CBC */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           (unsigned char *)key, iv) != 1)
    {
        print_error("Failed to initialize encryption");
        EVP_CIPHER_CTX_free(ctx);
        free(out_buf);
        return NULL;
    }

    /* Encrypt the data */
    if (EVP_EncryptUpdate(ctx, out_buf, &outlen,
                          (unsigned char *)content, content_len) != 1)
    {
        print_error("Encryption failed");
        EVP_CIPHER_CTX_free(ctx);
        free(out_buf);
        return NULL;
    }

    /* Finalize the encryption */
    if (EVP_EncryptFinal_ex(ctx, out_buf + outlen, &templen) != 1)
    {
        print_error("Encryption finalization failed");
        EVP_CIPHER_CTX_free(ctx);
        free(out_buf);
        return NULL;
    }

    /* Set the output length */
    *out_len = outlen + templen;

    /* Prepare result buffer */
    result = (char *)malloc(*out_len + 1);
    if (result)
    {
        memcpy(result, out_buf, *out_len);
        result[*out_len] = '\0'; /* Null terminate for safety */
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    free(out_buf);

    return result;
}

/* Base64 encode binary data */
char *base64_encode(const unsigned char *input, size_t length)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (!ctx)
    {
        print_error("Failed to create base64 encoding context");
        return NULL;
    }

    /* Calculate required output buffer size: base64 needs ~4/3 of input size plus padding */
    size_t output_len = ((length + 2) / 3) * 4 + 1; /* +1 for null terminator */
    char *output = (char *)malloc(output_len);
    if (!output)
    {
        EVP_ENCODE_CTX_free(ctx);
        print_error("Failed to allocate memory for base64 encoding");
        return NULL;
    }

    int outlen = 0;
    int total_out = 0;

    /* Initialize encoding context */
    EVP_EncodeInit(ctx);

    /* Encode the data */
    EVP_EncodeUpdate(ctx, (unsigned char *)output, &outlen, input, length);
    total_out += outlen;

    /* Finalize encoding */
    EVP_EncodeFinal(ctx, (unsigned char *)(output + total_out), &outlen);
    total_out += outlen;

    /* Ensure null-termination */
    output[total_out] = '\0';

    /* Clean up */
    EVP_ENCODE_CTX_free(ctx);

    return output;
}