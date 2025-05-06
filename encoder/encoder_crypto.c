/**
 * Zypher PHP Encoder - Encryption functionality
 * Handles AES encryption, key derivation, and cryptographic operations
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

/* Common headers */
#include "../include/zypher_encoder.h"
#include "../include/zypher_common.h"
#include "../build/zypher_master_key.h"

/* External debug function */
extern void print_debug(const char *format, ...);
extern void print_error(const char *format, ...);

/* Calculate checksum of content for integrity verification */
void calculate_content_checksum(const char *content, size_t length, char *output)
{
    unsigned char digest[MD5_DIGEST_LENGTH];

    /* Calculate MD5 hash using EVP interface */
    EVP_MD_CTX *md_ctx;
    unsigned int md_len;

    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(md_ctx, content, length);
    EVP_DigestFinal_ex(md_ctx, digest, &md_len);
    EVP_MD_CTX_free(md_ctx);

    /* Convert to hex string */
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[32] = '\0';
}

/* Encrypt content using file-specific key and IV */
char *encrypt_content(const char *content, size_t content_len, const char *key,
                      unsigned char *iv, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;
    unsigned char *ciphertext;

    /* Allocate memory for ciphertext - allow for padding */
    ciphertext = (unsigned char *)malloc(content_len + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext)
        return NULL;

    /* Create cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        free(ciphertext);
        return NULL;
    }

    /* Initialize encryption operation with AES-256-CBC */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                           (unsigned char *)key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }

    /* Encrypt the data */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)content,
                          content_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len = len;

    /* Finalize encryption (handle padding) */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    /* Set output length */
    if (out_len)
        *out_len = ciphertext_len;

    return (char *)ciphertext;
}

/* Derive file-specific encryption key based on master key and filename */
char *derive_encryption_key(const char *master_key, const char *filename, int iterations)
{
    /* Use HMAC-SHA256 for key derivation with multiple iterations */
    unsigned char *derived_key = malloc(32);
    unsigned int derived_len = 32;

    /* Create salt based on filename */
    char *salt = malloc(100);
    char *filename_md5 = malloc(33);
    unsigned char digest[16];

    /* Calculate MD5 of filename using EVP interface */
    EVP_MD_CTX *md_ctx;
    unsigned int md_len;

    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(md_ctx, filename, strlen(filename));
    EVP_DigestFinal_ex(md_ctx, digest, &md_len);
    EVP_MD_CTX_free(md_ctx);

    for (int i = 0; i < 16; i++)
    {
        sprintf(&filename_md5[i * 2], "%02x", digest[i]);
    }
    filename_md5[32] = '\0';

    /* Create salt */
    snprintf(salt, 100, "ZypherSalt-%s", filename_md5);

    /* Create combined data */
    size_t combined_len = strlen(filename) + strlen(salt);
    unsigned char *combined = malloc(combined_len + 1);
    memcpy(combined, filename, strlen(filename));
    memcpy(combined + strlen(filename), salt, strlen(salt));
    combined[combined_len] = '\0';

    /* Initial HMAC */
    HMAC(EVP_sha256(), master_key, strlen(master_key),
         combined, combined_len, derived_key, &derived_len);

    /* Multiple iterations to strengthen the key */
    for (int i = 0; i < iterations; i++)
    {
        unsigned char *buffer = malloc(32 + strlen(salt) + 1);
        unsigned int buffer_len = 0;

        memcpy(buffer, derived_key, 32);
        buffer_len += 32;

        memcpy(buffer + buffer_len, salt, strlen(salt));
        buffer_len += strlen(salt);

        buffer[buffer_len++] = (unsigned char)(i & 0xFF);

        HMAC(EVP_sha256(), master_key, strlen(master_key),
             buffer, buffer_len, derived_key, &derived_len);

        free(buffer);
    }

    /* Create hex string from binary key */
    char *result = malloc(65);
    for (int i = 0; i < 32; i++)
    {
        sprintf(&result[i * 2], "%02x", derived_key[i]);
    }
    result[64] = '\0';

    /* Cleanup */
    free(derived_key);
    free(salt);
    free(filename_md5);
    free(combined);

    return result;
}