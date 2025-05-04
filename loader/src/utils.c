#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"

#include "src/php_loader.h"
#include "utils.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* Enhanced key derivation using HMAC-SHA256 with multiple iterations */
void zypher_derive_key(const char *master_key, const char *filename, char *output_key, int iterations)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char salt[128];

    // Create a salt based on filename (matching encoder implementation)
    snprintf(salt, sizeof(salt), "ZypherSalt-%s", filename);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // Initial HMAC
    HMAC(EVP_sha256(), master_key, strlen(master_key),
         (unsigned char *)salt, strlen(salt), hash, NULL);

    // Multiple iterations for key strengthening
    for (int i = 0; i < iterations && i < MAX_KEY_ITERATIONS; i++)
    {
        // Add iteration counter to salt (matching encoder implementation)
        snprintf(salt, sizeof(salt), "ZypherSalt-%s-%d", filename, i);
        HMAC(EVP_sha256(), master_key, strlen(master_key),
             hash, sizeof(hash), hash, NULL);
    }
#else
    /* Create context for HMAC-SHA256 */
    HMAC_CTX *ctx = HMAC_CTX_new();

    /* Initialize with master key */
    HMAC_Init_ex(ctx, master_key, strlen(master_key), EVP_sha256(), NULL);

    /* Add salted filename to the mix */
    HMAC_Update(ctx, (unsigned char *)salt, strlen(salt));

    /* Finalize */
    unsigned int len = SHA256_DIGEST_LENGTH;
    HMAC_Final(ctx, hash, &len);

    /* Multiple iterations for key strengthening */
    for (int i = 0; i < iterations && i < MAX_KEY_ITERATIONS; i++)
    {
        HMAC_CTX_reset(ctx);
        HMAC_Init_ex(ctx, master_key, strlen(master_key), EVP_sha256(), NULL);
        HMAC_Update(ctx, hash, sizeof(hash));
        // Add iteration counter to match encode.php implementation
        HMAC_Update(ctx, (unsigned char *)&i, sizeof(i));
        HMAC_Final(ctx, hash, &len);
    }

    HMAC_CTX_free(ctx);
#endif

    /* Convert to hex string */
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(output_key + (i * 2), "%02x", hash[i]);
    }
    output_key[SHA256_DIGEST_LENGTH * 2] = '\0';
}

/**
 * Native implementation of string decoding for obfuscation
 * This replaces the PHP-based zypher_decode_str function with a native C implementation
 */
PHP_FUNCTION(zypher_decode_string)
{
    char *hex_str = NULL, *key = NULL;
    size_t hex_len, key_len;

    // Get parameters: the hex-encoded string and the key
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &hex_str, &hex_len, &key, &key_len) == FAILURE)
    {
        RETURN_NULL();
    }

    // Validate inputs
    if (hex_len == 0 || key_len == 0)
    {
        RETURN_EMPTY_STRING();
    }

    // Binary size is half of hex size (2 hex chars = 1 byte)
    size_t bin_len = hex_len / 2;
    unsigned char *bin = (unsigned char *)emalloc(bin_len + 1);

    // Convert hex to binary
    size_t i, j;
    for (i = 0, j = 0; i < hex_len; i += 2, j++)
    {
        char hex_byte[3] = {hex_str[i], hex_str[i + 1], 0};
        bin[j] = (unsigned char)strtol(hex_byte, NULL, 16);
    }
    bin[bin_len] = '\0';

    // XOR decode the binary data with the key
    unsigned char *result = (unsigned char *)emalloc(bin_len + 1);
    for (i = 0; i < bin_len; i++)
    {
        result[i] = bin[i] ^ key[i % key_len];
    }
    result[bin_len] = '\0';

    if (DEBUG)
    {
        php_printf("DEBUG: Decoded string of length %zu\n", bin_len);
    }

    // Free temporary binary buffer
    efree(bin);

    // Return the decoded string
    RETVAL_STRINGL((char *)result, bin_len);
    efree(result);
}